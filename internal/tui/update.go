package tui

import (
	"context"
	"errors"
	"net/url"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
)

// ErrNoLockfiles is returned by Config.Scan when no supported lockfile exists.
var ErrNoLockfiles = errors.New("no supported lockfiles found")

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.clampOffset()
		m.updatePreview()
		return m, nil

	case startScanMsg:
		return m, m.startScan()

	case scanDoneMsg:
		return m.handleScanDone(msg)

	case openedMsg:
		if msg.err != nil {
			m.status = "open browser: " + msg.err.Error()
		}
		return m, nil

	case spinner.TickMsg:
		if !m.scanning {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m Model) handleScanDone(msg scanDoneMsg) (tea.Model, tea.Cmd) {
	m.scanning = false
	m.cancelScan = nil
	m.previewFor = previewInvalid

	switch {
	case errors.Is(msg.err, context.Canceled):
		m.status = "scan canceled"
	case errors.Is(msg.err, ErrNoLockfiles):
		m.scanErr = nil
		m.noLockfiles = true
		m.cachedAt = timeZero
		m.setFindings(nil)
	case msg.err != nil:
		// Keep showing what we have (e.g. the cached list).
		m.scanErr = msg.err
	default:
		m.scanErr = nil
		m.noLockfiles = false
		m.cachedAt = timeZero
		m.status = ""
		m.setFindings(msg.findings)
		if m.cfg.OnScanned != nil {
			if err := m.cfg.OnScanned(msg.findings); err != nil {
				m.status = "cache write failed: " + err.Error()
			}
		}
	}
	m.layout()
	m.clampOffset()
	m.updatePreview()
	return m, nil
}

func (m Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "ctrl+c":
		if m.cancelScan != nil {
			m.cancelScan()
		}
		return m, tea.Quit
	case "up", "ctrl+p":
		m.moveCursor(-1)
		return m, nil
	case "down", "ctrl+n":
		m.moveCursor(1)
		return m, nil
	case "pgup":
		m.moveCursor(-max(1, m.listHeight()))
		return m, nil
	case "pgdown":
		m.moveCursor(max(1, m.listHeight()))
		return m, nil
	case "enter":
		m.detail = !m.detail
		m.updatePreview()
		return m, nil
	case "shift+up", "k":
		m.preview.ScrollUp(1)
		return m, nil
	case "shift+down", "j":
		m.preview.ScrollDown(1)
		return m, nil
	case "ctrl+o":
		return m, m.openSelected()
	case "ctrl+s":
		m.sev = (m.sev + 1) % sevFilterCount
		m.refresh()
		return m, nil
	case "ctrl+e":
		m.eco = (m.eco + 1) % (len(m.ecos) + 1)
		m.refresh()
		return m, nil
	case "ctrl+f":
		m.fixedOnly = !m.fixedOnly
		m.refresh()
		return m, nil
	case "ctrl+r":
		if m.scanning {
			return m, nil
		}
		m.status = ""
		return m, m.startScan()
	}

	before := m.input.Value()
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	if m.input.Value() != before {
		m.refresh()
	}
	return m, cmd
}

func (m Model) openSelected() tea.Cmd {
	idx, ok := m.selected()
	if !ok || m.cfg.OpenURL == nil {
		return nil
	}
	target := OSVURL(m.findings[idx].ID)
	open := m.cfg.OpenURL
	return func() tea.Msg { return openedMsg{err: open(target)} }
}

// OSVURL returns the osv.dev page for an OSV ID.
func OSVURL(id string) string {
	return "https://osv.dev/vulnerability/" + url.PathEscape(id)
}
