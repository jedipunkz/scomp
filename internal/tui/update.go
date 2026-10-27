package tui

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"

	"github.com/jedipunkz/scomp/internal/model"
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

	case issuesSearchedMsg:
		return m.handleIssuesSearched(msg)

	case issueDoneMsg:
		return m.handleIssueDone(msg)

	case spinner.TickMsg:
		if !m.scanning {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case tea.MouseWheelMsg:
		var cmd tea.Cmd
		m.preview, cmd = m.preview.Update(msg)
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
	if cmd, ok := m.issuePromptKey(msg); ok {
		return m, cmd
	}
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
	case "shift+up", "k":
		m.preview.ScrollUp(1)
		return m, nil
	case "shift+down", "j":
		m.preview.ScrollDown(1)
		return m, nil
	case "alt+o":
		return m, m.openSelected()
	case "alt+i":
		return m, m.startIssueSearch()
	case "alt+s":
		m.sev = (m.sev + 1) % sevFilterCount
		m.refresh()
		return m, nil
	case "alt+e":
		m.eco = (m.eco + 1) % (len(m.ecos) + 1)
		m.refresh()
		return m, nil
	case "alt+f":
		m.fixedOnly = !m.fixedOnly
		m.refresh()
		return m, nil
	case "alt+r":
		if m.scanning {
			return m, nil
		}
		m.status = ""
		return m, m.startScan()
	}

	return m.editInput(msg)
}

// editInput routes the key to the search input and refreshes on change.
func (m Model) editInput(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
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

// The GitHub issue flow (alt+i): look up existing issues for the selected
// finding, then ask the user what to do. With no existing issue the prompt is
// y (create) / c (cancel); with one, o (override: edit the existing issue) /
// d (duplicate: create anyway) / c (cancel). gh is never run while the prompt
// is open — the search runs at alt+i, the create or edit after the answer.

// startIssueSearch looks up existing issues for the selected finding. Each
// search gets a sequence number; results carrying an older number are stale
// and dropped. A second alt+i while searching retargets the search.
func (m *Model) startIssueSearch() tea.Cmd {
	if m.issueState != issueIdle && m.issueState != issueSearching {
		return nil
	}
	if m.cfg.SearchIssues == nil {
		return nil
	}
	idx, ok := m.selected()
	if !ok {
		return nil
	}
	m.issueState = issueSearching
	m.issueFinding = m.findings[idx]
	m.issueSeq++
	m.status = "searching GitHub issues…"
	ctx, f, seq, find := m.ctx, m.issueFinding, m.issueSeq, m.cfg.SearchIssues
	return func() tea.Msg {
		issues, err := find(ctx, f)
		return issuesSearchedMsg{seq: seq, finding: f, issues: issues, err: err}
	}
}

// issuePromptKey routes keys while the issue flow is active. While a prompt
// (confirm or choose) is open, every other key is swallowed; while a search
// is in flight, esc backs out and everything else passes through.
func (m *Model) issuePromptKey(msg tea.KeyPressMsg) (tea.Cmd, bool) {
	switch m.issueState {
	case issueConfirm, issueChoose:
	case issueSearching:
		if msg.String() == "esc" {
			m.closeIssuePrompt()
		}
		return nil, m.issueState == issueIdle
	default:
		return nil, false
	}
	switch msg.String() {
	case "ctrl+c":
		return nil, false // let the app quit
	case "c", "esc", "q":
		m.closeIssuePrompt()
		return nil, true
	case "y":
		if m.issueState == issueConfirm {
			return m.runIssue(issueCreate), true
		}
	case "o":
		if m.issueState == issueChoose {
			return m.runIssue(issueEdit), true
		}
	case "d":
		if m.issueState == issueChoose {
			return m.runIssue(issueCreate), true
		}
	}
	return nil, true
}

// closeIssuePrompt dismisses the prompt and drops any in-flight result.
func (m *Model) closeIssuePrompt() {
	m.issueState = issueIdle
	m.issueSeq++
	m.issueFound = nil
	m.status = ""
}

// runIssue starts the gh command for the prompt's action. The gh callback
// runs in a tea.Cmd goroutine and reports back with issueDoneMsg.
func (m *Model) runIssue(action issueAction) tea.Cmd {
	f, ctx := m.issueFinding, m.ctx
	switch action {
	case issueCreate:
		create := m.cfg.CreateIssue
		if create == nil {
			m.closeIssuePrompt()
			return nil
		}
		m.issueState = issueRunning
		m.status = "creating GitHub issue…"
		return func() tea.Msg {
			url, err := create(ctx, f)
			return issueDoneMsg{action: issueCreate, url: url, err: err}
		}
	case issueEdit:
		edit := m.cfg.EditIssue
		if edit == nil || len(m.issueFound) == 0 {
			m.closeIssuePrompt()
			return nil
		}
		number := m.issueFound[0].Number
		m.issueState = issueRunning
		m.status = fmt.Sprintf("updating issue #%d…", number)
		return func() tea.Msg {
			url, err := edit(ctx, f, number)
			return issueDoneMsg{action: issueEdit, number: number, url: url, err: err}
		}
	}
	return nil
}

func (m *Model) handleIssuesSearched(msg issuesSearchedMsg) (tea.Model, tea.Cmd) {
	if m.issueState != issueSearching || msg.seq != m.issueSeq {
		return *m, nil // stale result
	}
	m.status = ""
	switch {
	case msg.err != nil:
		m.issueState = issueIdle
		m.status = "search issues: " + errLine(msg.err)
	case len(msg.issues) == 0:
		m.issueState = issueConfirm
	default:
		// gh output is external data; sanitize before it reaches the popup.
		for i := range msg.issues {
			msg.issues[i].Title = model.Sanitize(msg.issues[i].Title)
			msg.issues[i].State = model.Sanitize(msg.issues[i].State)
			msg.issues[i].URL = model.Sanitize(msg.issues[i].URL)
		}
		m.issueState = issueChoose
		m.issueFound = msg.issues
	}
	return *m, nil
}

func (m *Model) handleIssueDone(msg issueDoneMsg) (tea.Model, tea.Cmd) {
	if m.issueState != issueRunning {
		return *m, nil // stale result
	}
	m.issueState = issueIdle
	m.issueFound = nil
	switch {
	case msg.err != nil:
		verb := "create issue"
		if msg.action == issueEdit {
			verb = "update issue"
		}
		m.status = verb + ": " + errLine(msg.err)
	case msg.action == issueEdit:
		m.status = "updated " + msg.url
	default:
		m.status = "created " + msg.url
	}
	return *m, nil
}
