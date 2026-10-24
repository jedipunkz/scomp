package tui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jedipunkz/scomp/internal/model"
)

const (
	headerLines = 2 // title + query
	chromeLines = 4 // top separator, detail separator, bottom separator, help
	minListH    = 3
	maxDetailH  = 14
	helpText    = "↑↓ move  enter detail  shift+↑↓ j/k scroll  ctrl+o open  ctrl+s severity  ctrl+e ecosystem  ctrl+f fixed  ctrl+r rescan  esc quit"
)

func (m Model) statusLine() string {
	if m.scanErr != nil {
		msg := "error: " + firstLine(m.scanErr.Error())
		if !m.detail {
			msg += " (enter: details)"
		}
		return styleError.Render(msg)
	}
	if m.status != "" {
		return styleDim.Render(m.status)
	}
	return ""
}

func (m Model) bodyHeight() int {
	h := m.height - headerLines - chromeLines
	if m.statusLine() != "" {
		h--
	}
	return max(1, h)
}

// detailHeight is the height of the bottom detail pane; 0 hides it.
func (m Model) detailHeight() int {
	if m.detail {
		return 0
	}
	h := m.bodyHeight()
	dh := min(max(h*35/100, 4), maxDetailH)
	if h-dh < minListH {
		return 0
	}
	return dh
}

func (m Model) listHeight() int {
	if m.detail {
		return 0
	}
	return m.bodyHeight() - m.detailHeight()
}

// layout sizes the input and preview to the current window.
func (m *Model) layout() {
	filters := m.filterLabel()
	m.input.SetWidth(max(1, m.width-ansi.StringWidth(m.input.Prompt)-ansi.StringWidth(filters)-2))
	w, h := max(1, m.width), m.bodyHeight()
	if !m.detail {
		h = m.detailHeight()
		if h == 0 {
			w, h = 1, 1 // pane hidden
		}
	}
	m.preview.SetWidth(w)
	m.preview.SetHeight(h)
}

func (m Model) filterLabel() string {
	eco := m.ecoName()
	if eco == "" {
		eco = "all"
	}
	fixed := "all"
	if m.fixedOnly {
		fixed = "only"
	}
	return fmt.Sprintf("sev:%s eco:%s fixed:%s", m.sev.label(), eco, fixed)
}

func (m Model) View() tea.View {
	m.layout()
	w := max(1, m.width)
	var lines []string
	lines = append(lines, fit(m.headerLine(), w))
	lines = append(lines, fit(spread(m.input.View(), styleDim.Render(m.filterLabel()), w), w))
	lines = append(lines, styleDim.Render(strings.Repeat("─", w)))
	lines = append(lines, m.bodyLines(w)...)
	lines = append(lines, styleDim.Render(strings.Repeat("─", w)))
	if s := m.statusLine(); s != "" {
		lines = append(lines, fit(s, w))
	}
	lines = append(lines, fit(styleDim.Render(helpText), w))
	if m.height > 0 && len(lines) > m.height {
		lines = lines[:m.height]
	}

	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	return v
}

func (m Model) headerLine() string {
	counts := map[model.Severity]int{}
	for _, f := range m.findings {
		counts[f.Severity]++
	}
	// Keep the end of long titles (repo name) so the status parts stay visible.
	title := m.cfg.Title
	if limit := max(12, m.width/3); ansi.StringWidth(title) > limit {
		title = ansi.TruncateLeft(title, ansi.StringWidth(title)-limit+1, "…")
	}
	parts := []string{styleTitle.Render("scomp"), title}
	sum := fmt.Sprintf("%d findings (C:%d H:%d M:%d L:%d", len(m.findings),
		counts[model.SeverityCritical], counts[model.SeverityHigh], counts[model.SeverityMedium], counts[model.SeverityLow])
	if n := counts[model.SeverityUnknown]; n > 0 {
		sum += fmt.Sprintf(" ?:%d", n)
	}
	sum += ")"
	if q := m.input.Value(); q != "" || m.filter() != (Filter{}) {
		sum = fmt.Sprintf("%d/%s", len(m.results), sum)
	}
	parts = append(parts, sum)
	switch {
	case m.scanning:
		parts = append(parts, m.spin.View()+" scanning…")
	case !m.cachedAt.IsZero():
		parts = append(parts, "cached "+ago(m.now().Sub(m.cachedAt)))
	}
	if m.cfg.ScannerPath != "" {
		parts = append(parts, styleDim.Render(m.cfg.ScannerPath))
	}
	return strings.Join(parts, " ─ ")
}

func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func (m Model) bodyLines(w int) []string {
	h := m.bodyHeight()
	if m.detail {
		return fitLines(m.preview.View(), w, h)
	}

	dh := m.detailHeight()
	out := m.listLines(w, h-dh)
	if dh == 0 {
		return out
	}
	out = append(out, styleDim.Render(strings.Repeat("─", w)))
	return append(out, fitLines(m.preview.View(), w, dh)...)
}

func (m Model) listLines(w, h int) []string {
	if msg := m.emptyMessage(); msg != nil {
		return center(msg, w, h)
	}

	nameW, verW, idW := 0, 0, 0
	for _, f := range m.findings {
		nameW = max(nameW, ansi.StringWidth(f.Package.Name))
		verW = max(verW, ansi.StringWidth(f.Package.Version))
		idW = max(idW, ansi.StringWidth(f.ID))
	}
	// marker(2) + sev(4) + 3 gaps
	avail := max(0, w-2-4-3*2)
	nameW = min(nameW, max(8, avail*45/100))
	verW = min(verW, 12)
	idW = min(idW, 20)

	lines := make([]string, h)
	for row := range h {
		i := m.offset + row
		if i >= len(m.results) {
			lines[row] = strings.Repeat(" ", w)
			continue
		}
		r := m.results[i]
		f := m.findings[r.Index]
		lay := m.layouts[r.Index]
		matched := map[int]bool{}
		for _, o := range r.Matched {
			matched[o] = true
		}
		base := lipgloss.NewStyle()
		marker := "  "
		if i == m.cursor {
			base = styleSelected
			marker = styleMarker.Render("▶ ")
		}
		sev := severityStyles[f.Severity].Render(pad(f.Severity.Short(), 4))
		cols := []string{
			marker + sev,
			pad(ansi.Truncate(highlight(f.Package.Name, lay.name, matched, base), nameW, "…"), nameW),
			pad(base.Render(ansi.Truncate(f.Package.Version, verW, "…")), verW),
			pad(ansi.Truncate(highlight(f.ID, lay.id, matched, base), idW, "…"), idW),
			styleDim.Render(highlight(f.Summary, lay.summary, matched, lipgloss.NewStyle())),
		}
		lines[row] = fit(strings.Join(cols, "  "), w)
	}
	return lines
}

func (m Model) emptyMessage() []string {
	switch {
	case len(m.findings) == 0 && m.scanning:
		return []string{m.spin.View() + " scanning…"}
	case len(m.findings) == 0 && m.noLockfiles:
		return []string{
			"No supported lockfiles found",
			"",
			styleDim.Render("looked for: " + strings.Join(m.cfg.Lockfiles, ", ")),
		}
	case len(m.findings) == 0 && m.scanErr != nil:
		return []string{styleError.Render("Scan failed"), styleDim.Render("press enter for details, ctrl+r to retry")}
	case len(m.findings) == 0:
		return []string{"No known vulnerabilities"}
	case len(m.results) == 0:
		return []string{styleDim.Render("No matches")}
	}
	return nil
}

// highlight renders s (which starts at byte offset start in the search key)
// with the matched key offsets highlighted.
func highlight(s string, start int, matched map[int]bool, base lipgloss.Style) string {
	if len(matched) == 0 {
		return base.Render(s)
	}
	var b strings.Builder
	var run strings.Builder
	runHL := false
	flush := func() {
		if run.Len() == 0 {
			return
		}
		if runHL {
			b.WriteString(styleHighlight.Render(run.String()))
		} else {
			b.WriteString(base.Render(run.String()))
		}
		run.Reset()
	}
	for i, r := range s {
		hl := matched[start+i]
		if hl != runHL {
			flush()
			runHL = hl
		}
		run.WriteRune(r)
	}
	flush()
	return b.String()
}

func (m Model) renderDetail(f model.Finding, w int) string {
	w = max(10, w)
	var b strings.Builder
	line := func(s string) {
		b.WriteString(wrap(s, w))
		b.WriteByte('\n')
	}
	field := func(label, value string) {
		line(styleDim.Render(fmt.Sprintf("%-10s: ", label)) + value)
	}
	orNone := func(ss []string) string {
		if len(ss) == 0 {
			return styleDim.Render("none")
		}
		return strings.Join(ss, ", ")
	}

	line(styleBold.Render(f.ID))
	if len(f.CVEs) > 0 {
		line(strings.Join(f.CVEs, ", "))
	}
	line("")
	field("Package", f.Package.Name+" "+f.Package.Version)
	field("Ecosystem", f.Package.Ecosystem)
	field("Source", f.Package.Source)
	field("Fixed", orNone(f.FixedVersions))
	sev := severityStyles[f.Severity].Render(f.Severity.String())
	if f.CVSSScore > 0 {
		sev += fmt.Sprintf(" (%.1f)", f.CVSSScore)
	}
	field("Severity", sev)
	field("Aliases", orNone(f.Aliases))
	if !f.Published.IsZero() {
		field("Published", f.Published.Format("2006-01-02"))
	}
	if !f.Modified.IsZero() {
		field("Modified", f.Modified.Format("2006-01-02"))
	}
	line("")
	if f.Summary != "" {
		line(styleBold.Render(f.Summary))
		line("")
	}
	if f.Details != "" {
		line(strings.TrimSpace(f.Details))
		line("")
	}
	line(styleDim.Render("References:"))
	line(OSVURL(f.ID))
	for _, r := range f.References {
		line(r)
	}
	return strings.TrimRight(b.String(), "\n")
}

type detailer interface{ Details() string }

func (m Model) renderError(w int) string {
	w = max(10, w)
	var b strings.Builder
	b.WriteString(styleError.Render(wrap("Last scan failed: "+sanitize(m.scanErr.Error()), w)))
	var d detailer
	if errors.As(m.scanErr, &d) && d.Details() != "" {
		b.WriteString("\n\n")
		b.WriteString(styleDim.Render("stderr:"))
		b.WriteByte('\n')
		b.WriteString(wrap(sanitize(strings.TrimSpace(d.Details())), w))
	}
	return b.String()
}

// wrap word-wraps s to w cells, hard-wrapping words longer than w.
func wrap(s string, w int) string {
	return ansi.Hardwrap(ansi.Wordwrap(s, w, ""), w, true)
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}

// pad right-pads s with spaces to w cells.
func pad(s string, w int) string {
	if n := ansi.StringWidth(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

// fit truncates or pads s to exactly w cells.
func fit(s string, w int) string {
	if ansi.StringWidth(s) > w {
		s = ansi.Truncate(s, w, "…")
	}
	return pad(s, w)
}

func fitLines(s string, w, h int) []string {
	src := strings.Split(s, "\n")
	out := make([]string, h)
	for i := range h {
		l := ""
		if i < len(src) {
			l = src[i]
		}
		out[i] = fit(l, w)
	}
	return out
}

// spread places left and right on one line of width w.
func spread(left, right string, w int) string {
	gap := w - ansi.StringWidth(left) - ansi.StringWidth(right)
	if gap < 1 {
		return left
	}
	return left + strings.Repeat(" ", gap) + right
}

func center(msg []string, w, h int) []string {
	out := make([]string, h)
	top := max(0, (h-len(msg))/2)
	for i := range h {
		l := ""
		if j := i - top; j >= 0 && j < len(msg) {
			l = msg[j]
			if lw := ansi.StringWidth(l); lw < w {
				l = strings.Repeat(" ", (w-lw)/2) + l
			}
		}
		out[i] = fit(l, w)
	}
	return out
}
