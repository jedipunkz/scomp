package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jedipunkz/scomp/internal/model"
)

const (
	headerLines   = 2 // title + query
	chromeLines   = 1 // help; pane title bars are part of the body
	titleBarLines = 2 // one title bar per pane
	minListH      = 3
	minDetailH    = 4
)

// helpKeyMap adapts the TUI's keys for the bubbles help component.
type helpKeyMap struct{}

func (helpKeyMap) ShortHelp() []key.Binding {
	bind := func(keys, k, desc string) key.Binding {
		return key.NewBinding(key.WithKeys(strings.Fields(keys)...), key.WithHelp(k, desc))
	}
	return []key.Binding{
		bind("up down", "↑↓", "move"),
		bind("alt+o", "alt+o", "open"),
		bind("alt+i", "alt+i", "issue"),
		bind("alt+s", "alt+s", "sev"),
		bind("alt+e", "alt+e", "eco"),
		bind("alt+f", "alt+f", "fixed"),
		bind("alt+r", "alt+r", "rescan"),
		bind("esc", "esc", "quit"),
	}
}

func (h helpKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{h.ShortHelp()}
}

// hasStatus reports whether statusLine is non-empty without rendering it.
// Layout code calls it several times per frame; statusLine runs Sanitize and
// a lipgloss Render, which never returns "" for a set status, so the two
// agree.
func (m Model) hasStatus() bool {
	return m.scanErr != nil || m.status != ""
}

func (m Model) statusLine() string {
	if m.scanErr != nil {
		msg := "error: " + errLine(m.scanErr)
		return styleError.Render(msg)
	}
	if m.status != "" {
		return styleDim.Render(model.Sanitize(m.status))
	}
	return ""
}

// issueQuestion is the question line of the GitHub issue popup.
func (m Model) issueQuestion() string {
	switch m.issueState {
	case issueConfirm:
		return "Create a GitHub issue for this finding?"
	case issueChoose:
		return "Override it, or create a duplicate?"
	}
	return ""
}

// issueKeyHelp renders the answer keys of the popup, help-bar style.
func (m Model) issueKeyHelp() string {
	var parts []string
	pair := func(k, desc string) {
		parts = append(parts, styleTitle.Render(k)+styleDim.Render(" "+desc))
	}
	switch m.issueState {
	case issueConfirm:
		pair("y", "create")
		pair("c", "cancel")
	case issueChoose:
		pair("o", "override")
		pair("d", "duplicate")
		pair("c", "cancel")
	}
	return strings.Join(parts, "   ")
}

// severityText renders the severity label with its CVSS score when known. It is
// shared by the detail pane and the issue popup.
func severityText(f model.Finding) string {
	return severityStyles[f.Severity].Render(f.Severity.String()) + model.CVSSSuffix(f.CVSSScore)
}

// fixedText renders the fixed versions, or a dim "none" when there are none.
// It is shared by the detail pane and the issue popup.
func fixedText(f model.Finding) string {
	if len(f.FixedVersions) == 0 {
		return styleDim.Render("none")
	}
	return styleFixed.Render(strings.Join(f.FixedVersions, ", "))
}

// issueModalLines renders the GitHub issue popup as centered lines. It takes
// over the whole view: the finding context is inside the popup, so no pane or
// help bar is shown behind it.
func (m Model) issueModalLines(w, h int) []string {
	inner := max(20, min(w-8, 70))
	f := m.issueFinding

	lines := []string{styleDetailID.Render(f.ID)}
	if len(f.CVEs) > 0 {
		lines = append(lines, styleDetailAlt.Render(strings.Join(f.CVEs, ", ")))
	}
	lines = append(lines,
		stylePackage.Render(f.Package.Name)+" "+styleVersion.Render(f.Package.Version)+" "+styleDim.Render(f.Package.Ecosystem),
	)
	if f.Summary != "" {
		lines = append(lines, styleBold.Render(wrap(f.Summary, inner)))
	}
	lines = append(lines, styleDim.Render("severity: ")+severityText(f)+styleDim.Render("   fixed: ")+fixedText(f))

	if m.issueState == issueChoose {
		e := m.issueFound[0]
		found := fmt.Sprintf("issue #%d [%s]: %s", e.Number, e.State, e.Title)
		lines = append(lines, "", styleURL.Render(wrap(found, inner)))
		if n := len(m.issueFound) - 1; n > 0 {
			lines = append(lines, styleDim.Render(fmt.Sprintf("+%d more matching issue(s)", n)))
		}
	}
	lines = append(lines, "", styleBold.Render(wrap(m.issueQuestion(), inner)), "", m.issueKeyHelp())

	box := styleModalBox.Render(strings.Join(lines, "\n"))
	return center(strings.Split(box, "\n"), w, h)
}

func (m Model) bodyHeight() int {
	h := m.height - headerLines - chromeLines
	if m.hasStatus() {
		h--
	}
	return max(1, h)
}

// detailHeight is the height of the bottom detail pane; 0 hides it.
func (m Model) detailHeight() int {
	// The list keeps about a quarter of the window minus two rows; the
	// detail pane takes the rest, minus the two title bars between the panes.
	lh := max(minListH, m.height/4-2)
	dh := m.bodyHeight() - lh - titleBarLines
	if dh < minDetailH {
		return 0
	}
	return dh
}

// listHeight is the number of finding rows. The body is bodyHeight rows: the
// list title bar, the list rows, and when shown the detail title bar and pane.
func (m Model) listHeight() int {
	dh := m.detailHeight()
	if dh == 0 {
		return m.bodyHeight() - 1 // list title bar
	}
	return m.bodyHeight() - dh - titleBarLines
}

// layout sizes the input, help and preview to the current window.
func (m *Model) layout() {
	filters := m.filterLabel()
	m.input.SetWidth(max(1, m.width-ansi.StringWidth(m.input.Prompt)-ansi.StringWidth(filters)-2))
	m.help.SetWidth(max(1, m.width))
	w, h := max(1, m.width), m.detailHeight()
	if h == 0 {
		w, h = 1, 1 // pane hidden
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
	if m.issueState == issueConfirm || m.issueState == issueChoose {
		// Full-screen popup: the finding context is inside the popup.
		lines = m.issueModalLines(w, max(1, m.height))
	} else {
		lines = append(lines, fit(m.headerLine(), w))
		lines = append(lines, fit(spread(m.input.View(), styleDim.Render(m.filterLabel()), w), w))
		lines = append(lines, m.bodyLines(w)...)
		if s := m.statusLine(); s != "" {
			lines = append(lines, fit(s, w))
		}
		lines = append(lines, fit(m.help.View(helpKeyMap{}), w))
	}
	if m.height > 0 && len(lines) > m.height {
		lines = lines[:m.height]
	}

	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.WindowTitle = "scomp"
	if t := singleLine(m.cfg.Title); t != "" {
		v.WindowTitle += " · " + t
	}
	return v
}

// singleLine sanitizes s for the terminal title and the header, which must be
// one line without control sequences.
func singleLine(s string) string {
	return strings.ReplaceAll(model.Sanitize(s), "\n", "")
}

func (m Model) headerLine() string {
	counts := m.sevCounts
	cnt := func(s model.Severity, label string) string {
		return severityStyles[s].Render(fmt.Sprintf("%s:%d", label, counts[s]))
	}
	// Keep the end of long titles (repo name) so the status parts stay visible.
	title := singleLine(m.cfg.Title)
	if limit := max(12, m.width/3); ansi.StringWidth(title) > limit {
		title = ansi.TruncateLeft(title, ansi.StringWidth(title)-limit+1, "…")
	}
	parts := []string{styleTitle.Render("scomp"), title}
	sum := fmt.Sprintf("%d findings (", len(m.findings)) + strings.Join([]string{
		cnt(model.SeverityCritical, "C"),
		cnt(model.SeverityHigh, "H"),
		cnt(model.SeverityMedium, "M"),
		cnt(model.SeverityLow, "L"),
	}, " ")
	if n := counts[model.SeverityUnknown]; n > 0 {
		sum += " " + cnt(model.SeverityUnknown, "?")
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
	if p := singleLine(m.cfg.ScannerPath); p != "" {
		parts = append(parts, styleDim.Render(p))
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
	dh := m.detailHeight()
	out := []string{m.listTitle(w)}
	out = append(out, m.listLines(w, m.listHeight())...)
	if dh == 0 {
		return out
	}
	out = append(out, m.detailTitle(w))
	return append(out, fitLines(m.preview.View(), w, dh)...)
}

// rule renders a pane title bar: a label followed by a rule filling the width.
func rule(w int, label string) string {
	s := stylePaneLabel.Render(" " + label + " ")
	return s + styleRule.Render(strings.Repeat("─", max(0, w-ansi.StringWidth(s))))
}

func (m Model) listTitle(w int) string {
	return rule(w, fmt.Sprintf("Findings %d/%d", len(m.results), len(m.findings)))
}

func (m Model) detailTitle(w int) string {
	return rule(w, "Detail")
}

func (m Model) listLines(w, h int) []string {
	if msg := m.emptyMessage(w); msg != nil {
		return center(msg, w, h)
	}

	nameW, verW, idW := m.nameMaxW, m.verMaxW, m.idMaxW
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
		// Offsets are computed here, for visible rows only, not per match in Search.
		matched := termOffsets(m.norm[r.Index].Key, m.terms)
		nameSt, verSt, idSt := stylePackage, styleVersion, styleID
		sumSt := styleSummary
		marker := "  "
		if i == m.cursor {
			marker = markerSel
			nameSt, verSt, idSt, sumSt = stylePackageSel, styleVersionSel, styleIDSel, styleSummarySel
		}
		cols := []string{
			marker + sevLabel(f.Severity),
			fit(highlight(f.Package.Name, lay.name, matched, nameSt, styleHighlight), nameW),
			fit(verSt.Render(f.Package.Version), verW),
			fit(highlight(f.ID, lay.id, matched, idSt, styleHighlight), idW),
			highlight(f.Summary, lay.summary, matched, sumSt, styleHighlight),
		}
		lines[row] = fit(strings.Join(cols, "  "), w)
	}
	return lines
}

// markerSel and sevLabels are the bounded set of list-row labels, rendered
// once instead of per visible row per frame. lipgloss v2 Render emits the
// same bytes regardless of the terminal (the renderer downsamples colors on
// output), so rendering at init is byte-identical to rendering per frame.
var (
	markerSel = styleMarker.Render("▶ ")
	sevLabels = func() (l [model.SeverityCritical + 1]string) {
		for s := range l {
			l[s] = renderSevLabel(model.Severity(s))
		}
		return l
	}()
)

func renderSevLabel(s model.Severity) string {
	return severityStyles[s].Render(pad(s.Short(), 4))
}

// sevLabel returns the padded, styled severity column of a list row.
func sevLabel(s model.Severity) string {
	if s >= 0 && int(s) < len(sevLabels) {
		return sevLabels[s]
	}
	return renderSevLabel(s)
}

func (m Model) emptyMessage(w int) []string {
	switch {
	case len(m.findings) == 0 && m.scanning:
		return []string{m.spin.View() + " scanning…"}
	case len(m.findings) == 0 && m.noLockfiles:
		msg := []string{"No supported lockfiles found", ""}
		for _, l := range strings.Split(wrap("looked for: "+strings.Join(m.cfg.Lockfiles, ", "), w), "\n") {
			msg = append(msg, styleDim.Render(l))
		}
		return msg
	case len(m.findings) == 0 && m.scanErr != nil:
		return []string{styleError.Render("Scan failed"), styleDim.Render("alt+r to retry")}
	case len(m.findings) == 0:
		return []string{"No known vulnerabilities"}
	case len(m.results) == 0:
		return []string{styleDim.Render("No matches")}
	}
	return nil
}

// highlight renders s (which starts at byte offset start in the search key)
// with the matched key offsets highlighted. offs must be sorted ascending, as
// termOffsets returns them; duplicates are fine. A rune is highlighted when
// its first byte is matched. One cursor walk over offs cuts s into runs by
// byte offset, and each run is rendered once. s is valid UTF-8 (setFindings
// sanitizes findings), so the cut bytes equal the re-encoded runes.
func highlight(s string, start int, offs []int, base, hl lipgloss.Style) string {
	if len(offs) == 0 {
		return base.Render(s)
	}
	c, _ := slices.BinarySearch(offs, start)
	if c == len(offs) || offs[c] >= start+len(s) {
		// No match inside s: a single base run, or nothing for an empty s.
		if s == "" {
			return ""
		}
		return base.Render(s)
	}
	var b strings.Builder
	runStart, runHL := 0, false
	write := func(end int) {
		if end == runStart {
			return
		}
		if runHL {
			b.WriteString(hl.Render(s[runStart:end]))
		} else {
			b.WriteString(base.Render(s[runStart:end]))
		}
	}
	for i := range s {
		o := start + i
		for c < len(offs) && offs[c] < o {
			c++
		}
		if isHL := c < len(offs) && offs[c] == o; isHL != runHL {
			write(i)
			runStart, runHL = i, isHL
		}
	}
	write(len(s))
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

	line(styleDetailID.Render(f.ID))
	if len(f.CVEs) > 0 {
		line(styleDetailAlt.Render(strings.Join(f.CVEs, ", ")))
	}
	line("")
	field("Package", f.Package.Name+" "+f.Package.Version)
	field("Ecosystem", f.Package.Ecosystem)
	field("Source", f.Package.Source)
	field("Fixed", fixedText(f))
	field("Severity", severityText(f))
	aliases := orNone(f.Aliases)
	if len(f.Aliases) > 0 {
		aliases = styleDetailAlt.Render(aliases)
	}
	field("Aliases", aliases)
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
	ref := func(u string) {
		b.WriteString(styleURL.Render(wrap(u, w)))
		b.WriteByte('\n')
	}
	ref(OSVURL(f.ID))
	for _, r := range f.References {
		ref(r)
	}
	return strings.TrimRight(b.String(), "\n")
}

type detailer interface{ Details() string }

func (m Model) renderError(w int) string {
	w = max(10, w)
	var b strings.Builder
	b.WriteString(styleError.Render(wrap("Last scan failed: "+model.Sanitize(m.scanErr.Error()), w)))
	var d detailer
	if errors.As(m.scanErr, &d) && d.Details() != "" {
		b.WriteString("\n\n")
		b.WriteString(styleDim.Render("stderr:"))
		b.WriteByte('\n')
		b.WriteString(wrap(model.Sanitize(strings.TrimSpace(d.Details())), w))
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

// errLine returns the sanitized first line of err for one-line status text.
func errLine(err error) string {
	return firstLine(model.Sanitize(err.Error()))
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
