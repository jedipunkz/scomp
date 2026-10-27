package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jedipunkz/scomp/internal/model"
)

func press(s string) tea.KeyPressMsg {
	switch s {
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "backspace":
		return tea.KeyPressMsg{Code: tea.KeyBackspace}
	}
	if c, ok := strings.CutPrefix(s, "alt+"); ok {
		return tea.KeyPressMsg{Code: []rune(c)[0], Mod: tea.ModAlt}
	}
	if c, ok := strings.CutPrefix(s, "ctrl+"); ok {
		code := rune(c[0])
		return tea.KeyPressMsg{Code: code, Mod: tea.ModCtrl}
	}
	r := []rune(s)[0]
	return tea.KeyPressMsg{Code: r, Text: s}
}

func send(t *testing.T, m Model, msgs ...tea.Msg) (Model, tea.Cmd) {
	t.Helper()
	var cmd tea.Cmd
	var tm tea.Model = m
	for _, msg := range msgs {
		tm, cmd = tm.Update(msg)
	}
	return tm.(Model), cmd
}

func typeText(t *testing.T, m Model, s string) Model {
	t.Helper()
	for _, r := range s {
		m, _ = send(t, m, press(string(r)))
	}
	return m
}

func newTestModel(cfg Config) Model {
	if cfg.Findings == nil {
		cfg.Findings = sampleFindings()
	}
	m := New(context.Background(), cfg)
	tm, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	return tm.(Model)
}

func selectedID(m Model) string {
	i, ok := m.selected()
	if !ok {
		return ""
	}
	return m.findings[i].ID
}

func TestKeyStrings(t *testing.T) {
	// Guard the key names handleKey switches on.
	for _, s := range []string{"up", "down", "esc", "alt+s", "alt+e", "alt+f", "alt+r", "alt+o", "alt+i", "ctrl+p", "ctrl+n", "j", "k"} {
		if got := press(s).String(); got != s {
			t.Errorf("press(%q).String() = %q", s, got)
		}
	}
}

func TestNavigationAndQuery(t *testing.T) {
	m := newTestModel(Config{})
	if got := selectedID(m); got != "GHSA-1" {
		t.Fatalf("initial selection = %s, want GHSA-1", got)
	}
	m, _ = send(t, m, press("down"), press("down"))
	if got := selectedID(m); got != "GO-2" {
		t.Errorf("after 2 down = %s, want GO-2", got)
	}
	m, _ = send(t, m, press("up"), press("ctrl+p"), press("ctrl+p"))
	if got := selectedID(m); got != "GHSA-1" {
		t.Errorf("cursor must stop at top, got %s", got)
	}
	m, _ = send(t, m, press("ctrl+n"))
	if got := selectedID(m); got != "GO-1" {
		t.Errorf("ctrl+n = %s, want GO-1", got)
	}

	// "q" goes into the query instead of quitting.
	m = typeText(t, m, "q")
	if m.input.Value() != "q" {
		t.Fatalf("query = %q, want q", m.input.Value())
	}
	m, _ = send(t, m, press("backspace"))
	m = typeText(t, m, "lodash")
	if len(m.results) != 1 || selectedID(m) != "GHSA-1" {
		t.Errorf("query lodash: results=%d selected=%s", len(m.results), selectedID(m))
	}
	if !strings.Contains(m.View().Content, "1/6 findings") {
		t.Error("header must show filtered count")
	}
}

func TestFilters(t *testing.T) {
	m := newTestModel(Config{})
	steps := []struct {
		key  string
		want int
	}{
		{"alt+s", 1}, // critical
		{"alt+s", 3}, // high+
		{"alt+s", 4}, // medium+
		{"alt+s", 6}, // all
		{"alt+e", 4}, // Go
		{"alt+e", 1}, // PyPI
		{"alt+e", 1}, // npm
		{"alt+e", 6}, // all
		{"alt+f", 2}, // fixed only
		{"alt+f", 6},
	}
	// ecosystems are sorted: Go, PyPI, npm
	for i, s := range steps {
		m, _ = send(t, m, press(s.key))
		if len(m.results) != s.want {
			t.Errorf("step %d (%s, %s): %d results, want %d", i, s.key, m.filterLabel(), len(m.results), s.want)
		}
	}
}

func TestFilterKeepsSelection(t *testing.T) {
	m := newTestModel(Config{})
	m, _ = send(t, m, press("down"))  // GO-1 (high)
	m, _ = send(t, m, press("alt+e")) // Go
	if got := selectedID(m); got != "GO-1" {
		t.Errorf("selection after filter = %s, want GO-1", got)
	}
}

func TestRescanKeepsSelection(t *testing.T) {
	t.Run("same findings", func(t *testing.T) {
		m := newTestModel(Config{})
		m, _ = send(t, m, press("down"), scanDoneMsg{findings: sampleFindings()})
		if got := selectedID(m); got != "GO-1" {
			t.Errorf("selection after same rescan = %s, want GO-1", got)
		}
	})
	t.Run("changed findings keep ID", func(t *testing.T) {
		m := newTestModel(Config{})
		m, _ = send(t, m, press("down"))
		fs := append(sampleFindings(), model.Finding{ID: "NEW-9", Severity: model.SeverityCritical, Package: model.Package{Name: "zzz", Ecosystem: "npm"}})
		m, _ = send(t, m, scanDoneMsg{findings: fs})
		if got := selectedID(m); got != "GO-1" {
			t.Errorf("selection after changed rescan = %s, want GO-1", got)
		}
		if idx, _ := m.selected(); m.previewFor != idx {
			t.Errorf("preview shows %d, selected index is %d", m.previewFor, idx)
		}
	})
	t.Run("selected finding gone", func(t *testing.T) {
		m := newTestModel(Config{})
		m, _ = send(t, m, press("down"))
		var fs []model.Finding
		for _, f := range sampleFindings() {
			if f.ID != "GO-1" {
				fs = append(fs, f)
			}
		}
		m, _ = send(t, m, scanDoneMsg{findings: fs})
		if got := selectedID(m); got != "GHSA-1" {
			t.Errorf("selection after removal = %q, want first row GHSA-1", got)
		}
		if m.cursor < 0 || m.cursor >= len(m.results) {
			t.Errorf("cursor %d out of range [0,%d)", m.cursor, len(m.results))
		}
	})
}

func TestDetailScrollKeys(t *testing.T) {
	// Content taller than the pane is needed for scrolling.
	long := model.Finding{
		ID:      "LONG-1",
		Details: strings.Repeat("line\n", 60),
		Package: model.Package{Name: "pkg"},
	}
	m := newTestModel(Config{Findings: []model.Finding{long}})
	if m.preview.YOffset() != 0 {
		t.Fatalf("initial YOffset = %d", m.preview.YOffset())
	}
	m, _ = send(t, m, press("j"))
	if m.preview.YOffset() != 1 {
		t.Errorf("j: YOffset = %d, want 1", m.preview.YOffset())
	}
	m, _ = send(t, m, press("k"))
	if m.preview.YOffset() != 0 {
		t.Errorf("k: YOffset = %d, want 0", m.preview.YOffset())
	}
}

func TestQTypesIntoQuery(t *testing.T) {
	m := newTestModel(Config{})
	m, _ = send(t, m, press("q"))
	if m.input.Value() != "q" {
		t.Errorf("query = %q, want q", m.input.Value())
	}
}

func TestQuitKeys(t *testing.T) {
	for _, k := range []string{"esc", "ctrl+c"} {
		m := newTestModel(Config{})
		_, cmd := send(t, m, press(k))
		if cmd == nil {
			t.Fatalf("%s: no cmd", k)
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Errorf("%s did not quit", k)
		}
	}
}

func TestScanLifecycle(t *testing.T) {
	var saved []model.Finding
	scanned := []model.Finding{{ID: "NEW-1", Severity: model.SeverityLow, Package: model.Package{Name: "x"}}}
	m := newTestModel(Config{
		Findings:    []model.Finding{},
		ScanOnStart: true,
		Scan:        func(context.Context) ([]model.Finding, error) { return scanned, nil },
		OnScanned:   func(fs []model.Finding) error { saved = fs; return nil },
	})

	m, cmd := send(t, m, startScanMsg{})
	if !m.scanning || cmd == nil {
		t.Fatal("scan did not start")
	}
	if !strings.Contains(m.View().Content, "scanning") {
		t.Error("view must show scanning state")
	}
	// alt+r while scanning must not start a second scan.
	if _, c := send(t, m, press("alt+r")); c != nil {
		t.Error("alt+r during scan must be ignored")
	}

	m, _ = send(t, m, scanDoneMsg{findings: scanned})
	if m.scanning || len(m.findings) != 1 || selectedID(m) != "NEW-1" {
		t.Fatalf("after scan: scanning=%v findings=%d", m.scanning, len(m.findings))
	}
	if len(saved) != 1 {
		t.Error("OnScanned must be called")
	}
}

func TestScanStatusKeepsCursorVisible(t *testing.T) {
	cfg := Config{OnScanned: func([]model.Finding) error { return errors.New("disk full") }}
	m := newTestModel(cfg)
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 120, Height: 9}, press("pgdown"), press("pgdown"))
	if m.offset == 0 {
		t.Fatal("precondition: list must be scrolled")
	}
	m, _ = send(t, m, scanDoneMsg{findings: sampleFindings()})
	if !strings.Contains(m.statusLine(), "cache write failed") {
		t.Fatalf("status = %q, want cache write failure", m.statusLine())
	}
	if m.cursor < m.offset || m.cursor >= m.offset+m.listHeight() {
		t.Errorf("cursor %d outside rows [%d, %d)", m.cursor, m.offset, m.offset+m.listHeight())
	}
}

func TestRescanKeepsHeaderCounts(t *testing.T) {
	m := newTestModel(Config{})
	const want = "6 findings (C:1 H:2 M:1 L:1 ?:1)"
	if got := ansi.Strip(m.headerLine()); !strings.Contains(got, want) {
		t.Fatalf("initial header = %q, want %q", got, want)
	}
	for i := range 2 {
		m, _ = send(t, m, scanDoneMsg{findings: sampleFindings()})
		if got := ansi.Strip(m.headerLine()); !strings.Contains(got, want) {
			t.Errorf("rescan %d header = %q, want %q", i+1, got, want)
		}
	}
}

func TestEmptyScanResetsHeaderAndWidths(t *testing.T) {
	const want = "0 findings (C:0 H:0 M:0 L:0)"
	cases := []struct {
		name string
		msg  tea.Msg
	}{
		{"empty scan", scanDoneMsg{findings: []model.Finding{}}},
		{"no lockfiles", scanDoneMsg{err: ErrNoLockfiles}},
	}
	for _, c := range cases {
		m := newTestModel(Config{})
		m, _ = send(t, m, c.msg)
		if got := ansi.Strip(m.headerLine()); !strings.Contains(got, want) {
			t.Errorf("%s: header = %q, want %q", c.name, got, want)
		}
		if m.nameMaxW != 0 || m.verMaxW != 0 || m.idMaxW != 0 {
			t.Errorf("%s: widths = %d/%d/%d, want 0/0/0", c.name, m.nameMaxW, m.verMaxW, m.idMaxW)
		}
	}
}

func TestScanErrorKeepsCachedList(t *testing.T) {
	m := newTestModel(Config{CachedAt: time.Now().Add(-3 * time.Hour)})
	if !strings.Contains(m.View().Content, "cached 3h ago") {
		t.Error("header must show cache age")
	}
	m, _ = send(t, m, scanDoneMsg{err: &stderrErr{"boom", "full stderr text"}})
	if len(m.findings) != 6 {
		t.Errorf("cached findings dropped: %d", len(m.findings))
	}
	v := m.View().Content
	if !strings.Contains(v, "error: boom") {
		t.Error("error must be shown in status line")
	}
	if !strings.Contains(v, "full stderr text") {
		t.Error("detail pane must show full stderr")
	}
}

type stderrErr struct{ msg, details string }

func (e *stderrErr) Error() string   { return e.msg }
func (e *stderrErr) Details() string { return e.details }

func TestEmptyStates(t *testing.T) {
	m := newTestModel(Config{Findings: []model.Finding{}, Lockfiles: []string{"go.mod"}})
	m, _ = send(t, m, scanDoneMsg{findings: []model.Finding{}})
	if !strings.Contains(m.View().Content, "No known vulnerabilities") {
		t.Error("missing no-vulnerabilities message")
	}
	m, _ = send(t, m, scanDoneMsg{err: ErrNoLockfiles})
	v := m.View().Content
	if !strings.Contains(v, "No supported lockfiles found") || !strings.Contains(v, "go.mod") {
		t.Error("missing no-lockfiles message")
	}

	long := make([]string, 40)
	for i := range long {
		long[i] = fmt.Sprintf("pattern-%02d.lock", i)
	}
	m = newTestModel(Config{Findings: []model.Finding{}, Lockfiles: long})
	m, _ = send(t, m, scanDoneMsg{err: ErrNoLockfiles})
	if v := m.View().Content; !strings.Contains(v, "pattern-12.lock") {
		t.Error("looked-for list is truncated instead of wrapped")
	}

	m = newTestModel(Config{})
	m = typeText(t, m, "zzzzzz")
	if !strings.Contains(m.View().Content, "No matches") {
		t.Error("missing no-matches message")
	}
}

func TestOpenURL(t *testing.T) {
	var opened string
	m := newTestModel(Config{OpenURL: func(u string) error { opened = u; return nil }})
	_, cmd := send(t, m, press("alt+o"))
	if cmd == nil {
		t.Fatal("alt+o returned no cmd")
	}
	cmd()
	if opened != "https://osv.dev/vulnerability/GHSA-1" {
		t.Errorf("opened %q", opened)
	}

	m = newTestModel(Config{OpenURL: func(string) error { return errors.New("no browser") }})
	_, cmd = send(t, m, press("alt+o"))
	m, _ = send(t, m, cmd())
	if !strings.Contains(m.View().Content, "no browser") {
		t.Error("open error must be shown")
	}
}

func TestDetailPane(t *testing.T) {
	m := newTestModel(Config{})
	v := m.View().Content
	if !strings.Contains(v, "Ecosystem :") {
		t.Error("bottom detail pane must show the selected finding")
	}
	if !strings.Contains(v, "GHSA-1") {
		t.Error("detail pane must show the selected finding's ID")
	}

	// Too short for a pane: list only.
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 60, Height: 8})
	if strings.Contains(m.View().Content, "Ecosystem :") {
		t.Error("short terminal must hide the detail pane")
	}

	// Pane follows the selection.
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 120, Height: 30}, press("down"))
	if !strings.Contains(m.View().Content, "GO-1") {
		t.Error("detail pane must follow the selection")
	}
}

func TestPaneTitles(t *testing.T) {
	m := newTestModel(Config{})
	v := m.View().Content
	if !strings.Contains(v, "Findings 6/6") || !strings.Contains(v, " Detail ") {
		t.Error("pane title bars must be shown")
	}
	if !strings.Contains(v, "↑↓") || !strings.Contains(v, "rescan") {
		t.Error("help bar must show the key bindings")
	}
}

func TestShortTerminalLayout(t *testing.T) {
	m := newTestModel(Config{})
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 40, Height: 6})
	lines := strings.Split(m.View().Content, "\n")
	if len(lines) > 6 {
		t.Fatalf("%d lines exceed height 6", len(lines))
	}
	if m.detailHeight() != 0 {
		t.Errorf("detailHeight = %d, want 0", m.detailHeight())
	}
}

func TestViewFitsWindow(t *testing.T) {
	for _, size := range [][2]int{{120, 30}, {80, 24}, {40, 10}, {20, 5}} {
		m := newTestModel(Config{})
		m, _ = send(t, m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		lines := strings.Split(m.View().Content, "\n")
		if len(lines) > size[1] {
			t.Errorf("%v: %d lines exceed height", size, len(lines))
		}
		for i, l := range lines {
			if w := lipglossWidth(l); w > size[0] {
				t.Errorf("%v: line %d width %d exceeds %d", size, i, w, size[0])
			}
		}
	}
}

func TestViewFitsHeightWithHelpBar(t *testing.T) {
	heights := []int{30}
	for h := 3; h <= 14; h++ {
		heights = append(heights, h)
	}
	for _, status := range []string{"", "scan done"} {
		for _, h := range heights {
			m := newTestModel(Config{})
			m.status = status
			m, _ = send(t, m, tea.WindowSizeMsg{Width: 120, Height: h})
			lines := strings.Split(m.View().Content, "\n")
			if len(lines) > h {
				t.Errorf("height %d status %q: %d lines exceed height", h, status, len(lines))
			}
			// Help needs header, list title, status (if set) and help rows.
			need := headerLines + 1 + chromeLines
			if status != "" {
				need++
			}
			if h >= need && !strings.Contains(m.View().Content, "rescan") {
				t.Errorf("height %d status %q: help bar missing (%d lines)", h, status, len(lines))
			}
		}
	}
}

func lipglossWidth(s string) int { return ansi.StringWidth(s) }

func TestHeaderKeepsStatusVisible(t *testing.T) {
	m := newTestModel(Config{Title: "/very/long/path/" + strings.Repeat("x", 200) + "/repo", CachedAt: time.Now().Add(-time.Hour)})
	header := strings.Split(m.View().Content, "\n")[0]
	if !strings.Contains(header, "cached 1h ago") || !strings.Contains(header, "x/repo") {
		t.Errorf("header = %q", header)
	}
}

func TestTitleAndScannerPathAreSanitized(t *testing.T) {
	const payload = "\x1b]52;c;SGVsbG8=\x07\x1b]2;pwned\x07"
	cfg := Config{
		Title:       "github.com/x/y" + payload + "\x07\nlf",
		ScannerPath: "osv-scanner" + payload + "\x1b[31m",
	}
	m := newTestModel(cfg)
	v := m.View()

	if strings.ContainsFunc(v.WindowTitle, unicode.IsControl) {
		t.Errorf("WindowTitle has control characters: %q", v.WindowTitle)
	}
	if !strings.Contains(v.WindowTitle, "github.com/x/ylf") {
		t.Errorf("WindowTitle = %q, want sanitized title", v.WindowTitle)
	}

	header := m.headerLine()
	if strings.Contains(header, "\x1b]") || strings.Contains(header, "\x07") || strings.Contains(header, "SGVsbG8=") || strings.Contains(header, "pwned") {
		t.Errorf("header contains an OSC payload: %q", header)
	}
	if strings.ContainsFunc(ansi.Strip(header), unicode.IsControl) {
		t.Errorf("header has control characters after stripping SGR: %q", header)
	}
}
