package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	}
	if c, ok := strings.CutPrefix(s, "ctrl+"); ok {
		code := rune(c[0])
		if c == "tab" {
			code = tea.KeyTab
		}
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
	for _, s := range []string{"up", "down", "enter", "esc", "ctrl+s", "ctrl+e", "ctrl+f", "ctrl+r", "ctrl+o", "ctrl+p", "ctrl+n", "j", "k", "q"} {
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
		{"ctrl+s", 1}, // critical
		{"ctrl+s", 3}, // high+
		{"ctrl+s", 4}, // medium+
		{"ctrl+s", 6}, // all
		{"ctrl+e", 4}, // Go
		{"ctrl+e", 1}, // PyPI
		{"ctrl+e", 1}, // npm
		{"ctrl+e", 6}, // all
		{"ctrl+f", 2}, // fixed only
		{"ctrl+f", 6},
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
	m, _ = send(t, m, press("down"))   // GO-1 (high)
	m, _ = send(t, m, press("ctrl+e")) // Go
	if got := selectedID(m); got != "GO-1" {
		t.Errorf("selection after filter = %s, want GO-1", got)
	}
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

func TestDetailBackKeys(t *testing.T) {
	m := newTestModel(Config{})
	m, _ = send(t, m, press("enter"))
	if !m.detail {
		t.Fatal("enter must show detail")
	}
	m, cmd := send(t, m, press("q"))
	if m.detail {
		t.Error("q must return to the list")
	}
	if cmd != nil {
		t.Error("q must not quit from the detail view")
	}
	m, _ = send(t, m, press("enter"))
	m, _ = send(t, m, press("esc"))
	if m.detail {
		t.Error("esc must return to the list")
	}
	_, cmd = send(t, m, press("esc"))
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("esc on the list must quit")
	}

	// On the list, q goes into the query instead.
	m = newTestModel(Config{})
	m, _ = send(t, m, press("q"))
	if m.input.Value() != "q" || m.detail {
		t.Errorf("query = %q, detail = %v; want q, false", m.input.Value(), m.detail)
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
	// ctrl+r while scanning must not start a second scan.
	if _, c := send(t, m, press("ctrl+r")); c != nil {
		t.Error("ctrl+r during scan must be ignored")
	}

	m, _ = send(t, m, scanDoneMsg{findings: scanned})
	if m.scanning || len(m.findings) != 1 || selectedID(m) != "NEW-1" {
		t.Fatalf("after scan: scanning=%v findings=%d", m.scanning, len(m.findings))
	}
	if len(saved) != 1 {
		t.Error("OnScanned must be called")
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
	m, _ = send(t, m, press("enter"))
	if !strings.Contains(m.View().Content, "full stderr text") {
		t.Error("detail view must show full stderr")
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

	m = newTestModel(Config{})
	m = typeText(t, m, "zzzzzz")
	if !strings.Contains(m.View().Content, "No matches") {
		t.Error("missing no-matches message")
	}
}

func TestOpenURL(t *testing.T) {
	var opened string
	m := newTestModel(Config{OpenURL: func(u string) error { opened = u; return nil }})
	_, cmd := send(t, m, press("ctrl+o"))
	if cmd == nil {
		t.Fatal("ctrl+o returned no cmd")
	}
	cmd()
	if opened != "https://osv.dev/vulnerability/GHSA-1" {
		t.Errorf("opened %q", opened)
	}

	m = newTestModel(Config{OpenURL: func(string) error { return errors.New("no browser") }})
	_, cmd = send(t, m, press("ctrl+o"))
	m, _ = send(t, m, cmd())
	if !strings.Contains(m.View().Content, "no browser") {
		t.Error("open error must be shown")
	}
}

func TestDetailPaneAndToggle(t *testing.T) {
	m := newTestModel(Config{})
	v := m.View().Content
	if !strings.Contains(v, "Ecosystem :") {
		t.Error("bottom detail pane must show the selected finding")
	}
	if !strings.Contains(v, "GHSA-1") {
		t.Error("detail pane must show the selected finding's ID")
	}
	m, _ = send(t, m, press("enter"))
	if !m.detail || !strings.Contains(m.View().Content, "Ecosystem :") {
		t.Error("enter must show full-screen detail")
	}
	m, _ = send(t, m, press("enter"))
	if m.detail || !strings.Contains(m.View().Content, "Ecosystem :") {
		t.Error("enter must return to the list with the detail pane")
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

func lipglossWidth(s string) int { return ansi.StringWidth(s) }

func TestHeaderKeepsStatusVisible(t *testing.T) {
	m := newTestModel(Config{Title: "/very/long/path/" + strings.Repeat("x", 200) + "/repo", CachedAt: time.Now().Add(-time.Hour)})
	header := strings.Split(m.View().Content, "\n")[0]
	if !strings.Contains(header, "cached 1h ago") || !strings.Contains(header, "x/repo") {
		t.Errorf("header = %q", header)
	}
}
