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

func key(s string) tea.KeyPressMsg {
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
	if c, ok := strings.CutPrefix(s, "ctrl+"); ok {
		return tea.KeyPressMsg{Code: rune(c[0]), Mod: tea.ModCtrl}
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
		m, _ = send(t, m, key(string(r)))
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
	for _, s := range []string{"up", "down", "enter", "esc", "ctrl+s", "ctrl+e", "ctrl+f", "ctrl+r", "ctrl+o", "ctrl+p", "ctrl+n"} {
		if got := key(s).String(); got != s {
			t.Errorf("key(%q).String() = %q", s, got)
		}
	}
}

func TestNavigationAndQuery(t *testing.T) {
	m := newTestModel(Config{})
	if got := selectedID(m); got != "GHSA-1" {
		t.Fatalf("initial selection = %s, want GHSA-1", got)
	}
	m, _ = send(t, m, key("down"), key("down"))
	if got := selectedID(m); got != "GO-2" {
		t.Errorf("after 2 down = %s, want GO-2", got)
	}
	m, _ = send(t, m, key("up"), key("ctrl+p"), key("ctrl+p"))
	if got := selectedID(m); got != "GHSA-1" {
		t.Errorf("cursor must stop at top, got %s", got)
	}
	m, _ = send(t, m, key("ctrl+n"))
	if got := selectedID(m); got != "GO-1" {
		t.Errorf("ctrl+n = %s, want GO-1", got)
	}

	// "q" goes into the query instead of quitting.
	m = typeText(t, m, "q")
	if m.input.Value() != "q" {
		t.Fatalf("query = %q, want q", m.input.Value())
	}
	m, _ = send(t, m, key("backspace"))
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
		m, _ = send(t, m, key(s.key))
		if len(m.results) != s.want {
			t.Errorf("step %d (%s, %s): %d results, want %d", i, s.key, m.filterLabel(), len(m.results), s.want)
		}
	}
}

func TestFilterKeepsSelection(t *testing.T) {
	m := newTestModel(Config{})
	m, _ = send(t, m, key("down"))   // GO-1 (high)
	m, _ = send(t, m, key("ctrl+e")) // Go
	if got := selectedID(m); got != "GO-1" {
		t.Errorf("selection after filter = %s, want GO-1", got)
	}
}

func TestQuitKeys(t *testing.T) {
	for _, k := range []string{"esc", "ctrl+c"} {
		m := newTestModel(Config{})
		_, cmd := send(t, m, key(k))
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
	if _, c := send(t, m, key("ctrl+r")); c != nil {
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
	m, _ = send(t, m, key("enter"))
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
	_, cmd := send(t, m, key("ctrl+o"))
	if cmd == nil {
		t.Fatal("ctrl+o returned no cmd")
	}
	cmd()
	if opened != "https://osv.dev/vulnerability/GHSA-1" {
		t.Errorf("opened %q", opened)
	}

	m = newTestModel(Config{OpenURL: func(string) error { return errors.New("no browser") }})
	_, cmd = send(t, m, key("ctrl+o"))
	m, _ = send(t, m, cmd())
	if !strings.Contains(m.View().Content, "no browser") {
		t.Error("open error must be shown")
	}
}

func TestDetailToggleAndNarrowLayout(t *testing.T) {
	m := newTestModel(Config{})
	if !strings.Contains(m.View().Content, "│") {
		t.Error("wide layout must show side preview")
	}
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 60, Height: 20})
	if strings.Contains(m.View().Content, "Ecosystem :") {
		t.Error("narrow layout must hide preview")
	}
	m, _ = send(t, m, key("enter"))
	if !m.detail || !strings.Contains(m.View().Content, "Ecosystem :") {
		t.Error("enter must show full-screen detail")
	}
	m, _ = send(t, m, key("enter"))
	if m.detail {
		t.Error("enter must return to the list")
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

func TestSanitize(t *testing.T) {
	in := "ok\x1b[31mred\x1b[0m\x1b]0;title\x07\r\bend\ttab\nline"
	if got, want := sanitize(in), "okredend tab\nline"; got != want {
		t.Errorf("sanitize = %q, want %q", got, want)
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
