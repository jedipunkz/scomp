package tui

import (
	"context"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/jedipunkz/scomp/internal/model"
)

// plainView is the rendered view with all styling stripped, for text
// assertions on styled content.
func plainView(m Model) string {
	return ansi.Strip(m.View().Content)
}

// issueCfg wires callbacks capturing what the flow did. search returns
// found and searchErr for every call.
func issueCfg(found []ExistingIssue, searchErr error) (Config, *[]model.Finding, *[]model.Finding, *[]int) {
	var searched, created []model.Finding
	var edited []int
	return Config{
		SearchIssues: func(_ context.Context, f model.Finding) ([]ExistingIssue, error) {
			searched = append(searched, f)
			return found, searchErr
		},
		CreateIssue: func(_ context.Context, f model.Finding) (string, error) {
			created = append(created, f)
			return "https://github.com/o/r/issues/13", nil
		},
		EditIssue: func(_ context.Context, f model.Finding, n int) (string, error) {
			edited = append(edited, n)
			return "https://github.com/o/r/issues/12", nil
		},
	}, &searched, &created, &edited
}

// openPrompt drives one ctrl+i search to its result.
func openPrompt(t *testing.T, m Model) Model {
	t.Helper()
	m, cmd := send(t, m, press("ctrl+i"))
	if cmd == nil {
		t.Fatal("ctrl+i returned no cmd")
	}
	m, _ = send(t, m, cmd())
	return m
}

func TestIssueConfirmCreates(t *testing.T) {
	cfg, searched, created, _ := issueCfg(nil, nil)
	m := newTestModel(cfg)
	m, _ = send(t, m, press("down")) // GO-1
	m = openPrompt(t, m)
	if m.issueState != issueConfirm {
		t.Fatalf("state = %v, want confirm", m.issueState)
	}
	if len(*searched) != 1 || (*searched)[0].ID != "GO-1" {
		t.Fatalf("searched = %+v, want GO-1", *searched)
	}
	if v := plainView(m); !strings.Contains(v, "GO-1") || !strings.Contains(v, "Create a GitHub issue for this finding?") ||
		!strings.Contains(v, "y create") || !strings.Contains(v, "c cancel") {
		t.Errorf("confirm popup not shown:\n%s", v)
	}
	m, cmd := send(t, m, press("y"))
	if cmd == nil || m.issueState != issueRunning {
		t.Fatalf("y: cmd=%v state=%v", cmd != nil, m.issueState)
	}
	m, _ = send(t, m, cmd())
	if len(*created) != 1 || (*created)[0].ID != "GO-1" {
		t.Fatalf("created = %+v, want GO-1", *created)
	}
	if m.issueState != issueIdle {
		t.Errorf("state after done = %v, want idle", m.issueState)
	}
	if v := m.View().Content; !strings.Contains(v, "created https://github.com/o/r/issues/13") {
		t.Errorf("created URL not shown:\n%s", v)
	}
}

func TestIssueConfirmCancels(t *testing.T) {
	for _, key := range []string{"c", "esc", "q"} {
		cfg, _, created, _ := issueCfg(nil, nil)
		m := openPrompt(t, newTestModel(cfg))
		m, cmd := send(t, m, press(key))
		if m.issueState != issueIdle || cmd != nil {
			t.Fatalf("%s: state = %v, want idle and no cmd", key, m.issueState)
		}
		if len(*created) != 0 {
			t.Errorf("%s: created %+v", key, *created)
		}
		if v := m.View().Content; !strings.Contains(v, "Findings") {
			t.Errorf("%s: normal view not restored:\n%s", key, v)
		}
	}
}

func TestIssueChooseOverride(t *testing.T) {
	cfg, searched, created, edited := issueCfg(
		[]ExistingIssue{{Number: 12, Title: "old title", State: "open", URL: "https://github.com/o/r/issues/12"}}, nil)
	m := newTestModel(cfg)
	m, _ = send(t, m, press("down")) // GO-1
	m = openPrompt(t, m)
	if m.issueState != issueChoose {
		t.Fatalf("state = %v, want choose", m.issueState)
	}
	if v := plainView(m); !strings.Contains(v, "issue #12 [open]: old title") || !strings.Contains(v, "Override it, or create a duplicate?") ||
		!strings.Contains(v, "o override") || !strings.Contains(v, "d duplicate") || !strings.Contains(v, "c cancel") {
		t.Errorf("choose popup not shown:\n%s", v)
	}
	m, cmd := send(t, m, press("o"))
	if cmd == nil || m.issueState != issueRunning {
		t.Fatalf("o: cmd=%v state=%v", cmd != nil, m.issueState)
	}
	m, _ = send(t, m, cmd())
	if len(*edited) != 1 || (*edited)[0] != 12 {
		t.Errorf("edited issues = %v, want [12]", *edited)
	}
	if len(*created) != 0 {
		t.Errorf("created %+v, want none", *created)
	}
	if len(*searched) != 1 || (*searched)[0].ID != "GO-1" {
		t.Errorf("override must use the selected finding, got %+v", *searched)
	}
	if v := m.View().Content; !strings.Contains(v, "updated https://github.com/o/r/issues/12") {
		t.Errorf("updated URL not shown:\n%s", v)
	}
}

func TestIssueChooseDuplicate(t *testing.T) {
	cfg, _, created, edited := issueCfg(
		[]ExistingIssue{{Number: 12, Title: "old title", State: "closed", URL: "https://github.com/o/r/issues/12"}}, nil)
	m := newTestModel(cfg)
	m, _ = send(t, m, press("down")) // GO-1
	m = openPrompt(t, m)
	m, cmd := send(t, m, press("d"))
	m, _ = send(t, m, cmd())
	if len(*created) != 1 || (*created)[0].ID != "GO-1" {
		t.Errorf("created = %+v, want GO-1", *created)
	}
	if len(*edited) != 0 {
		t.Errorf("edited = %v, want none", *edited)
	}
	if v := m.View().Content; !strings.Contains(v, "created https://github.com/o/r/issues/13") {
		t.Errorf("created URL not shown:\n%s", v)
	}
}

func TestIssueChooseSwallowsOtherKeys(t *testing.T) {
	cfg, _, created, edited := issueCfg(
		[]ExistingIssue{{Number: 12, Title: "t", State: "open", URL: "u"}}, nil)
	m := openPrompt(t, newTestModel(cfg))
	for _, key := range []string{"x", "y", "G", "enter"} {
		m, _ = send(t, m, press(key))
		if m.issueState != issueChoose {
			t.Fatalf("%s: state = %v", key, m.issueState)
		}
		if m.input.Value() != "" {
			t.Fatalf("%s typed into the query: %q", key, m.input.Value())
		}
	}
	if len(*created) != 0 || len(*edited) != 0 {
		t.Errorf("created=%v edited=%v, want none", *created, *edited)
	}
}

func TestIssuePopupSanitizesTitles(t *testing.T) {
	cfg, _, _, _ := issueCfg(
		[]ExistingIssue{{Number: 3, Title: "bad\x1b[31mtitle", State: "open", URL: "https://github.com/o/r/issues/3"}}, nil)
	m := openPrompt(t, newTestModel(cfg))
	if v := plainView(m); !strings.Contains(v, "badtitle") {
		t.Errorf("gh-provided title must be sanitized:\n%s", v)
	}
}

func TestIssueSearchError(t *testing.T) {
	cfg, _, _, _ := issueCfg(nil, context.DeadlineExceeded)
	m := openPrompt(t, newTestModel(cfg))
	if m.issueState != issueIdle {
		t.Fatalf("state = %v, want idle", m.issueState)
	}
	if v := m.View().Content; !strings.Contains(v, "search issues: context deadline exceeded") {
		t.Errorf("search error not shown:\n%s", v)
	}
}

func TestIssueCreateError(t *testing.T) {
	cfg, _, _, _ := issueCfg(nil, nil)
	cfg.CreateIssue = func(context.Context, model.Finding) (string, error) {
		return "", context.DeadlineExceeded
	}
	m := openPrompt(t, newTestModel(cfg))
	m, cmd := send(t, m, press("y"))
	m, _ = send(t, m, cmd())
	if m.issueState != issueIdle {
		t.Fatalf("state = %v, want idle", m.issueState)
	}
	if v := m.View().Content; !strings.Contains(v, "create issue: context deadline exceeded") {
		t.Errorf("create error not shown:\n%s", v)
	}
}

func TestIssueKeyAliases(t *testing.T) {
	for _, key := range []string{"tab", "ctrl+tab"} {
		cfg, searched, _, _ := issueCfg(nil, nil)
		m := newTestModel(cfg)
		m, cmd := send(t, m, press(key))
		if cmd == nil || m.issueState != issueSearching {
			t.Fatalf("%s: cmd=%v state=%v", key, cmd != nil, m.issueState)
		}
		m, _ = send(t, m, cmd())
		if m.issueState != issueConfirm {
			t.Fatalf("%s: state after search = %v", key, m.issueState)
		}
		if len(*searched) != 1 || (*searched)[0].ID != "GHSA-1" {
			t.Fatalf("%s: searched %+v", key, *searched)
		}
		m, _ = send(t, m, press("c"))
	}
}

func TestIssueSearchingEscBacksOutAndReSearch(t *testing.T) {
	cfg, searched, _, _ := issueCfg(nil, nil)
	m := newTestModel(cfg)
	m, first := send(t, m, press("ctrl+i"))
	// esc while searching backs out instead of quitting.
	m, _ = send(t, m, press("esc"))
	if m.issueState != issueIdle {
		t.Fatalf("state = %v, want idle", m.issueState)
	}
	// ctrl+i again retargets; the first result is stale and dropped.
	m, second := send(t, m, press("ctrl+i"))
	m, _ = send(t, m, first())
	if m.issueState != issueSearching {
		t.Fatalf("stale result opened a prompt: %v", m.issueState)
	}
	m, _ = send(t, m, second())
	if m.issueState != issueConfirm {
		t.Fatalf("fresh result ignored: %v", m.issueState)
	}
	m, _ = send(t, m, press("c"))
	if len(*searched) != 2 {
		t.Errorf("searched %d times, want 2", len(*searched))
	}
}

func TestIssueNoSelectionAndNoCallbacks(t *testing.T) {
	// Nothing selected: no prompt.
	m := newTestModel(Config{Findings: []model.Finding{}})
	m, cmd := send(t, m, press("ctrl+i"))
	if cmd != nil || m.issueState != issueIdle {
		t.Errorf("empty list: cmd=%v state=%v", cmd != nil, m.issueState)
	}
	// SearchIssues nil: ctrl+i disabled.
	m = newTestModel(Config{})
	m, cmd = send(t, m, press("ctrl+i"))
	if cmd != nil || m.issueState != issueIdle {
		t.Errorf("no callbacks: cmd=%v state=%v", cmd != nil, m.issueState)
	}
}
