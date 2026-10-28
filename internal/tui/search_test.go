package tui

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/jedipunkz/scomp/internal/model"
)

func sampleFindings() []model.Finding {
	return []model.Finding{
		{ID: "PYSEC-1", Severity: model.SeverityMedium, Summary: "Proxy-Authorization leak", Package: model.Package{Name: "requests", Ecosystem: "PyPI"}, FixedVersions: []string{"2.31.0"}},
		{ID: "GO-2", Severity: model.SeverityHigh, Summary: "HTTP/2 rapid reset", Package: model.Package{Name: "golang.org/x/net", Ecosystem: "Go"}, CVEs: []string{"CVE-2023-44487"}},
		{ID: "GO-1", Severity: model.SeverityHigh, Summary: "CONTINUATION flood in net/http", Package: model.Package{Name: "golang.org/x/net", Ecosystem: "Go"}, FixedVersions: []string{"0.23.0"}},
		{ID: "GHSA-1", Severity: model.SeverityCritical, Summary: "Prototype pollution", Package: model.Package{Name: "lodash", Ecosystem: "npm"}},
		{ID: "GO-3", Severity: model.SeverityUnknown, Summary: "Something", Package: model.Package{Name: "a.dev/z", Ecosystem: "Go"}},
		{ID: "GO-4", Severity: model.SeverityLow, Summary: "Low thing", Package: model.Package{Name: "a.dev/y", Ecosystem: "Go"}},
	}
}

// search runs Search without a reused buffer and drops the terms, for tests
// that only check which findings match.
func search(fs []model.Finding, norms []Normalized, query string, f Filter) []Result {
	rs, _ := Search(nil, fs, norms, query, f)
	return rs
}

func ids(fs []model.Finding, rs []Result) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, fs[r.Index].ID)
	}
	return out
}

func normOf(fs []model.Finding) []Normalized {
	norms := make([]Normalized, len(fs))
	for i, f := range fs {
		norms[i], _ = Normalize(f)
	}
	return norms
}

func TestSearch(t *testing.T) {
	fs := sampleFindings()
	model.SortFindings(fs)
	norms := normOf(fs)

	tests := []struct {
		name   string
		query  string
		filter Filter
		want   []string
	}{
		{name: "all", want: []string{"GHSA-1", "GO-1", "GO-2", "PYSEC-1", "GO-4", "GO-3"}},
		{name: "critical only", filter: Filter{MinSeverity: model.SeverityCritical}, want: []string{"GHSA-1"}},
		{name: "high and above", filter: Filter{MinSeverity: model.SeverityHigh}, want: []string{"GHSA-1", "GO-1", "GO-2"}},
		{name: "medium and above", filter: Filter{MinSeverity: model.SeverityMedium}, want: []string{"GHSA-1", "GO-1", "GO-2", "PYSEC-1"}},
		{name: "ecosystem", filter: Filter{Ecosystem: "Go"}, want: []string{"GO-1", "GO-2", "GO-4", "GO-3"}},
		{name: "fixed only", filter: Filter{FixedOnly: true}, want: []string{"GO-1", "PYSEC-1"}},
		{name: "query by CVE", query: "CVE-2023-44487", want: []string{"GO-2"}},
		{name: "query by summary word", query: "lodash", want: []string{"GHSA-1"}},
		{name: "query is case-insensitive", query: "LODASH", want: []string{"GHSA-1"}},
		{name: "filter applies before query", query: "net", filter: Filter{FixedOnly: true}, want: []string{"GO-1"}},
		{name: "no match", query: "zzzzzz", want: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ids(fs, search(fs, norms, tt.query, tt.filter))
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSearchTiesKeepSortedOrder(t *testing.T) {
	fs := []model.Finding{
		{ID: "B", Severity: model.SeverityLow, Package: model.Package{Name: "pkg"}},
		{ID: "A", Severity: model.SeverityHigh, Package: model.Package{Name: "pkg"}},
	}
	model.SortFindings(fs)
	got := ids(fs, search(fs, normOf(fs), "pkg", Filter{}))
	if want := []string{"A", "B"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestQueryFilters(t *testing.T) {
	fs := sampleFindings()
	model.SortFindings(fs)
	norms := normOf(fs)

	tests := []struct {
		name  string
		query string
		want  []string
	}{
		{name: "severity exact", query: "severity:high", want: []string{"GO-1", "GO-2"}},
		{name: "severity shorthand", query: "sev:high", want: []string{"GO-1", "GO-2"}},
		{name: "severity list", query: "severity:critical,medium", want: []string{"GHSA-1", "PYSEC-1"}},
		{name: "severity at least", query: "severity:>=high", want: []string{"GHSA-1", "GO-1", "GO-2"}},
		{name: "severity above", query: "severity:>high", want: []string{"GHSA-1"}},
		{name: "severity at most", query: "severity:<=medium", want: []string{"PYSEC-1", "GO-4", "GO-3"}},
		{name: "severity space separated", query: "severity: high", want: []string{"GO-1", "GO-2"}},
		{name: "severity case-insensitive", query: "severity:CRITICAL", want: []string{"GHSA-1"}},
		{name: "severity label alias", query: "severity:moderate", want: []string{"PYSEC-1"}},
		{name: "ecosystem", query: "ecosystem:go", want: []string{"GO-1", "GO-2", "GO-4", "GO-3"}},
		{name: "ecosystem shorthand", query: "eco:npm", want: []string{"GHSA-1"}},
		{name: "package", query: "pkg:lodash", want: []string{"GHSA-1"}},
		{name: "id", query: "id:GO-1", want: []string{"GO-1"}},
		{name: "cve", query: "cve:CVE-2023-44487", want: []string{"GO-2"}},
		{name: "cve has no match", query: "cve:GHSA", want: []string{}},
		{name: "source", query: "source:go.mod", want: []string{}},
		{name: "fixed true", query: "fixed:true", want: []string{"GO-1", "PYSEC-1"}},
		{name: "fixed false", query: "fixed:false", want: []string{"GHSA-1", "GO-2", "GO-4", "GO-3"}},
		{name: "combined", query: "eco:go severity:>=high fixed:true", want: []string{"GO-1"}},
		{name: "combined with free text", query: "flood severity:high", want: []string{"GO-1"}},
		{name: "unknown key falls back to free text", query: "foo:GO-1", want: []string{}},
		{name: "invalid severity falls back to free text", query: "severity:hgih", want: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ids(fs, search(fs, norms, tt.query, Filter{}))
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryMatchesFreeTextAndOffsets(t *testing.T) {
	fs := sampleFindings()
	model.SortFindings(fs)
	norms := normOf(fs)

	// Free text must match the joined key, not only single fields.
	got := ids(fs, search(fs, norms, "pollution", Filter{}))
	if want := []string{"GHSA-1"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	// Match offsets cover every byte of each term occurrence in the key.
	rs, terms := Search(nil, fs, norms, "go", Filter{})
	if len(rs) == 0 {
		t.Fatal("no results")
	}
	for _, r := range rs {
		lower := norms[r.Index].Key
		want := map[int]bool{}
		for i := 0; i+2 <= len(lower); i++ {
			if lower[i:i+2] == "go" {
				want[i], want[i+1] = true, true
			}
		}
		offs := termOffsets(lower, terms)
		got := map[int]bool{}
		for _, o := range offs {
			got[o] = true
		}
		if !maps.Equal(got, want) {
			t.Errorf("termOffsets = %v for %q, want covered bytes %v", offs, lower, want)
		}
	}
}

func TestParseQuery(t *testing.T) {
	q := parseQuery("net sev:>=high fixed:true eco:go")
	if len(q.terms) != 1 || q.terms[0] != "net" {
		t.Errorf("terms = %v", q.terms)
	}
	if len(q.sev) != 1 || len(q.sev[0]) != 1 || q.sev[0][0] != (sevCond{op: ">=", val: model.SeverityHigh}) {
		t.Errorf("sev = %v", q.sev)
	}
	if q.fixed == nil || !*q.fixed {
		t.Errorf("fixed = %v", q.fixed)
	}
	if len(q.eco) != 1 || q.eco[0] != "go" {
		t.Errorf("eco = %v", q.eco)
	}
	if q := parseQuery(""); len(q.terms) != 0 || q.fixed != nil {
		t.Errorf("empty query = %+v", q)
	}
}

func TestSearchKeyLayout(t *testing.T) {
	f := model.Finding{ID: "GO-1", CVEs: []string{"CVE-1"}, Summary: "sum", Package: model.Package{Name: "pkg", Ecosystem: "Go"}}
	key, l := SearchKey(f)
	if key != "pkg Go GO-1 CVE-1 sum" {
		t.Fatalf("key = %q", key)
	}
	if key[l.id:l.id+4] != "GO-1" || key[l.summary:] != "sum" || key[l.name:l.name+3] != "pkg" {
		t.Errorf("bad layout %+v for %q", l, key)
	}
}

func TestFoldKeyPreservesByteLength(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"ABC", "abc"},
		{"ÀB", "àb"},
		{"İ", "İ"}, // ToLower(U+0130) is 1 byte, the original is 2: kept as is
		{"aİB", "aİb"},
	}
	for _, tt := range tests {
		got := foldKey(tt.in)
		if got != tt.want {
			t.Errorf("foldKey(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if len(got) != len(tt.in) {
			t.Errorf("foldKey(%q) changed byte length: %d -> %d", tt.in, len(tt.in), len(got))
		}
	}
}

func TestHighlightOffsetsAfterLengthChangingRune(t *testing.T) {
	f := model.Finding{
		ID:      "GO-9",
		Summary: "İ flaw in parser",
		Package: model.Package{Name: "x", Ecosystem: "Go"},
	}
	n, lay := Normalize(f)
	key, _ := SearchKey(f)
	rs, terms := Search(nil, []model.Finding{f}, []Normalized{n}, "flaw", Filter{})
	if len(rs) != 1 {
		t.Fatalf("got %d results, want 1", len(rs))
	}
	offs := termOffsets(n.Key, terms)
	want := strings.Index(key, "flaw")
	if wantOff := []int{want, want + 1, want + 2, want + 3}; !slices.Equal(offs, wantOff) {
		t.Fatalf("termOffsets = %v, want %v", offs, wantOff)
	}

	matched := map[int]bool{}
	for _, o := range offs {
		matched[o] = true
	}
	bracket := lipgloss.NewStyle().Transform(func(s string) string { return "[" + s + "]" })
	got := highlight(f.Summary, lay.summary, matched, lipgloss.NewStyle(), bracket)
	if wantS := "İ [flaw] in parser"; got != wantS {
		t.Errorf("highlight = %q, want %q", got, wantS)
	}
}

func TestHighlightOverlappingTerms(t *testing.T) {
	f := model.Finding{
		ID:      "GO-8",
		Summary: "flaw flaw",
		Package: model.Package{Name: "x", Ecosystem: "Go"},
	}
	n, lay := Normalize(f)
	rs, terms := Search(nil, []model.Finding{f}, []Normalized{n}, "flaw law", Filter{})
	if len(rs) != 1 {
		t.Fatalf("got %d results, want 1", len(rs))
	}
	matched := map[int]bool{}
	for _, o := range termOffsets(n.Key, terms) {
		matched[o] = true
	}
	bracket := lipgloss.NewStyle().Transform(func(s string) string { return "[" + s + "]" })
	got := highlight(f.Summary, lay.summary, matched, lipgloss.NewStyle(), bracket)
	if want := "[flaw] [flaw]"; got != want {
		t.Errorf("highlight = %q, want %q", got, want)
	}
}
