package tui

import (
	"slices"
	"testing"

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

func ids(fs []model.Finding, rs []Result) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, fs[r.Index].ID)
	}
	return out
}

func TestSortFindings(t *testing.T) {
	fs := sampleFindings()
	SortFindings(fs)
	got := ids(fs, Search(fs, keysOf(fs), "", Filter{}))
	want := []string{"GHSA-1", "GO-1", "GO-2", "PYSEC-1", "GO-4", "GO-3"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func keysOf(fs []model.Finding) []string {
	keys := make([]string, len(fs))
	for i, f := range fs {
		keys[i], _ = SearchKey(f)
	}
	return keys
}

func TestSearch(t *testing.T) {
	fs := sampleFindings()
	SortFindings(fs)
	keys := keysOf(fs)

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
			got := ids(fs, Search(fs, keys, tt.query, tt.filter))
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
	SortFindings(fs)
	got := ids(fs, Search(fs, keysOf(fs), "pkg", Filter{}))
	if want := []string{"A", "B"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
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
