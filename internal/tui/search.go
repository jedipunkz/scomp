package tui

import (
	"cmp"
	"slices"
	"strings"

	"github.com/sahilm/fuzzy"

	"github.com/jedipunkz/scomp/internal/model"
)

// Filter is applied before fuzzy matching.
type Filter struct {
	MinSeverity model.Severity // SeverityUnknown means all
	Ecosystem   string         // "" means all
	FixedOnly   bool
}

func (f Filter) match(x model.Finding) bool {
	if f.MinSeverity != model.SeverityUnknown && x.Severity < f.MinSeverity {
		return false
	}
	if f.Ecosystem != "" && x.Package.Ecosystem != f.Ecosystem {
		return false
	}
	if f.FixedOnly && len(x.FixedVersions) == 0 {
		return false
	}
	return true
}

// Result is a finding that passed the filter and query.
type Result struct {
	Index   int   // index into the sorted findings
	Matched []int // byte offsets into the search key that matched the query
}

// SortFindings orders findings by severity desc, package name asc, ID asc.
func SortFindings(fs []model.Finding) {
	slices.SortStableFunc(fs, func(a, b model.Finding) int {
		if c := cmp.Compare(b.Severity, a.Severity); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Package.Name, b.Package.Name); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
}

// Segment offsets of each field inside a search key.
type keyLayout struct {
	name, id, summary int // start offsets; -1 if absent
}

// SearchKey builds "<name> <ecosystem> <id> <cves...> <summary>" and the field offsets.
func SearchKey(f model.Finding) (string, keyLayout) {
	var b strings.Builder
	var l keyLayout
	l.name = 0
	b.WriteString(f.Package.Name)
	b.WriteByte(' ')
	b.WriteString(f.Package.Ecosystem)
	b.WriteByte(' ')
	l.id = b.Len()
	b.WriteString(f.ID)
	for _, c := range f.CVEs {
		b.WriteByte(' ')
		b.WriteString(c)
	}
	b.WriteByte(' ')
	l.summary = b.Len()
	b.WriteString(f.Summary)
	return b.String(), l
}

type keySource struct {
	keys []string
	idx  []int
}

func (s keySource) String(i int) string { return s.keys[s.idx[i]] }
func (s keySource) Len() int            { return len(s.idx) }

// Search filters findings (already sorted with SortFindings) and fuzzy-matches the rest.
// With an empty query, results keep the sorted order. Otherwise they are ordered by
// score desc; ties keep the sorted order.
func Search(findings []model.Finding, keys []string, query string, f Filter) []Result {
	idx := make([]int, 0, len(findings))
	for i, x := range findings {
		if f.match(x) {
			idx = append(idx, i)
		}
	}
	if strings.TrimSpace(query) == "" {
		out := make([]Result, len(idx))
		for i, j := range idx {
			out[i] = Result{Index: j}
		}
		return out
	}
	matches := fuzzy.FindFrom(query, keySource{keys: keys, idx: idx})
	out := make([]Result, len(matches))
	for i, m := range matches {
		out[i] = Result{Index: idx[m.Index], Matched: m.MatchedIndexes}
	}
	return out
}
