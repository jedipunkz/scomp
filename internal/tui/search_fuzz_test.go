package tui

import (
	"slices"
	"strings"
	"testing"
)

// FuzzSearchQuery runs arbitrary query strings through Search. The invariants
// below mirror what the TUI list rendering relies on: result indices stay in
// range and keep the sorted order (strictly increasing), match offsets are
// sorted ascending, every match offset
// stays inside the search key and covers exactly the bytes of the free-text term
// occurrences (no byte missing, none extra), and an
// empty query passes the whole (already filtered) input through unchanged.
func FuzzSearchQuery(f *testing.F) {
	for _, s := range []string{
		"", "crypto", "crypto tls",
		"severity:high ecosystem:go fixed:true",
		"severity: >=medium,=low", "pkg: golang.org/x/net",
		"unknown:key:value", "fixed:maybe", ":",
	} {
		f.Add(s)
	}
	findings, norms := genFindings(200)
	f.Fuzz(func(t *testing.T, query string) {
		results, terms := Search(nil, findings, norms, query, Filter{})
		prev := -1
		q := parseQuery(query)
		if !slices.Equal(terms, q.terms) {
			t.Fatalf("Search terms = %q, want parsed terms %q", terms, q.terms)
		}
		for _, r := range results {
			if r.Index < 0 || r.Index >= len(findings) {
				t.Fatalf("result index %d out of range [0,%d)", r.Index, len(findings))
			}
			if prev >= 0 && r.Index <= prev {
				t.Fatalf("result index %d not after %d, want strictly increasing order", r.Index, prev)
			}
			prev = r.Index
			key := norms[r.Index].Key
			offs := termOffsets(key, terms)
			if !slices.IsSorted(offs) {
				t.Fatalf("match offsets %v not sorted, highlight walks them in order", offs)
			}
			for _, off := range offs {
				if off < 0 || off >= len(key) {
					t.Fatalf("match offset %d out of range for key %q", off, key)
				}
			}
			// Every byte of every term occurrence, for the extent check below.
			covered := map[int]bool{}
			for _, t := range q.terms {
				for i := 0; ; {
					j := strings.Index(key[i:], t)
					if j < 0 {
						break
					}
					for k := range len(t) {
						covered[i+j+k] = true
					}
					i += j + len(t)
				}
			}
			matched := map[int]bool{}
			for _, off := range offs {
				if !covered[off] {
					t.Fatalf("match offset %d is not inside a term occurrence in key %q", off, key)
				}
				matched[off] = true
			}
			if len(matched) != len(covered) {
				t.Fatalf("matched bytes %d != covered bytes %d in key %q", len(matched), len(covered), key)
			}
		}
		if query == "" && len(results) != len(findings) {
			t.Fatalf("empty query returned %d results, want %d", len(results), len(findings))
		}
	})
}
