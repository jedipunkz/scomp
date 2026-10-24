package tui

import (
	"strings"
	"testing"
)

// FuzzSearchQuery runs arbitrary query strings through Search. The invariants
// below mirror what the TUI list rendering relies on: result indices stay in
// range and keep the sorted order (strictly increasing), every match offset
// stays inside the search key and starts a free-text term occurrence, and an
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
		results := Search(findings, norms, query, Filter{})
		prev := -1
		// Every term occurrence start offset, for the occurrence check below.
		starts := map[int]bool{}
		q := parseQuery(query)
		for _, r := range results {
			if r.Index < 0 || r.Index >= len(findings) {
				t.Fatalf("result index %d out of range [0,%d)", r.Index, len(findings))
			}
			if prev >= 0 && r.Index <= prev {
				t.Fatalf("result index %d not after %d, want strictly increasing order", r.Index, prev)
			}
			prev = r.Index
			key := norms[r.Index].Key
			for _, off := range r.Matched {
				if off < 0 || off >= len(key) {
					t.Fatalf("match offset %d out of range for key %q", off, key)
				}
			}
			for _, t := range q.terms {
				for i := 0; ; {
					j := strings.Index(key[i:], t)
					if j < 0 {
						break
					}
					starts[i+j] = true
					i += j + len(t)
				}
			}
			for _, off := range r.Matched {
				if !starts[off] {
					t.Fatalf("match offset %d is not a term occurrence in key %q", off, key)
				}
			}
		}
		if query == "" && len(results) != len(findings) {
			t.Fatalf("empty query returned %d results, want %d", len(results), len(findings))
		}
	})
}
