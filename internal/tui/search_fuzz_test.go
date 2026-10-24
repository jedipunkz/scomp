package tui

import (
	"strings"
	"testing"
)

// FuzzSearchQuery runs arbitrary query strings through Search. The invariants
// below mirror what the TUI list rendering relies on: result indices stay in
// range and keep the sorted order (strictly increasing), match offsets stay
// inside the search key, and an empty query passes the whole (already
// filtered) input through unchanged.
func FuzzSearchQuery(f *testing.F) {
	for _, s := range []string{
		"", "crypto", "crypto tls",
		"severity:high ecosystem:go fixed:true",
		"severity: >=medium,=low", "pkg: golang.org/x/net",
		"unknown:key:value", "fixed:maybe", ":",
	} {
		f.Add(s)
	}
	findings, keys := genFindings(200)
	f.Fuzz(func(t *testing.T, query string) {
		results := Search(findings, keys, query, Filter{})
		prev := -1
		for _, r := range results {
			if r.Index < 0 || r.Index >= len(findings) {
				t.Fatalf("result index %d out of range [0,%d)", r.Index, len(findings))
			}
			if prev >= 0 && r.Index <= prev {
				t.Fatalf("result index %d not after %d, want strictly increasing order", r.Index, prev)
			}
			prev = r.Index
			key := strings.ToLower(keys[r.Index])
			for _, off := range r.Matched {
				if off < 0 || off >= len(key) {
					t.Fatalf("match offset %d out of range for key %q", off, key)
				}
			}
			for i := 1; i < len(r.Matched); i++ {
				if r.Matched[i] < r.Matched[i-1] {
					t.Fatalf("match offsets %v not monotonic", r.Matched)
				}
			}
		}
		if query == "" && len(results) != len(findings) {
			t.Fatalf("empty query returned %d results, want %d", len(results), len(findings))
		}
	})
}
