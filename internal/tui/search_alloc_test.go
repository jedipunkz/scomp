package tui

import (
	"testing"
)

// TestSearch_AllocCount asserts the allocation count of the search hot path:
// CLAUDE.md requires Search to avoid per-keystroke allocations, so a
// regression must fail go test. Unlike benchmark timings, allocation counts
// are deterministic and CI-safe. Thresholds are the measured values plus ~10%
// headroom; counts scale with the match set, so each query/size pair carries
// its own cap.
func TestSearch_AllocCount(t *testing.T) {
	sizes := []int{1000, 10000}
	caps := map[string][2]float64{
		// query name: {n=1000, n=10000}; measured values + ~10% headroom.
		"empty":  {1111, 11020},
		"single": {1331, 13216},
		"multi":  {1103, 11003},
		"fields": {1382, 13757},
	}
	for _, size := range sizes {
		findings, keys := genFindings(size)
		for _, q := range benchmarkQueries {
			allocs := testing.AllocsPerRun(10, func() {
				_ = Search(findings, keys, q.query, Filter{})
			})
			want := caps[q.name][map[int]int{1000: 0, 10000: 1}[size]]
			if allocs > want {
				t.Errorf("Search(size=%d, query=%q) allocated %g, want <= %g",
					size, q.query, allocs, want)
			}
		}
	}
}
