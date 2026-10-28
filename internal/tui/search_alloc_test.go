package tui

import (
	"testing"
)

// TestSearch_AllocCount asserts the allocation count of the search hot path:
// CLAUDE.md requires Search to avoid per-keystroke allocations, so a
// regression must fail go test. Thresholds are the measured values plus ~10%
// headroom; counts scale with the match set, so each query/size pair carries
// its own cap. The counts are stable per process but not fully across
// environments: CI macOS once measured 8 for fields/n=10000 where every
// local run and the Linux bench gate measure 7 (see the cap comment).
//
// AllocsPerRun counts process-wide mallocs and integer-divides by the run
// count, so a few stray runtime allocations during the window add a whole
// alloc at 10 runs (CI macOS measured 5 for multi/n=10000 against 3
// elsewhere). allocRuns dilutes them below one per run without touching the
// caps.
const allocRuns = 100

func TestSearch_AllocCount(t *testing.T) {
	sizes := []int{1000, 10000}
	caps := map[string][2]float64{
		// query name: {n=1000, n=10000}; measured values + ~10% headroom.
		"empty":  {11, 20},
		"single": {231, 2216},
		"multi":  {4, 4},
		// n=10000 measured 7 locally (go1.27.0/1.27.3, with and without
		// -race) and 7.00 on the Linux bench gate; CI macOS once measured 8,
		// so the cap carries an extra slot of headroom.
		"fields": {7, 9},
	}
	for _, size := range sizes {
		findings, keys := genFindings(size)
		for _, q := range benchmarkQueries {
			allocs := testing.AllocsPerRun(allocRuns, func() {
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
