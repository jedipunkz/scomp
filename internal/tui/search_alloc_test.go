package tui

import (
	"testing"
)

// TestSearch_AllocCount asserts the allocation count of the search hot path:
// CLAUDE.md requires Search to avoid per-keystroke allocations, so a
// regression must fail go test. Thresholds are the measured values plus ~10%
// headroom, rounded up to a whole allocation. Search reuses the capacity of
// the previous results and leaves match offsets to the view (visible rows
// only), so the counts no longer scale with the match set: what remains is
// parseQuery. The counts are stable per process but not fully across
// environments: CI macOS once measured one more than Linux for
// fields/n=10000 (see the cap comment).
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
		// Measured (go1.27.0, linux/amd64, with and without -race):
		// empty 0/0, single 2/2, multi 3/3, fields 6/6.
		"empty":  {1, 1},
		"single": {3, 3},
		"multi":  {4, 4},
		// n=10000 keeps one extra slot: CI macOS once measured one more
		// than Linux here.
		"fields": {7, 8},
	}
	for _, size := range sizes {
		findings, keys := genFindings(size)
		for _, q := range benchmarkQueries {
			// Reuse the results like Model.refreshKeep does across keystrokes;
			// AllocsPerRun's warm-up call grows buf before measuring.
			var buf []Result
			allocs := testing.AllocsPerRun(allocRuns, func() {
				buf, _ = Search(buf, findings, keys, q.query, Filter{})
			})
			want := caps[q.name][map[int]int{1000: 0, 10000: 1}[size]]
			if allocs > want {
				t.Errorf("Search(size=%d, query=%q) allocated %g, want <= %g",
					size, q.query, allocs, want)
			}
		}
	}
}
