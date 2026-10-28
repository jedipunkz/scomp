package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

// BenchmarkListLines renders a full page of list rows, the per-frame cost of
// highlighting free-text matches. "nomatch" filters every finding out; "e"
// matches many bytes per row.
func BenchmarkListLines(b *testing.B) {
	const w, h = 160, 100
	fs, _ := genFindings(1000)
	for _, q := range []struct{ name, query string }{
		{name: "empty", query: ""},
		{name: "single", query: "crypto"},
		{name: "multi", query: "go request"},
		{name: "dense", query: "e"},
		{name: "nomatch", query: "zzzz"},
	} {
		b.Run("query="+q.name, func(b *testing.B) {
			tm, _ := New(b.Context(), Config{Findings: fs}).Update(tea.WindowSizeMsg{Width: w, Height: h + 20})
			m := tm.(Model)
			m.input.SetValue(q.query)
			m.refresh()
			b.ReportAllocs()
			for range b.N {
				_ = m.listLines(w, h)
			}
		})
	}
}
