package scanner

import (
	"os"
	"testing"
)

// BenchmarkParse measures the osv-scanner JSON → findings conversion with the
// checked-in sample output. The bench job compares it against the PR base.
func BenchmarkParse(b *testing.B) {
	sample, err := os.ReadFile("../../testdata/osv-scanner-v2.json")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for range b.N {
		if _, err := Parse(sample, "/root"); err != nil {
			b.Fatalf("Parse: %v", err)
		}
	}
}
