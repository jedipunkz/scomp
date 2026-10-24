package tui

import (
	"fmt"
	"testing"

	"github.com/jedipunkz/scomp/internal/model"
)

// genFindings builds n deterministic findings and their search keys. It is
// shared by the allocation assert (TestSearch_AllocCount), the fuzz test
// (FuzzSearchQuery) and the benchmarks (BenchmarkSearch) so all three guard
// the same data shape.
func genFindings(n int) ([]model.Finding, []string) {
	ecosystems := []string{"Go", "npm", "PyPI", "crates.io"}
	sources := []string{"go.mod", "package-lock.json"}
	pkgs := []string{
		"golang.org/x/net", "github.com/aws/aws-sdk-go", "express",
		"requests", "github.com/gin-gonic/gin",
	}
	severities := []model.Severity{
		model.SeverityLow, model.SeverityMedium,
		model.SeverityHigh, model.SeverityCritical,
	}
	words := []string{"input validation", "crypto", "tls", "buffer overflow", "tls handshake"}
	fs := make([]model.Finding, 0, n)
	keys := make([]string, 0, n)
	for i := range n {
		f := model.Finding{
			ID: fmt.Sprintf("GO-2024-%05d", i+1),
			Aliases: []string{
				fmt.Sprintf("CVE-2024-%05d", i+1),
				fmt.Sprintf("GHSA-aaaa-%04d-bbbb", i),
			},
			CVEs:     []string{fmt.Sprintf("CVE-2024-%05d", i+1)},
			Summary:  fmt.Sprintf("%s has an improper %s in the request handler", pkgs[i%len(pkgs)], words[i%len(words)]),
			Severity: severities[i%len(severities)],
			Package: model.Package{
				Name:      pkgs[i%len(pkgs)],
				Version:   fmt.Sprintf("v%d.%d.%d", i%4, i%17, i%29),
				Ecosystem: ecosystems[i%len(ecosystems)],
				Source:    sources[i%len(sources)],
			},
			FixedVersions: []string{fmt.Sprintf("v%d.%d.%d", 4, 0, i%11)},
			References:    []string{fmt.Sprintf("https://example.com/advisories/%05d", i+1)},
		}
		k, _ := SearchKey(f)
		fs = append(fs, f)
		keys = append(keys, k)
	}
	return fs, keys
}

// benchmarkQueries is also used by TestSearch_AllocCount so the benchmark
// table and the allocation caps cover the same queries.
var benchmarkQueries = []struct {
	name  string
	query string
}{
	{name: "empty", query: ""},
	{name: "single", query: "crypto"},
	{name: "multi", query: "crypto tls"},
	{name: "fields", query: "severity:high ecosystem:go fixed:true"},
}

func BenchmarkSearch(b *testing.B) {
	for _, size := range []int{1000, 10000} {
		findings, keys := genFindings(size)
		for _, q := range benchmarkQueries {
			b.Run(fmt.Sprintf("query=%s/n=%d", q.name, size), func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					_ = Search(findings, keys, q.query, Filter{})
				}
			})
		}
	}
}
