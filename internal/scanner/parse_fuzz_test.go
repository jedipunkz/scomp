package scanner

import (
	"os"
	"strings"
	"testing"

	"github.com/jedipunkz/scomp/internal/model"
)

// seedCorpus returns the checked-in osv-scanner sample plus minimal shapes.
func seedCorpus(t *testing.F) {
	t.Add([]byte(`{}`))
	t.Add([]byte(`{"results":[]}`))
	t.Add([]byte(`{"results":[{"source":{"path":"go.mod"},"packages":[{"package":{"name":"golang.org/x/net","version":"0.17.0","ecosystem":"Go"},"groups":[{"ids":["GO-2024-2687"],"max_severity":"7.5"}]}]}]}`))
	t.Add([]byte(`{"results":[{"source":{"path":"go.mod"},"packages":[{"package":{"name":"a","version":"1","ecosystem":"Go"},"groups":[{"ids":["GO-1"],"experimental_analysis":{"GO-1":{"called":false}}},{"ids":["GO-2"],"experimental_analysis":{"GO-2":{"called":true}}}],"vulnerabilities":[{"id":"GO-1"},{"id":"GO-2"}]}]}]}`))
	sample, err := os.ReadFile("../../testdata/osv-scanner-v2.json")
	if err != nil {
		panic(err)
	}
	t.Add(sample)
}

// FuzzParse runs arbitrary bytes through Parse. The invariants below mirror
// the guarantees exec and lib scanners rely on: a successful Parse never
// returns nil, every finding has a non-empty ID and a severity within the
// Severity range, and the slice fields are encoded as [] rather than null.
func FuzzParse(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		findings, err := Parse(data, "/root")
		if err != nil {
			return // invalid JSON is expected for arbitrary input
		}
		if findings == nil {
			t.Fatal("Parse returned nil, want a non-nil slice")
		}
		for _, fd := range findings {
			if fd.ID == "" {
				t.Fatal("finding has an empty ID, want a non-empty ID")
			}
			if fd.Severity < model.SeverityUnknown || fd.Severity > model.SeverityCritical {
				t.Fatalf("finding %q has severity %d, out of range", fd.ID, fd.Severity)
			}
			for _, s := range [][]string{fd.Aliases, fd.CVEs, fd.FixedVersions, fd.References} {
				if s == nil {
					t.Fatalf("finding %q has a nil slice field, want []", fd.ID)
				}
			}
			for _, c := range fd.CVEs {
				if !strings.HasPrefix(c, "CVE-") {
					t.Fatalf("finding %q has CVE entry %q, want a CVE- prefix", fd.ID, c)
				}
			}
		}
	})
}
