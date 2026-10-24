package scanner

import (
	"os"
	"slices"
	"testing"

	"github.com/jedipunkz/scomp/internal/model"
)

func TestParseSample(t *testing.T) {
	data, err := os.ReadFile("../../testdata/osv-scanner-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data, "/repo")
	if err != nil {
		t.Fatal(err)
	}

	byID := map[string]model.Finding{}
	for _, f := range got {
		byID[f.ID] = f
	}
	if len(got) != 4 || len(byID) != 4 {
		t.Fatalf("got %d findings (%d unique IDs), want 4: %+v", len(got), len(byID), got)
	}

	tests := []struct {
		id        string
		pkg       model.Package
		severity  model.Severity
		score     float64
		cves      []string
		alias     string
		fixed     []string
		summary   string
		published string
	}{
		{
			id:        "GO-2024-2687",
			pkg:       model.Package{Name: "golang.org/x/net", Version: "0.17.0", Ecosystem: "Go", Source: "go.mod"},
			severity:  model.SeverityMedium,
			score:     5.3,
			cves:      []string{"CVE-2023-45288"},
			alias:     "GHSA-4v7x-pqxf-cx7m",
			fixed:     []string{"0.23.0"}, // the stdlib entry (1.21.9, 1.22.2) must not leak in
			summary:   "HTTP/2 CONTINUATION flood in net/http",
			published: "2024-04-03T21:12:01Z",
		},
		{
			id:       "GO-2024-3333",
			pkg:      model.Package{Name: "golang.org/x/net", Version: "0.17.0", Ecosystem: "Go", Source: "go.mod"},
			severity: model.SeverityUnknown, // empty max_severity
		},
		{
			id:       "PYSEC-2023-74",
			pkg:      model.Package{Name: "requests", Version: "2.28.0", Ecosystem: "PyPI", Source: "requirements.txt"},
			severity: model.SeverityMedium,
			score:    6.1,
			alias:    "GHSA-j8r2-6x86-q33q",
			fixed:    []string{"2.31.0"}, // GIT range commit hashes are skipped
		},
		{
			id:       "PYSEC-2026-4320",
			pkg:      model.Package{Name: "certifi", Version: "2026.7.22", Ecosystem: "PyPI", Source: "requirements.txt"},
			severity: model.SeverityCritical,
			score:    9.1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			f, ok := byID[tt.id]
			if !ok {
				t.Fatalf("finding %s missing", tt.id)
			}
			if f.Package != tt.pkg {
				t.Errorf("package = %+v, want %+v", f.Package, tt.pkg)
			}
			if f.Severity != tt.severity || f.CVSSScore != tt.score {
				t.Errorf("severity = %v/%v, want %v/%v", f.Severity, f.CVSSScore, tt.severity, tt.score)
			}
			if tt.cves != nil && !slices.Equal(f.CVEs, tt.cves) {
				t.Errorf("CVEs = %v, want %v", f.CVEs, tt.cves)
			}
			if tt.alias != "" && !slices.Contains(f.Aliases, tt.alias) {
				t.Errorf("aliases %v missing %s", f.Aliases, tt.alias)
			}
			if slices.Contains(f.Aliases, f.ID) {
				t.Errorf("aliases %v must not contain own ID", f.Aliases)
			}
			if tt.fixed != nil && !slices.Equal(f.FixedVersions, tt.fixed) {
				t.Errorf("fixed = %v, want %v", f.FixedVersions, tt.fixed)
			}
			if tt.summary != "" && f.Summary != tt.summary {
				t.Errorf("summary = %q, want %q", f.Summary, tt.summary)
			}
			if tt.published != "" && f.Published.UTC().Format("2006-01-02T15:04:05Z") != tt.published {
				t.Errorf("published = %v, want %s", f.Published, tt.published)
			}
		})
	}
}

func TestParseEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantIDs []string
		wantErr bool
	}{
		{name: "empty results", input: `{"results":[]}`, wantIDs: []string{}},
		{name: "no results key", input: `{}`, wantIDs: []string{}},
		{name: "invalid json", input: `{`, wantErr: true},
		{
			name: "no groups falls back to one finding per vulnerability",
			input: `{"results":[{"source":{"path":"/r/go.mod"},"packages":[{"package":{"name":"a","version":"1","ecosystem":"Go"},
				"vulnerabilities":[{"id":"GO-1","database_specific":{"severity":"HIGH"}},{"id":"GO-2"}]}]}]}`,
			wantIDs: []string{"GO-1", "GO-2"},
		},
		{
			name: "duplicate package entries are deduplicated",
			input: `{"results":[{"source":{"path":"/r/go.mod"},"packages":[
				{"package":{"name":"a","version":"1","ecosystem":"Go"},"groups":[{"ids":["GO-1"]}],"vulnerabilities":[{"id":"GO-1"}]},
				{"package":{"name":"a","version":"1","ecosystem":"Go"},"groups":[{"ids":["GO-1"]}],"vulnerabilities":[{"id":"GO-1"}]}]}]}`,
			wantIDs: []string{"GO-1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse([]byte(tt.input), "/r")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			ids := []string{}
			for _, f := range got {
				ids = append(ids, f.ID)
			}
			if !slices.Equal(ids, tt.wantIDs) {
				t.Errorf("IDs = %v, want %v", ids, tt.wantIDs)
			}
		})
	}
}

func TestParseSeverityLabelFallback(t *testing.T) {
	in := `{"results":[{"source":{"path":"/r/go.mod"},"packages":[{"package":{"name":"a","version":"1","ecosystem":"Go"},
		"groups":[{"ids":["GHSA-x"],"max_severity":""}],"vulnerabilities":[{"id":"GHSA-x","database_specific":{"severity":"MODERATE"}}]}]}]}`
	got, err := Parse([]byte(in), "/r")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Severity != model.SeverityMedium {
		t.Fatalf("got %+v, want one medium finding", got)
	}
	if got[0].Package.Source != "go.mod" {
		t.Errorf("source = %q, want go.mod", got[0].Package.Source)
	}
}
