package scanner

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// loadResults decodes osv-scanner JSON into the in-process result type, the
// same value osvscanner.DoScan returns to Lib.Scan.
func loadResults(tb testing.TB, data []byte) models.VulnerabilityResults {
	tb.Helper()
	var res models.VulnerabilityResults
	if err := json.Unmarshal(data, &res); err != nil {
		tb.Fatalf("decode results: %v", err)
	}
	return res
}

// TestConvertMatchesParse checks that the direct conversion used by Lib
// yields exactly what the former JSON round-trip (json.Marshal + Parse)
// yielded: same findings, order, dedup, aliases, severity and fixed versions.
func TestConvertMatchesParse(t *testing.T) {
	sample, err := os.ReadFile("../../testdata/osv-scanner-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	pkgA := `"package":{"name":"a","version":"1","ecosystem":"Go"}`
	tests := []struct {
		name  string
		input string
		n     int // findings expected, so an empty result cannot pass vacuously
	}{
		{name: "sample", input: string(sample), n: 4},
		{name: "empty results", input: `{"results":[]}`},
		{name: "no results key", input: `{}`},
		{
			name: "no groups falls back to one finding per vulnerability",
			input: `{"results":[{"source":{"path":"/r/go.mod"},"packages":[{` + pkgA + `,
				"vulnerabilities":[{"id":"GO-1","database_specific":{"severity":"HIGH"}},{"id":"GO-2"},{"id":"GO-1"}]}]}]}`,
			n: 2,
		},
		{
			name: "duplicate package entries are deduplicated",
			input: `{"results":[{"source":{"path":"/r/go.mod"},"packages":[
				{` + pkgA + `,"groups":[{"ids":["GO-1"]}],"vulnerabilities":[{"id":"GO-1"}]},
				{` + pkgA + `,"groups":[{"ids":["GO-1"]}],"vulnerabilities":[{"id":"GO-1"}]}]}]}`,
			n: 1,
		},
		{
			name: "severity label fallback and missing timestamps",
			input: `{"results":[{"source":{"path":"/r/go.mod"},"packages":[{` + pkgA + `,
				"groups":[{"ids":["GHSA-x"],"max_severity":""}],
				"vulnerabilities":[{"id":"GHSA-x","database_specific":{"severity":"MODERATE","other":1}}]}]}]}`,
			n: 1,
		},
		{
			name: "unsafe and empty IDs are dropped",
			input: `{"results":[{"source":{"path":"/r/go.mod"},"packages":[{` + pkgA + `,
				"groups":[{"ids":["GHSA-x&calc"]},{"ids":[""]},{"ids":[]},{"ids":["RLSA-2023:1234"],"max_severity":" 9.8 "}]}]}]}`,
			n: 1,
		},
		{
			name: "group resolves to its second ID and merges aliases",
			input: `{"results":[{"source":{"path":"/elsewhere/package-lock.json"},"packages":[{
				"package":{"name":"left-pad","version":"1.0.0","ecosystem":"npm"},
				"groups":[{"ids":["GHSA-a","GO-b"],"aliases":["CVE-2020-2","GHSA-a","CVE-2020-1"],"max_severity":"7.5"}],
				"vulnerabilities":[{"id":"GO-b","aliases":["CVE-2020-3",""],"summary":"s","details":"d",
					"published":"2024-04-03T21:12:01.123456789Z","modified":"2024-04-04T00:00:00Z",
					"references":[{"type":"WEB","url":"https://a"},{"url":""},{"url":"https://a"},{"type":"FIX","url":"https://b"}],
					"affected":[
						{"package":{"name":"left-pad","ecosystem":"NPM:x"},"ranges":[
							{"type":"GIT","repo":"r","events":[{"introduced":"0"},{"fixed":"abc123"}]},
							{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"},{"fixed":"1.0.1"},{"last_affected":"1.0.0"}]}]},
						{"package":{"name":"other","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"fixed":"9"}]}]},
						{"package":{"name":"left-pad","ecosystem":"npm"},"ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"2.0.0"}]}]}]}]}]}]}`,
			n: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := loadResults(t, []byte(tt.input))
			data, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			want, err := Parse(data, "/r")
			if err != nil {
				t.Fatal(err)
			}
			got := convert(&res, "/r")
			if len(want) != tt.n {
				t.Fatalf("Parse returned %d findings, want %d: %+v", len(want), tt.n, want)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("convert differs from Parse(json.Marshal(results))\n got: %+v\nwant: %+v", got, want)
			}
		})
	}
}

// TestConvertNilMessages checks that nil protobuf entries, which the JSON
// round-trip never produced but a Go value can hold, do not panic.
func TestConvertNilMessages(t *testing.T) {
	res := models.VulnerabilityResults{Results: []models.PackageSource{{
		Source: models.SourceInfo{Path: "/r/go.mod"},
		Packages: []models.PackageVulns{{
			Package:         models.PackageInfo{Name: "a", Version: "1", Ecosystem: "Go"},
			Groups:          []models.GroupInfo{{IDs: []string{"GO-1"}}},
			Vulnerabilities: []*osvschema.Vulnerability{nil, {Id: "GO-1", Affected: []*osvschema.Affected{nil, {Ranges: []*osvschema.Range{nil}}}}},
		}},
	}}}
	got := convert(&res, "/r")
	if len(got) != 1 || got[0].ID != "GO-1" || !got[0].Published.IsZero() {
		t.Fatalf("got %+v, want one GO-1 finding with a zero published time", got)
	}
}

// BenchmarkConvert measures the in-process results → findings conversion
// used by Lib.Scan, on the checked-in sample.
func BenchmarkConvert(b *testing.B) {
	sample, err := os.ReadFile("../../testdata/osv-scanner-v2.json")
	if err != nil {
		b.Fatal(err)
	}
	res := loadResults(b, sample)
	b.ReportAllocs()
	for range b.N {
		if got := convert(&res, "/repo"); len(got) == 0 {
			b.Fatal("convert returned no findings")
		}
	}
}
