package scanner

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jedipunkz/scomp/internal/model"
)

// osvOutput mirrors the subset of `osv-scanner --format json` (v2) that scomp uses.
type osvOutput struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Groups []struct {
				IDs         []string `json:"ids"`
				Aliases     []string `json:"aliases"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
			Vulnerabilities []osvVuln `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

type osvVuln struct {
	ID               string    `json:"id"`
	Aliases          []string  `json:"aliases"`
	Summary          string    `json:"summary"`
	Details          string    `json:"details"`
	Published        time.Time `json:"published"`
	Modified         time.Time `json:"modified"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type group struct {
	ids         []string
	aliases     []string
	maxSeverity string
}

// vuln is the per-advisory data a finding is built from. Parse fills it from
// the JSON output and convert from the in-process osv-scanner results, so both
// scanners share the grouping, dedup, alias and severity rules below.
type vuln struct {
	aliases             []string
	summary, details    string
	published, modified time.Time
	dbSeverity          string   // database_specific.severity label
	fixed               []string // fixed versions for the enclosing package, deduplicated
	references          []string // reference URLs, deduplicated
}

// appendPackage appends one finding per vulnerability group of pkg
// (osv-scanner merges aliased advisories such as GO-… and GHSA-… into one
// group) and skips findings already recorded in seen. Without groups, every
// vulnerability becomes its own group.
//
// The package has n vulnerabilities; id(i) returns the ID of the i-th and
// load(i) extracts its details. Only the vulnerability backing a group is
// loaded, so aliased advisories that never surface cost nothing.
func appendPackage(findings []model.Finding, seen map[string]bool, pkg model.Package, groups []group,
	n int, id func(int) string, load func(int) vuln,
) []model.Finding {
	byID := map[string]int{}
	for i := range n {
		byID[id(i)] = i // a repeated ID resolves to its last entry
	}
	if len(groups) == 0 {
		for i := range n {
			groups = append(groups, group{ids: []string{id(i)}})
		}
	}
	for _, g := range groups {
		var v vuln
		found := false
		for _, gid := range g.ids {
			if i, ok := byID[gid]; ok {
				v, found = load(i), true
				break
			}
		}
		f, ok := buildFinding(pkg, g, v, found)
		if !ok {
			continue
		}
		k := pkg.Source + "\x00" + pkg.Ecosystem + "\x00" + pkg.Name + "\x00" + pkg.Version + "\x00" + f.ID
		if seen[k] {
			continue
		}
		seen[k] = true
		findings = append(findings, f)
	}
	return findings
}

// Parse converts osv-scanner JSON output into findings.
// One finding is produced per vulnerability group.
func Parse(data []byte, root string) ([]model.Finding, error) {
	var out osvOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse osv-scanner output: %w", err)
	}

	findings := []model.Finding{}
	seen := map[string]bool{}
	for _, res := range out.Results {
		source := relPath(root, res.Source.Path)
		for _, p := range res.Packages {
			pkg := model.Package{
				Name:      p.Package.Name,
				Version:   p.Package.Version,
				Ecosystem: p.Package.Ecosystem,
				Source:    source,
			}
			groups := make([]group, 0, len(p.Groups))
			for _, g := range p.Groups {
				groups = append(groups, group{ids: g.IDs, aliases: g.Aliases, maxSeverity: g.MaxSeverity})
			}
			vs := p.Vulnerabilities
			findings = appendPackage(findings, seen, pkg, groups, len(vs),
				func(i int) string { return vs[i].ID },
				func(i int) vuln { return jsonVuln(&vs[i], pkg) })
		}
	}
	return findings, nil
}

func jsonVuln(v *osvVuln, pkg model.Package) vuln {
	out := vuln{
		aliases:    v.Aliases,
		summary:    v.Summary,
		details:    v.Details,
		published:  v.Published,
		modified:   v.Modified,
		dbSeverity: v.DatabaseSpecific.Severity,
	}
	for _, a := range v.Affected {
		if a.Package.Name != pkg.Name || !sameEcosystem(a.Package.Ecosystem, pkg.Ecosystem) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				continue // GIT range events are commit hashes
			}
			for _, e := range r.Events {
				out.fixed = appendUnique(out.fixed, e.Fixed)
			}
		}
	}
	for _, r := range v.References {
		out.references = appendUnique(out.references, r.URL)
	}
	return out
}

// appendUnique appends s unless it is empty or already in ss.
func appendUnique(ss []string, s string) []string {
	if s == "" || slices.Contains(ss, s) {
		return ss
	}
	return append(ss, s)
}

// buildFinding builds the finding for group g from v, the vulnerability
// backing it; found is false when the output has none of the group's IDs.
func buildFinding(pkg model.Package, g group, v vuln, found bool) (model.Finding, bool) {
	if len(g.ids) == 0 || g.ids[0] == "" {
		// An empty first ID would produce a row with no ID and a broken
		// osv.dev link; real osv-scanner output never contains one, but the
		// parser must not emit it either (found by FuzzParse).
		return model.Finding{}, false
	}
	id := g.ids[0]
	if !validOSVID(id) {
		// The ID is embedded in the osv.dev URL that openBrowser passes to
		// cmd.exe under WSL. url.PathEscape leaves & and | unescaped, so an
		// unvalidated ID could run commands there. Real OSV IDs (GHSA-…,
		// CVE-…, GO-…, PYSEC-…, RLSA-2023:1234, UUID-style) use only these
		// characters.
		return model.Finding{}, false
	}
	f := model.Finding{ID: id, Package: pkg}
	aliasSet := map[string]bool{}
	addAliases := func(as []string) {
		for _, a := range as {
			if a != "" && a != id {
				aliasSet[a] = true
			}
		}
	}
	addAliases(g.ids)
	addAliases(g.aliases)

	if found {
		addAliases(v.aliases)
		f.Summary = v.summary
		f.Details = v.details
		f.Published = v.published
		f.Modified = v.modified
		// load builds these slices afresh for every group, so the finding
		// owns them.
		f.FixedVersions = v.fixed
		f.References = v.references
	}

	for a := range aliasSet {
		f.Aliases = append(f.Aliases, a)
		if strings.HasPrefix(a, "CVE-") {
			f.CVEs = append(f.CVEs, a)
		}
	}
	slices.Sort(f.Aliases)
	slices.Sort(f.CVEs)
	// Encode as [] rather than null in JSON output.
	for _, p := range []*[]string{&f.Aliases, &f.CVEs, &f.FixedVersions, &f.References} {
		if *p == nil {
			*p = []string{}
		}
	}

	if score, err := strconv.ParseFloat(strings.TrimSpace(g.maxSeverity), 64); err == nil {
		f.CVSSScore = score
		f.Severity = model.SeverityFromScore(score)
	}
	if f.Severity == model.SeverityUnknown && found {
		f.Severity = model.SeverityFromLabel(v.dbSeverity)
	}
	return f, true
}

// validOSVID reports whether id uses only ASCII letters, digits, '.', ':' and
// '-'. Control characters and cmd.exe metacharacters are rejected.
func validOSVID(id string) bool {
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == ':', c == '-':
		default:
			return false
		}
	}
	return id != ""
}

// sameEcosystem compares ecosystems ignoring case and release suffixes
// such as "Debian:12".
func sameEcosystem(a, b string) bool {
	base := func(s string) string {
		s, _, _ = strings.Cut(s, ":")
		return s
	}
	return strings.EqualFold(base(a), base(b))
}

func relPath(root, p string) string {
	if p == "" {
		return ""
	}
	if r, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(r, "..") {
		return filepath.ToSlash(r)
	}
	return p
}
