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

// Parse converts osv-scanner JSON output into findings.
// One finding is produced per vulnerability group (osv-scanner merges
// aliased advisories such as GO-… and GHSA-… into one group).
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
			vulns := map[string]*osvVuln{}
			for i := range p.Vulnerabilities {
				vulns[p.Vulnerabilities[i].ID] = &p.Vulnerabilities[i]
			}

			groups := make([]group, 0, len(p.Groups))
			for _, g := range p.Groups {
				groups = append(groups, group{ids: g.IDs, aliases: g.Aliases, maxSeverity: g.MaxSeverity})
			}
			if len(groups) == 0 {
				for _, v := range p.Vulnerabilities {
					groups = append(groups, group{ids: []string{v.ID}})
				}
			}

			for _, g := range groups {
				f, ok := buildFinding(pkg, g, vulns)
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
		}
	}
	return findings, nil
}

func buildFinding(pkg model.Package, g group, vulns map[string]*osvVuln) (model.Finding, bool) {
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
	var v *osvVuln
	for _, gid := range g.ids {
		if v = vulns[gid]; v != nil {
			break
		}
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

	if v != nil {
		addAliases(v.Aliases)
		f.Summary = v.Summary
		f.Details = v.Details
		f.Published = v.Published
		f.Modified = v.Modified
		f.FixedVersions = fixedVersions(v, pkg)
		for _, r := range v.References {
			if r.URL != "" && !slices.Contains(f.References, r.URL) {
				f.References = append(f.References, r.URL)
			}
		}
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
	if f.Severity == model.SeverityUnknown && v != nil {
		f.Severity = model.SeverityFromLabel(v.DatabaseSpecific.Severity)
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

// fixedVersions collects "fixed" events for the affected entry matching pkg.
// GIT ranges are skipped because their events are commit hashes.
func fixedVersions(v *osvVuln, pkg model.Package) []string {
	var fixed []string
	for _, a := range v.Affected {
		if a.Package.Name != pkg.Name || !sameEcosystem(a.Package.Ecosystem, pkg.Ecosystem) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" && !slices.Contains(fixed, e.Fixed) {
					fixed = append(fixed, e.Fixed)
				}
			}
		}
	}
	return fixed
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
