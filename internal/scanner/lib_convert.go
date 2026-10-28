package scanner

import (
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/jedipunkz/scomp/internal/model"
)

// convert turns in-process osv-scanner results into findings. It yields the
// same findings as Parse on the JSON encoding of res, without marshaling the
// results and decoding them again.
func convert(res *models.VulnerabilityResults, root string) []model.Finding {
	findings := []model.Finding{}
	seen := map[string]bool{}
	for _, src := range res.Results {
		source := relPath(root, src.Source.Path)
		for _, p := range src.Packages {
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
				func(i int) string { return vs[i].GetId() },
				func(i int) vuln { return libVuln(vs[i], pkg) })
		}
	}
	return findings
}

// libVuln reads the fields jsonVuln reads, from the osv-schema protobuf
// message. The getters are nil-safe, so missing sub-messages read as empty.
func libVuln(v *osvschema.Vulnerability, pkg model.Package) vuln {
	out := vuln{
		aliases:    v.GetAliases(),
		summary:    v.GetSummary(),
		details:    v.GetDetails(),
		dbSeverity: v.GetDatabaseSpecific().GetFields()["severity"].GetStringValue(),
	}
	// An unset timestamp is omitted from the JSON and decodes as the zero
	// time; AsTime on nil would give the Unix epoch instead.
	if ts := v.GetPublished(); ts != nil {
		out.published = ts.AsTime()
	}
	if ts := v.GetModified(); ts != nil {
		out.modified = ts.AsTime()
	}
	for _, a := range v.GetAffected() {
		if a.GetPackage().GetName() != pkg.Name || !sameEcosystem(a.GetPackage().GetEcosystem(), pkg.Ecosystem) {
			continue
		}
		for _, r := range a.GetRanges() {
			if r.GetType() == osvschema.Range_GIT {
				continue // GIT range events are commit hashes
			}
			for _, e := range r.GetEvents() {
				out.fixed = appendUnique(out.fixed, e.GetFixed())
			}
		}
	}
	for _, r := range v.GetReferences() {
		out.references = appendUnique(out.references, r.GetUrl())
	}
	return out
}
