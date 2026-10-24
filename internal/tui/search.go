package tui

import (
	"cmp"
	"slices"
	"strings"

	"github.com/jedipunkz/scomp/internal/model"
)

// Filter is applied before the query. It is driven by the
// ctrl+s / ctrl+e / ctrl+f key bindings; the query can add more constraints.
type Filter struct {
	MinSeverity model.Severity // SeverityUnknown means all
	Ecosystem   string         // "" means all
	FixedOnly   bool
}

func (f Filter) match(x model.Finding) bool {
	if f.MinSeverity != model.SeverityUnknown && x.Severity < f.MinSeverity {
		return false
	}
	if f.Ecosystem != "" && x.Package.Ecosystem != f.Ecosystem {
		return false
	}
	if f.FixedOnly && len(x.FixedVersions) == 0 {
		return false
	}
	return true
}

// Result is a finding that passed the filter and query.
type Result struct {
	Index   int   // index into the sorted findings
	Matched []int // byte offsets into the search key that matched a free-text term
}

// SortFindings orders findings by severity desc, package name asc, ID asc.
func SortFindings(fs []model.Finding) {
	slices.SortStableFunc(fs, func(a, b model.Finding) int {
		if c := cmp.Compare(b.Severity, a.Severity); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Package.Name, b.Package.Name); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
}

// Normalized is the precomputed lowercase text Search matches a finding
// against. It is built once per finding (in setFindings) so the per-keystroke
// hot path does no normalization; match offsets are byte offsets into Key.
type Normalized struct {
	Key    string   // lowercased search key
	Eco    string   // lowercased ecosystem
	Name   string   // lowercased package name
	ID     string   // lowercased OSV ID
	Source string   // lowercased lockfile source
	CVEs   []string // lowercased CVE IDs
}

// Normalize lowercases the text of one finding for reuse across keystrokes.
// The layout for the raw key is returned alongside because highlight() needs
// the field offsets.
func Normalize(f model.Finding) (Normalized, keyLayout) {
	key, l := SearchKey(f)
	cves := make([]string, len(f.CVEs))
	for i, c := range f.CVEs {
		cves[i] = strings.ToLower(c)
	}
	n := Normalized{
		Key:    strings.ToLower(key),
		Eco:    strings.ToLower(f.Package.Ecosystem),
		Name:   strings.ToLower(f.Package.Name),
		ID:     strings.ToLower(f.ID),
		Source: strings.ToLower(f.Package.Source),
		CVEs:   cves,
	}
	return n, l
}

// Segment offsets of each field inside a search key.
type keyLayout struct {
	name, id, summary int // start offsets; -1 if absent
}

// SearchKey builds "<name> <ecosystem> <id> <cves...> <summary>" and the field offsets.
func SearchKey(f model.Finding) (string, keyLayout) {
	var b strings.Builder
	var l keyLayout
	l.name = 0
	b.WriteString(f.Package.Name)
	b.WriteByte(' ')
	b.WriteString(f.Package.Ecosystem)
	b.WriteByte(' ')
	l.id = b.Len()
	b.WriteString(f.ID)
	for _, c := range f.CVEs {
		b.WriteByte(' ')
		b.WriteString(c)
	}
	b.WriteByte(' ')
	l.summary = b.Len()
	b.WriteString(f.Summary)
	return b.String(), l
}

// sevCond is one severity comparison such as ">=high" or "=critical".
type sevCond struct {
	op  string // "=", ">=", ">", "<=", "<"; "" means "="
	val model.Severity
}

func (c sevCond) match(x model.Severity) bool {
	switch c.op {
	case ">=":
		return x >= c.val
	case ">":
		return x > c.val
	case "<=":
		return x <= c.val
	case "<":
		return x < c.val
	default:
		return x == c.val
	}
}

var severityValues = map[string]model.Severity{
	"unknown":  model.SeverityUnknown,
	"low":      model.SeverityLow,
	"medium":   model.SeverityMedium,
	"moderate": model.SeverityMedium,
	"high":     model.SeverityHigh,
	"critical": model.SeverityCritical,
}

// parseSevConds parses a severity value: an optional comparison operator and a
// comma-separated list of names ("high", ">=medium", "high,critical").
func parseSevConds(v string) ([]sevCond, bool) {
	var conds []sevCond
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		op, val := "", part
		for _, o := range []string{">=", "<=", ">", "<", "="} {
			if s, ok := strings.CutPrefix(part, o); ok {
				op, val = o, s
				break
			}
		}
		sev, ok := severityValues[strings.ToLower(strings.TrimSpace(val))]
		if !ok {
			return nil, false
		}
		conds = append(conds, sevCond{op: cmp.Or(op, "="), val: sev})
	}
	return conds, len(conds) > 0
}

// query is a parsed search query. Field terms (key:value) and free-text terms
// are ANDed; the values inside one field term are ORed.
type query struct {
	terms []string    // free text, matched against the lowercased search key
	sev   [][]sevCond // severity constraints; OR within one, AND across
	eco   []string    // ecosystem substrings
	pkg   []string    // package name substrings
	id    []string    // OSV ID substrings
	cve   []string    // CVE ID substrings
	src   []string    // lockfile source substrings
	fixed *bool       // fixed:true / fixed:false
}

var fieldKeys = map[string]bool{
	"severity": true, "sev": true,
	"ecosystem": true, "eco": true,
	"package": true, "pkg": true,
	"id": true, "cve": true, "source": true, "fixed": true,
}

// parseQuery splits the query into field terms and free text. A field term is
// "key:value"; the value may also be separated by a space ("severity: high").
// Unknown keys and unparsable values fall back to free text.
func parseQuery(s string) query {
	var q query
	fields := strings.Fields(s)
	for i := 0; i < len(fields); i++ {
		key, val, ok := strings.Cut(fields[i], ":")
		k := strings.ToLower(key)
		if !ok || !fieldKeys[k] {
			q.terms = append(q.terms, strings.ToLower(fields[i]))
			continue
		}
		raw := fields[i]
		if val == "" && i+1 < len(fields) {
			i++
			val = fields[i]
			raw += " " + val
		}
		if !q.add(k, val) {
			q.terms = append(q.terms, strings.ToLower(raw))
		}
	}
	return q
}

// add applies one key:value pair. It reports whether the value was valid.
func (q *query) add(key, val string) bool {
	switch key {
	case "severity", "sev":
		conds, ok := parseSevConds(val)
		if !ok {
			return false
		}
		q.sev = append(q.sev, conds)
	case "ecosystem", "eco":
		q.eco = append(q.eco, strings.ToLower(val))
	case "package", "pkg":
		q.pkg = append(q.pkg, strings.ToLower(val))
	case "id":
		q.id = append(q.id, strings.ToLower(val))
	case "cve":
		q.cve = append(q.cve, strings.ToLower(val))
	case "source":
		q.src = append(q.src, strings.ToLower(val))
	case "fixed":
		var b bool
		switch strings.ToLower(val) {
		case "true", "yes", "1":
			b = true
		case "false", "no", "0":
			b = false
		default:
			return false
		}
		q.fixed = &b
	}
	return true
}

// match reports whether the finding satisfies every constraint of the query.
// n carries the precomputed lowercase text of f (see Normalize).
func (q query) match(f model.Finding, n Normalized) bool {
	for _, t := range q.terms {
		if !strings.Contains(n.Key, t) {
			return false
		}
	}
	for _, cs := range q.sev {
		if !slices.ContainsFunc(cs, func(c sevCond) bool { return c.match(f.Severity) }) {
			return false
		}
	}
	for _, s := range q.eco {
		if !strings.Contains(n.Eco, s) {
			return false
		}
	}
	for _, s := range q.pkg {
		if !strings.Contains(n.Name, s) {
			return false
		}
	}
	for _, s := range q.id {
		if !strings.Contains(n.ID, s) {
			return false
		}
	}
	for _, s := range q.cve {
		// CVE values are lowercased by parseQuery; n.CVEs by Normalize.
		matched := false
		for _, c := range n.CVEs {
			if strings.Contains(c, s) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, s := range q.src {
		if !strings.Contains(n.Source, s) {
			return false
		}
	}
	if q.fixed != nil && (len(f.FixedVersions) > 0) != *q.fixed {
		return false
	}
	return true
}

// termOffsets returns the byte offsets of every occurrence of every term in
// the (lowercased) key, used for highlighting in the list.
func termOffsets(key string, terms []string) []int {
	var off []int
	for _, t := range terms {
		for i := 0; ; {
			j := strings.Index(key[i:], t)
			if j < 0 {
				break
			}
			off = append(off, i+j)
			i += j + len(t)
		}
	}
	return off
}

// Search filters findings (already sorted with SortFindings) by the Filter,
// then by the parsed query. Results keep the sorted order. norms must hold the
// Normalized text of each finding, in the same order (see Normalize).
func Search(findings []model.Finding, norms []Normalized, queryStr string, f Filter) []Result {
	q := parseQuery(queryStr)
	var out []Result
	for i, x := range findings {
		if !f.match(x) {
			continue
		}
		if !q.match(x, norms[i]) {
			continue
		}
		out = append(out, Result{Index: i, Matched: termOffsets(norms[i].Key, q.terms)})
	}
	return out
}
