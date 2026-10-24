// Package model defines the data passed between the scanner, cache and TUI.
package model

import (
	"fmt"
	"strings"
	"time"
)

type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityUnknown:  "unknown",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "unknown"
}

// Short returns the 4-character label used in the TUI list.
func (s Severity) Short() string {
	switch s {
	case SeverityCritical:
		return "CRIT"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MED"
	case SeverityLow:
		return "LOW"
	default:
		return "UNK"
	}
}

func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *Severity) UnmarshalText(b []byte) error {
	for k, v := range severityNames {
		if v == string(b) {
			*s = k
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", string(b))
}

// SeverityFromScore maps a CVSS score to a severity band.
func SeverityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// SeverityFromLabel maps an advisory label such as GHSA's "MODERATE" to a severity.
func SeverityFromLabel(label string) Severity {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MODERATE", "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

type Package struct {
	Name      string `json:"name"`      // e.g. golang.org/x/net
	Version   string `json:"version"`   // e.g. 0.17.0
	Ecosystem string `json:"ecosystem"` // e.g. Go, npm, PyPI
	Source    string `json:"source"`    // lockfile path relative to the root, e.g. go.mod
}

// Finding is one package × one vulnerability; one row in the TUI.
type Finding struct {
	ID            string    `json:"id"`      // OSV ID, e.g. GO-2024-2687
	Aliases       []string  `json:"aliases"` // alternate IDs such as CVE / GHSA
	CVEs          []string  `json:"cves"`    // entries from Aliases starting with CVE-
	Summary       string    `json:"summary"`
	Details       string    `json:"details"` // Markdown
	Severity      Severity  `json:"severity"`
	CVSSScore     float64   `json:"cvss_score"` // 0 if unknown
	Package       Package   `json:"package"`
	FixedVersions []string  `json:"fixed_versions"` // empty if no fixed version
	References    []string  `json:"references"`     // URLs
	Published     time.Time `json:"published"`
	Modified      time.Time `json:"modified"`
}
