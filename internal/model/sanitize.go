// Sanitization of externally sourced strings. Findings and scanner error text
// originate outside scomp (OSV data, lockfiles, file names under the scan
// root, scanner stderr), so every string that reaches the terminal or the TUI
// passes through these helpers first.
package model

import (
	"strings"
	"unicode"

	"github.com/charmbracelet/x/ansi"
)

// SanitizeFinding sanitizes every externally sourced string of a finding.
func SanitizeFinding(f Finding) Finding {
	f.ID = Sanitize(f.ID)
	f.Summary = Sanitize(f.Summary)
	f.Details = Sanitize(f.Details)
	f.Package.Name = Sanitize(f.Package.Name)
	f.Package.Version = Sanitize(f.Package.Version)
	f.Package.Ecosystem = Sanitize(f.Package.Ecosystem)
	f.Package.Source = Sanitize(f.Package.Source)
	f.Aliases = SanitizeAll(f.Aliases)
	f.CVEs = SanitizeAll(f.CVEs)
	f.FixedVersions = SanitizeAll(f.FixedVersions)
	f.References = SanitizeAll(f.References)
	return f
}

// SanitizeAll sanitizes every string in ss.
func SanitizeAll(ss []string) []string {
	if ss == nil {
		return nil
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = Sanitize(s)
	}
	return out
}

// Sanitize removes ANSI escape sequences, control characters and Unicode bidi
// embedding/override/isolate characters, keeping newlines and converting tabs
// to spaces.
func Sanitize(s string) string {
	s = ansi.Strip(s)
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case r == '\t':
			return ' '
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			// Bidi embedding/override and isolate controls are category Cf, so
			// unicode.IsControl misses them. U+202E (RLO) reverses how the
			// following text is displayed, which allows visual spoofing.
			return -1
		case unicode.IsControl(r), r == ' ', r == ' ':
			return -1
		}
		return r
	}, s)
}
