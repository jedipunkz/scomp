package model

import "testing"

func TestSanitize(t *testing.T) {
	in := "ok\x1b[31mred\x1b[0m\x1b]0;title\x07\r\bend\ttab\nline"
	if got, want := Sanitize(in), "okredend tab\nline"; got != want {
		t.Errorf("sanitize = %q, want %q", got, want)
	}
}

// TestSanitizeFinding_AllFieldsSanitized checks that every externally sourced
// string of a Finding passes through Sanitize.
func TestSanitizeFinding_AllFieldsSanitized(t *testing.T) {
	in := "x\x1b[31m1\x1b[0m"
	f := SanitizeFinding(Finding{
		ID:      in,
		Summary: in,
		Details: in,
		Package: Package{
			Name:      in,
			Version:   in,
			Ecosystem: in,
			Source:    in,
		},
		Aliases:       []string{in},
		CVEs:          []string{in},
		FixedVersions: []string{in},
		References:    []string{in},
	})
	for _, got := range []string{
		f.ID, f.Summary, f.Details,
		f.Package.Name, f.Package.Version, f.Package.Ecosystem, f.Package.Source,
		f.Aliases[0], f.CVEs[0], f.FixedVersions[0], f.References[0],
	} {
		if got != "x1" {
			t.Errorf("field not sanitized: %q", got)
		}
	}
}
