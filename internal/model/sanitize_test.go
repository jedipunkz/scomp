package model

import "testing"

func TestSanitize(t *testing.T) {
	in := "ok\x1b[31mred\x1b[0m\x1b]0;title\x07\r\bend\ttab\nline"
	if got, want := Sanitize(in), "okredend tab\nline"; got != want {
		t.Errorf("sanitize = %q, want %q", got, want)
	}
}

// TestSanitize_BidiControlsRemoved checks that Unicode bidi embedding, override
// and isolate controls (category Cf) are removed, so a package name cannot be
// displayed reversed (RTLO spoofing).
func TestSanitize_BidiControlsRemoved(t *testing.T) {
	in := "moc.pas\u202Eexe.exe"
	if got, want := Sanitize(in), "moc.pasexe.exe"; got != want {
		t.Errorf("sanitize RLO = %q, want %q", got, want)
	}
	in = "pkg\u2066evil\u2069\u202A\u202B\u202C\u202D\u202E\u2067\u2068"
	if got, want := Sanitize(in), "pkgevil"; got != want {
		t.Errorf("sanitize isolates = %q, want %q", got, want)
	}
}

// TestSanitize_KeepsNonBidiFormatChars checks that the bidi range does not
// remove adjacent characters: ZWJ (U+200D) in emoji sequences, and the RLM/LRM
// marks (U+200E/U+200F) and U+2066-adjacent letters.
func TestSanitize_KeepsNonBidiFormatChars(t *testing.T) {
	in := "👨\u200D👩 a\u200Eb\u2029c\u2065d"
	if got, want := Sanitize(in), "👨\u200D👩 a\u200Ebc\u2065d"; got != want {
		t.Errorf("sanitize = %q, want %q", got, want)
	}
}

// TestSanitizeFinding_BidiInPackageName checks that SanitizeFinding applies the
// bidi removal to Package.Name, the field shown in the TUI and the issue body.
func TestSanitizeFinding_BidiInPackageName(t *testing.T) {
	f := SanitizeFinding(Finding{Package: Package{Name: "moc.pas\u202Eexe.exe\u2066"}})
	if got, want := f.Package.Name, "moc.pasexe.exe"; got != want {
		t.Errorf("Package.Name = %q, want %q", got, want)
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
