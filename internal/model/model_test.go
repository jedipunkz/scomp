package model

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestSeverityFromScore(t *testing.T) {
	tests := []struct {
		score float64
		want  Severity
	}{
		{10, SeverityCritical},
		{9.0, SeverityCritical},
		{8.9, SeverityHigh},
		{7.0, SeverityHigh},
		{6.9, SeverityMedium},
		{4.0, SeverityMedium},
		{3.9, SeverityLow},
		{0.1, SeverityLow},
		{0, SeverityUnknown},
	}
	for _, tt := range tests {
		if got := SeverityFromScore(tt.score); got != tt.want {
			t.Errorf("SeverityFromScore(%v) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

func TestSeverityFromLabel(t *testing.T) {
	tests := map[string]Severity{
		"CRITICAL": SeverityCritical,
		"high":     SeverityHigh,
		"MODERATE": SeverityMedium,
		"Medium":   SeverityMedium,
		"LOW":      SeverityLow,
		"":         SeverityUnknown,
		"bogus":    SeverityUnknown,
	}
	for in, want := range tests {
		if got := SeverityFromLabel(in); got != want {
			t.Errorf("SeverityFromLabel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSeverityFromName(t *testing.T) {
	tests := map[string]Severity{
		"unknown":   SeverityUnknown,
		"low":       SeverityLow,
		"Medium":    SeverityMedium,
		" moderate": SeverityMedium,
		"HIGH":      SeverityHigh,
		"critical":  SeverityCritical,
	}
	for in, want := range tests {
		got, ok := SeverityFromName(in)
		if !ok || got != want {
			t.Errorf("SeverityFromName(%q) = %v, %t; want %v, true", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "hgih", "severity"} {
		if _, ok := SeverityFromName(in); ok {
			t.Errorf("SeverityFromName(%q) ok = true, want false", in)
		}
	}
}

func TestCVSSSuffix(t *testing.T) {
	tests := map[float64]string{
		0:    "",
		-1:   "",
		7.4:  " (CVSS 7.4)",
		10:   " (CVSS 10.0)",
		0.05: " (CVSS 0.1)",
	}
	for in, want := range tests {
		if got := CVSSSuffix(in); got != want {
			t.Errorf("CVSSSuffix(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestSortFindings(t *testing.T) {
	fs := []Finding{
		{ID: "PYSEC-1", Severity: SeverityMedium, Package: Package{Name: "requests"}},
		{ID: "GO-2", Severity: SeverityHigh, Package: Package{Name: "golang.org/x/net"}},
		{ID: "GO-1", Severity: SeverityHigh, Package: Package{Name: "golang.org/x/net"}},
		{ID: "GHSA-1", Severity: SeverityCritical, Package: Package{Name: "lodash"}},
		{ID: "GO-3", Severity: SeverityUnknown, Package: Package{Name: "a.dev/z"}},
		{ID: "GO-4", Severity: SeverityLow, Package: Package{Name: "a.dev/y"}},
	}
	SortFindings(fs)
	var got []string
	for _, f := range fs {
		got = append(got, f.ID)
	}
	want := []string{"GHSA-1", "GO-1", "GO-2", "PYSEC-1", "GO-4", "GO-3"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	for s := SeverityUnknown; s <= SeverityCritical; s++ {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var got Severity
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if got != s {
			t.Errorf("round trip %v: got %v (json %s)", s, got, b)
		}
	}
	var s Severity
	if err := json.Unmarshal([]byte(`"nope"`), &s); err == nil {
		t.Error("expected error for unknown severity")
	}
}
