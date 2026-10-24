package model

import (
	"encoding/json"
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
