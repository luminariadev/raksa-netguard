package schema

import (
	"testing"
	"time"
)

func TestParseSeverityAndRanking(t *testing.T) {
	valid := []struct {
		raw  string
		want Severity
		rank int
	}{
		{"CRITICAL", SeverityCritical, 5},
		{" high ", SeverityHigh, 4},
		{"Medium", SeverityMedium, 3},
		{"low", SeverityLow, 2},
		{"info", SeverityInfo, 1},
	}

	for _, tc := range valid {
		got, err := ParseSeverity(tc.raw)
		if err != nil {
			t.Fatalf("ParseSeverity(%q): unexpected error %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("ParseSeverity(%q): want %s, got %s", tc.raw, tc.want, got)
		}
		if SeverityRank(got) != tc.rank {
			t.Fatalf("SeverityRank(%s): want %d, got %d", got, tc.rank, SeverityRank(got))
		}
	}

	if _, err := ParseSeverity("extreme"); err == nil {
		t.Fatal("expected error for invalid severity")
	}
	if SeverityRank("unknown") != 0 {
		t.Fatal("expected rank 0 for unknown severity")
	}

	if !MeetsThreshold(SeverityCritical, SeverityHigh) {
		t.Fatal("critical should meet high threshold")
	}
	if MeetsThreshold(SeverityMedium, SeverityHigh) {
		t.Fatal("medium should not meet high threshold")
	}
	if MeetsThreshold(SeverityCritical, "") {
		t.Fatal("empty threshold should never trigger")
	}
}

func TestNewReportAndThresholdBreach(t *testing.T) {
	t.Run("nil findings serializes empty slice and zero summary", func(t *testing.T) {
		rep := NewReport(nil, time.Time{})
		if rep.SchemaVersion != SchemaVersion || rep.Tool != ToolName || rep.Layer != LayerNetwork {
			t.Fatalf("unexpected report header: %+v", rep)
		}
		if rep.Findings == nil || len(rep.Findings) != 0 {
			t.Fatalf("expected non-nil empty findings slice, got %#v", rep.Findings)
		}
		if rep.Summary.Total != 0 || rep.GeneratedAt.IsZero() {
			t.Fatalf("unexpected summary or timestamp: %+v", rep)
		}
	})

	t.Run("counts all severities and detects threshold breach", func(t *testing.T) {
		now := time.Date(2026, 11, 25, 16, 0, 0, 0, time.UTC)
		findings := []Finding{
			{ID: "1", Severity: SeverityCritical},
			{ID: "2", Severity: SeverityHigh},
			{ID: "3", Severity: SeverityMedium},
			{ID: "4", Severity: SeverityLow},
			{ID: "5", Severity: SeverityInfo},
		}
		rep := NewReport(findings, now)
		if rep.Summary.Total != 5 || rep.Summary.Critical != 1 || rep.Summary.High != 1 ||
			rep.Summary.Medium != 1 || rep.Summary.Low != 1 || rep.Summary.Info != 1 {
			t.Fatalf("unexpected summary counts: %+v", rep.Summary)
		}
		if !rep.HasThresholdBreach(SeverityHigh) {
			t.Fatal("expected breach at high threshold")
		}
		if rep.HasThresholdBreach("") {
			t.Fatal("empty threshold should return false")
		}

		lowOnly := NewReport([]Finding{{ID: "4", Severity: SeverityLow}}, now)
		if lowOnly.HasThresholdBreach(SeverityHigh) {
			t.Fatal("low finding must not breach high threshold")
		}
	})
}
