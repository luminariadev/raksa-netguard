package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/luminariadev/raksa-netguard/internal/schema"
)

func TestFormatters(t *testing.T) {
	now := time.Date(2026, 11, 25, 15, 0, 0, 0, time.UTC)
	sampleFindings := []schema.Finding{
		{
			ID:          "net-001-tcp-0-0-0-0-23",
			RuleID:      "NET-001",
			Module:      "baseline-auditor",
			Layer:       schema.LayerNetwork,
			Severity:    schema.SeverityCritical,
			Title:       "Forbidden listening port exposed",
			Description: "Port 23/tcp is active.",
			Target:      "tcp://0.0.0.0:23",
			Remediation: "Disable telnet.",
			MitreD3FEND: "D3-NI",
			Timestamp:   now,
		},
		{
			ID:          "net-103-198-51-100-77-1",
			RuleID:      "NET-103",
			Module:      "scan-detector",
			Layer:       schema.LayerNetwork,
			Severity:    schema.SeverityMedium,
			Title:       "Connection burst anomaly detected",
			Description: "Burst from 198.51.100.77.",
			Target:      "ip://198.51.100.77->192.0.2.20",
			Remediation: "Apply rate limit.",
			MitreD3FEND: "D3-NTF",
			Timestamp:   now,
		},
	}

	t.Run("table format with findings and empty report", func(t *testing.T) {
		var buf bytes.Buffer
		rep := schema.NewReport(sampleFindings, now)
		if err := WriteReport(&buf, rep, "table"); err != nil {
			t.Fatalf("WriteReport table: %v", err)
		}
		out := buf.String()
		for _, want := range []string{"SEVERITY", "CRITICAL", "NET-001", "tcp://0.0.0.0:23", "total=2"} {
			if !strings.Contains(out, want) {
				t.Fatalf("table output missing %q:\n%s", want, out)
			}
		}

		buf.Reset()
		emptyRep := schema.NewReport(nil, now)
		if err := WriteReport(&buf, emptyRep, "table"); err != nil {
			t.Fatalf("WriteReport empty table: %v", err)
		}
		if !strings.Contains(buf.String(), "No findings detected") {
			t.Fatalf("expected clean summary message, got: %s", buf.String())
		}
	})

	t.Run("json format matches Raksa schema v1", func(t *testing.T) {
		var buf bytes.Buffer
		rep := schema.NewReport(sampleFindings, now)
		if err := WriteReport(&buf, rep, "json"); err != nil {
			t.Fatalf("WriteReport json: %v", err)
		}
		var decoded schema.Report
		if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
			t.Fatalf("unmarshal json report: %v", err)
		}
		if decoded.SchemaVersion != "1.0" || decoded.Summary.Total != 2 || decoded.Summary.Critical != 1 {
			t.Fatalf("unexpected decoded JSON report: %+v", decoded)
		}
		if strings.Contains(buf.String(), `\u003e`) {
			t.Fatalf("JSON output should not escape '>' characters:\n%s", buf.String())
		}
	})

	t.Run("sarif format emits valid SARIF 2.1.0", func(t *testing.T) {
		var buf bytes.Buffer
		rep := schema.NewReport(sampleFindings, now)
		if err := WriteReport(&buf, rep, "sarif"); err != nil {
			t.Fatalf("WriteReport sarif: %v", err)
		}

		var doc sarifLog
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("unmarshal sarif report: %v", err)
		}
		if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
			t.Fatalf("unexpected SARIF envelope: %+v", doc)
		}
		run := doc.Runs[0]
		if len(run.Tool.Driver.Rules) != 2 || len(run.Results) != 2 {
			t.Fatalf("expected 2 rules and 2 results, got rules=%d results=%d", len(run.Tool.Driver.Rules), len(run.Results))
		}
		if run.Results[0].Level != "error" || run.Results[1].Level != "warning" {
			t.Fatalf("unexpected SARIF level mapping: %+v", run.Results)
		}

		// Empty SARIF still outputs empty arrays, not null.
		buf.Reset()
		if err := WriteReport(&buf, schema.NewReport(nil, now), "sarif"); err != nil {
			t.Fatalf("WriteReport empty sarif: %v", err)
		}
		if strings.Contains(buf.String(), `"results": null`) || strings.Contains(buf.String(), `"rules": null`) {
			t.Fatalf("empty SARIF should serialize slices as [], got:\n%s", buf.String())
		}
	})

	t.Run("rejects unknown format", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteReport(&buf, schema.NewReport(nil, now), "xml"); err == nil {
			t.Fatal("expected error for unsupported format")
		}
	})

	t.Run("sanitizes ANSI escapes and control characters in table output", func(t *testing.T) {
		var buf bytes.Buffer
		dirty := []schema.Finding{
			{
				ID:          "net-101-test",
				RuleID:      "NET-101\x1b[31m",
				Module:      "scan-detector",
				Layer:       schema.LayerNetwork,
				Severity:    schema.SeverityHigh,
				Title:       "Title\nInjected\x07Row",
				Description: "Test",
				Target:      "ip://198.51.100.1\x1b[2J",
				Remediation: "Block",
				MitreD3FEND: "D3-NTA",
				Timestamp:   now,
			},
		}
		if err := WriteReport(&buf, schema.NewReport(dirty, now), "table"); err != nil {
			t.Fatalf("WriteReport dirty table: %v", err)
		}
		out := buf.String()
		if strings.Contains(out, "\x1b") || strings.Contains(out, "\x07") {
			t.Fatalf("table output leaked ANSI/control bytes: %q", out)
		}
		if !strings.Contains(out, "Title InjectedRow") {
			t.Fatalf("expected sanitized whitespace replacement, got: %q", out)
		}
	})
}
