package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luminariadev/raksa-netguard/internal/schema"
)

func TestCLI_RunSubcommands(t *testing.T) {
	t.Run("version and help exit 0", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		if code := run([]string{"version"}, &out, &errBuf); code != exitOK {
			t.Fatalf("version exit=%d stderr=%s", code, errBuf.String())
		}
		if !strings.Contains(out.String(), "raksa-netguard") {
			t.Fatalf("unexpected version output: %s", out.String())
		}

		out.Reset()
		errBuf.Reset()
		if code := run([]string{"help"}, &out, &errBuf); code != exitOK {
			t.Fatalf("help exit=%d stderr=%s", code, errBuf.String())
		}
		if !strings.Contains(out.String(), "Commands:") {
			t.Fatalf("unexpected help output: %s", out.String())
		}
	})

	t.Run("no args and unknown subcommand exit 1", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		if code := run(nil, &out, &errBuf); code != exitErr {
			t.Fatalf("expected exitErr for empty args, got %d", code)
		}
		errBuf.Reset()
		if code := run([]string{"attack"}, &out, &errBuf); code != exitErr {
			t.Fatalf("expected exitErr for unknown subcommand, got %d", code)
		}
	})

	t.Run("policy-check handles compliant and risky policies", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		example := filepath.Join("..", "..", "configs", "baseline.example.yaml")
		if code := run([]string{"policy-check", "--policy", example, "--fail-on", "high"}, &out, &errBuf); code != exitOK {
			t.Fatalf("expected exitOK for compliant example policy, got %d stderr=%s", code, errBuf.String())
		}

		riskyPath := filepath.Join(t.TempDir(), "risky.yaml")
		riskyYAML := `
version: "1.0"
allowed_ports:
  - port: 23
    protocol: tcp
    allowed_binds: ["0.0.0.0"]
`
		if err := os.WriteFile(riskyPath, []byte(riskyYAML), 0o600); err != nil {
			t.Fatalf("write risky policy: %v", err)
		}

		out.Reset()
		errBuf.Reset()
		if code := run([]string{"policy-check", "--policy", riskyPath, "--fail-on", "high"}, &out, &errBuf); code != exitThreshold {
			t.Fatalf("expected exitThreshold (2) for risky policy, got %d stderr=%s", code, errBuf.String())
		}

		out.Reset()
		errBuf.Reset()
		if code := run([]string{"policy-check"}, &out, &errBuf); code != exitErr {
			t.Fatalf("expected exitErr when --policy missing, got %d", code)
		}
	})

	t.Run("analyze handles UFW table, JSONL schema output, and fail-on gate", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		ufwPath := filepath.Join("..", "..", "testdata", "ufw_mixed.log")
		if code := run([]string{"analyze", "--log", ufwPath, "--format", "table"}, &out, &errBuf); code != exitOK {
			t.Fatalf("analyze UFW exit=%d stderr=%s", code, errBuf.String())
		}
		if !strings.Contains(out.String(), "NET-101") || !strings.Contains(out.String(), "NET-102") {
			t.Fatalf("expected NET-101 and NET-102 in table output:\n%s", out.String())
		}

		out.Reset()
		errBuf.Reset()
		jsonlPath := filepath.Join("..", "..", "testdata", "flows_scan.jsonl")
		if code := run([]string{"analyze", "--log", jsonlPath, "--format", "json", "--fail-on", "high"}, &out, &errBuf); code != exitThreshold {
			t.Fatalf("expected exitThreshold (2), got %d stderr=%s", code, errBuf.String())
		}
		var rep schema.Report
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatalf("unmarshal CLI JSON report: %v", err)
		}
		if rep.Summary.High != 1 || rep.Summary.Medium != 1 {
			t.Fatalf("unexpected CLI JSON summary: %+v", rep.Summary)
		}
	})
}
