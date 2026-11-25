package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luminariadev/raksa-netguard/internal/schema"
)

func TestLoadPolicy_ValidAndErrors(t *testing.T) {
	t.Run("loads example baseline policy", func(t *testing.T) {
		p, err := LoadPolicy(filepath.Join("..", "..", "configs", "baseline.example.yaml"))
		if err != nil {
			t.Fatalf("unexpected error loading example policy: %v", err)
		}
		if len(p.AllowedPorts) != 5 {
			t.Fatalf("expected 5 allowed ports, got %d", len(p.AllowedPorts))
		}
		if len(p.ForbiddenPorts) != 3 {
			t.Fatalf("expected 3 forbidden ports, got %d", len(p.ForbiddenPorts))
		}
	})

	cases := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "invalid port zero",
			content: `
version: "1.0"
allowed_ports:
  - port: 0
    protocol: tcp
`,
			wantErr: "out of range",
		},
		{
			name: "invalid protocol",
			content: `
version: "1.0"
allowed_ports:
  - port: 443
    protocol: icmp
`,
			wantErr: "unsupported protocol",
		},
		{
			name: "duplicate allowed port",
			content: `
version: "1.0"
allowed_ports:
  - port: 443
    protocol: tcp
  - port: 443
    protocol: TCP
`,
			wantErr: "duplicate allowed_ports",
		},
		{
			name: "conflict allowed and forbidden",
			content: `
version: "1.0"
allowed_ports:
  - port: 23
    protocol: tcp
forbidden_ports:
  - port: 23
    protocol: tcp
`,
			wantErr: "cannot appear in both",
		},
		{
			name: "malformed yaml",
			content: `
allowed_ports:
  - port: [not-a-number
`,
			wantErr: "parse policy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.yaml")
			writeTempPolicy(t, path, tc.content)

			_, err := LoadPolicy(path)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidatePolicy(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	t.Run("clean example policy yields zero findings", func(t *testing.T) {
		p, err := LoadPolicy(filepath.Join("..", "..", "configs", "baseline.example.yaml"))
		if err != nil {
			t.Fatalf("load example policy: %v", err)
		}
		findings := ValidatePolicy(p, now)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %+v", findings)
		}
	})

	t.Run("flags sensitive wildcard without justification and cleartext service", func(t *testing.T) {
		p := &Policy{
			Version: "1.0",
			AllowedPorts: []PortRule{
				{
					Port:         5432,
					Protocol:     "tcp",
					AllowedBinds: []string{"0.0.0.0"},
					AllowPublic:  false,
				},
				{
					Port:         21,
					Protocol:     "tcp",
					AllowedBinds: []string{"127.0.0.1"},
				},
			},
		}

		findings := ValidatePolicy(p, now)
		if len(findings) != 2 {
			t.Fatalf("expected 2 findings, got %d (%+v)", len(findings), findings)
		}

		seen := map[string]bool{}
		for _, f := range findings {
			seen[f.RuleID] = true
		}
		if !seen["NET-010"] || !seen["NET-011"] {
			t.Fatalf("expected both NET-010 and NET-011, got %+v", seen)
		}
	})
}

func TestParseProcNet(t *testing.T) {
	t.Run("parses IPv4 TCP listeners and ignores established sockets", func(t *testing.T) {
		sample := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 12345
   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346
   2: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000   100        0 12347
`
		got, err := ParseProcNet(strings.NewReader(sample), "tcp")
		if err != nil {
			t.Fatalf("ParseProcNet tcp: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 listeners, got %+v", got)
		}
		if got[0].BindAddr != "0.0.0.0" || got[0].Port != 443 {
			t.Fatalf("unexpected first listener: %+v", got[0])
		}
		if got[1].BindAddr != "127.0.0.1" || got[1].Port != 8080 {
			t.Fatalf("unexpected second listener: %+v", got[1])
		}
	})

	t.Run("parses IPv6 TCP listeners", func(t *testing.T) {
		sample := `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:1538 00000000000000000000000000000000:0000 0A
   1: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A
`
		got, err := ParseProcNet(strings.NewReader(sample), "tcp")
		if err != nil {
			t.Fatalf("ParseProcNet tcp6: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 IPv6 listeners, got %+v", got)
		}
		if got[0].BindAddr != "::" || got[0].Port != 80 {
			t.Fatalf("unexpected listener 0: %+v", got[0])
		}
		if got[1].BindAddr != "::1" || got[1].Port != 5432 {
			t.Fatalf("unexpected listener 1: %+v", got[1])
		}
	})

	t.Run("parses bound UDP sockets", func(t *testing.T) {
		sample := `  sl  local_address rem_address   st
   0: 0100007F:0035 00000000:0000 07
   1: 0100007F:D431 0100007F:0035 01
`
		got, err := ParseProcNet(strings.NewReader(sample), "udp")
		if err != nil {
			t.Fatalf("ParseProcNet udp: %v", err)
		}
		if len(got) != 1 || got[0].Protocol != "udp" || got[0].Port != 53 {
			t.Fatalf("unexpected UDP listeners: %+v", got)
		}
	})
}

func TestParseNetstatOutput(t *testing.T) {
	sample := `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       1420
  TCP    127.0.0.1:8080         0.0.0.0:0              LISTENING       3210
  TCP    127.0.0.1:8080         127.0.0.1:50123        ESTABLISHED     3210
  TCP    [::]:80                [::]:0                 LISTENING       1420
  TCP    [::1]:5432             [::]:0                 LISTENING       4400
  UDP    0.0.0.0:5353           *:*                                    1820
`
	got, err := ParseNetstatOutput(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("ParseNetstatOutput: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("expected 5 parsed listeners, got %d (%+v)", len(got), got)
	}
	if got[0].Protocol != "tcp" || got[0].Port != 80 || got[0].BindAddr != "::" {
		t.Fatalf("unexpected first listener: %+v", got[0])
	}
	if got[4].Protocol != "udp" || got[4].Port != 5353 || got[4].PID != "1820" {
		t.Fatalf("unexpected UDP listener: %+v", got[4])
	}
}

func TestAudit(t *testing.T) {
	now := time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC)

	policy := &Policy{
		Version: "1.0",
		AllowedPorts: []PortRule{
			{
				Port:         443,
				Protocol:     "tcp",
				Service:      "nginx",
				AllowedBinds: []string{"0.0.0.0", "::"},
				AllowPublic:  true,
			},
			{
				Port:         5432,
				Protocol:     "tcp",
				Service:      "postgresql",
				AllowedBinds: []string{"127.0.0.1"},
				AllowPublic:  false,
			},
			{
				Port:         6379,
				Protocol:     "tcp",
				Service:      "redis",
				AllowedBinds: []string{"0.0.0.0"},
				AllowPublic:  false,
			},
		},
		ForbiddenPorts: []ForbiddenPort{
			{
				Port:     23,
				Protocol: "tcp",
				Reason:   "Telnet forbidden",
			},
		},
	}

	t.Run("clean host returns zero findings", func(t *testing.T) {
		listeners := []Listener{
			{Protocol: "tcp", BindAddr: "0.0.0.0", Port: 443, State: "LISTENING", PID: "100"},
			{Protocol: "tcp", BindAddr: "127.0.0.1", Port: 5432, State: "LISTENING", PID: "200"},
		}
		got := Audit(listeners, policy, now)
		if len(got) != 0 {
			t.Fatalf("expected 0 findings, got %+v", got)
		}
	})

	t.Run("detects NET-001 through NET-004", func(t *testing.T) {
		listeners := []Listener{
			{Protocol: "tcp", BindAddr: "0.0.0.0", Port: 23, State: "LISTENING", PID: "11"},   // NET-001 critical
			{Protocol: "tcp", BindAddr: "0.0.0.0", Port: 9090, State: "LISTENING", PID: "22"}, // NET-002 high
			{Protocol: "tcp", BindAddr: "0.0.0.0", Port: 5432, State: "LISTENING", PID: "33"}, // NET-003 high
			{Protocol: "tcp", BindAddr: "0.0.0.0", Port: 6379, State: "LISTENING", PID: "44"}, // NET-004 medium
		}

		got := Audit(listeners, policy, now)
		if len(got) != 4 {
			t.Fatalf("expected 4 findings, got %d (%+v)", len(got), got)
		}

		want := map[string]schema.Severity{
			"NET-001": schema.SeverityCritical,
			"NET-002": schema.SeverityHigh,
			"NET-003": schema.SeverityHigh,
			"NET-004": schema.SeverityMedium,
		}
		for _, f := range got {
			expSev, ok := want[f.RuleID]
			if !ok {
				t.Fatalf("unexpected rule %s", f.RuleID)
			}
			if f.Severity != expSev {
				t.Fatalf("rule %s expected severity %s, got %s", f.RuleID, expSev, f.Severity)
			}
			if f.MitreD3FEND == "" || f.Remediation == "" {
				t.Fatalf("rule %s missing MITRE D3FEND or remediation", f.RuleID)
			}
		}
	})
}

func writeTempPolicy(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp policy: %v", err)
	}
}
