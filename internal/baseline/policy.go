package baseline

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/luminariadev/raksa-netguard/internal/schema"
	"gopkg.in/yaml.v3"
)

const (
	moduleBaseline = "baseline-auditor"
	maxPolicyBytes = 1 << 20 // 1 MiB cap prevents YAML memory exhaustion on untrusted files
)

var sensitivePorts = map[int]string{
	22:    "ssh",
	23:    "telnet",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	6379:  "redis",
	9200:  "elasticsearch",
	27017: "mongodb",
}

var insecureCleartextPorts = map[int]string{
	21:  "ftp",
	23:  "telnet",
	69:  "tftp",
	512: "rexec",
	513: "rlogin",
	514: "rsh",
}

// Policy defines the expected listening ports and optional scan thresholds for a host.
type Policy struct {
	Version        string          `yaml:"version"`
	HostRole       string          `yaml:"host_role"`
	AllowedPorts   []PortRule      `yaml:"allowed_ports"`
	ForbiddenPorts []ForbiddenPort `yaml:"forbidden_ports"`
	Detector       *DetectorPolicy `yaml:"detector,omitempty"`
}

// PortRule authorizes a listening socket on a specific port and protocol.
type PortRule struct {
	Port         int      `yaml:"port"`
	Protocol     string   `yaml:"protocol"`
	Service      string   `yaml:"service"`
	AllowedBinds []string `yaml:"allowed_binds"`
	AllowPublic  bool     `yaml:"allow_public"`
	Reason       string   `yaml:"reason"`
}

// ForbiddenPort explicitly prohibits a port/protocol from listening on the host.
type ForbiddenPort struct {
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol"`
	Reason   string `yaml:"reason"`
}

// DetectorPolicy stores optional log-detector defaults inside a baseline policy file.
type DetectorPolicy struct {
	Window                  string `yaml:"window"`
	VerticalPortThreshold   int    `yaml:"vertical_port_threshold"`
	HorizontalHostThreshold int    `yaml:"horizontal_host_threshold"`
	BurstThreshold          int    `yaml:"burst_threshold"`
	Cooldown                string `yaml:"cooldown"`
	IgnorePrivate           *bool  `yaml:"ignore_private,omitempty"`
}

type portKey struct {
	port  int
	proto string
}

// LoadPolicy reads, parses, and validates a YAML baseline policy from disk.
func LoadPolicy(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %q: %w", path, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxPolicyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read policy %q: %w", path, err)
	}
	if len(data) > maxPolicyBytes {
		return nil, fmt.Errorf("policy %q exceeds maximum size of %d bytes", path, maxPolicyBytes)
	}

	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy %q: %w", path, err)
	}

	if err := p.normalizeAndValidate(); err != nil {
		return nil, fmt.Errorf("invalid policy %q: %w", path, err)
	}
	return &p, nil
}

func (p *Policy) normalizeAndValidate() error {
	allowedSeen := make(map[portKey]struct{}, len(p.AllowedPorts))
	for i := range p.AllowedPorts {
		rule := &p.AllowedPorts[i]
		if err := validatePort(rule.Port); err != nil {
			return fmt.Errorf("allowed_ports[%d]: %w", i, err)
		}
		proto, err := normalizeProtocol(rule.Protocol)
		if err != nil {
			return fmt.Errorf("allowed_ports[%d]: %w", i, err)
		}
		rule.Protocol = proto

		for j, b := range rule.AllowedBinds {
			norm := normalizeBindAddr(b)
			if norm == "" {
				return fmt.Errorf("allowed_ports[%d].allowed_binds[%d]: empty bind address", i, j)
			}
			if !IsWildcardBind(norm) && net.ParseIP(norm) == nil {
				return fmt.Errorf("allowed_ports[%d].allowed_binds[%d]: invalid IP address %q", i, j, b)
			}
			rule.AllowedBinds[j] = norm
		}

		key := portKey{port: rule.Port, proto: proto}
		if _, exists := allowedSeen[key]; exists {
			return fmt.Errorf("duplicate allowed_ports entry for %d/%s", rule.Port, proto)
		}
		allowedSeen[key] = struct{}{}
	}

	forbiddenSeen := make(map[portKey]struct{}, len(p.ForbiddenPorts))
	for i := range p.ForbiddenPorts {
		fp := &p.ForbiddenPorts[i]
		if err := validatePort(fp.Port); err != nil {
			return fmt.Errorf("forbidden_ports[%d]: %w", i, err)
		}
		proto, err := normalizeProtocol(fp.Protocol)
		if err != nil {
			return fmt.Errorf("forbidden_ports[%d]: %w", i, err)
		}
		fp.Protocol = proto

		key := portKey{port: fp.Port, proto: proto}
		if _, exists := forbiddenSeen[key]; exists {
			return fmt.Errorf("duplicate forbidden_ports entry for %d/%s", fp.Port, proto)
		}
		if _, conflict := allowedSeen[key]; conflict {
			return fmt.Errorf("port %d/%s cannot appear in both allowed_ports and forbidden_ports", fp.Port, proto)
		}
		forbiddenSeen[key] = struct{}{}
	}

	return nil
}

// ValidatePolicy evaluates a loaded Policy for overly permissive or insecure baseline definitions.
func ValidatePolicy(p *Policy, now time.Time) []schema.Finding {
	if p == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var findings []schema.Finding
	for _, rule := range p.AllowedPorts {
		if svc, insecure := insecureCleartextPorts[rule.Port]; insecure {
			findings = append(findings, schema.Finding{
				ID:          fmt.Sprintf("net-011-%s-%d", rule.Protocol, rule.Port),
				RuleID:      "NET-011",
				Module:      moduleBaseline,
				Layer:       schema.LayerNetwork,
				Severity:    schema.SeverityHigh,
				Title:       "Insecure cleartext protocol permitted in baseline",
				Description: fmt.Sprintf("Baseline policy explicitly allows cleartext service %s on %d/%s.", svc, rule.Port, rule.Protocol),
				Target:      fmt.Sprintf("policy://allowed_ports/%s/%d", rule.Protocol, rule.Port),
				Evidence: map[string]any{
					"port":     rule.Port,
					"protocol": rule.Protocol,
					"service":  svc,
				},
				Remediation: fmt.Sprintf("Remove %d/%s from allowed_ports, move it to forbidden_ports, and migrate to an encrypted alternative.", rule.Port, rule.Protocol),
				MitreD3FEND: "D3-NI",
				Timestamp:   now.UTC(),
			})
		}

		if svc, sensitive := sensitivePorts[rule.Port]; sensitive && ruleAllowsWildcard(rule) {
			if !rule.AllowPublic || strings.TrimSpace(rule.Reason) == "" {
				findings = append(findings, schema.Finding{
					ID:          fmt.Sprintf("net-010-%s-%d", rule.Protocol, rule.Port),
					RuleID:      "NET-010",
					Module:      moduleBaseline,
					Layer:       schema.LayerNetwork,
					Severity:    schema.SeverityHigh,
					Title:       "Sensitive port allowed on wildcard address without justification",
					Description: fmt.Sprintf("Sensitive service %s (%d/%s) permits wildcard binds without allow_public: true and an explicit reason.", svc, rule.Port, rule.Protocol),
					Target:      fmt.Sprintf("policy://allowed_ports/%s/%d", rule.Protocol, rule.Port),
					Evidence: map[string]any{
						"port":          rule.Port,
						"protocol":      rule.Protocol,
						"service":       svc,
						"allowed_binds": rule.AllowedBinds,
						"allow_public":  rule.AllowPublic,
					},
					Remediation: "Restrict allowed_binds to loopback or private management interfaces, or document allow_public: true with a clear security justification.",
					MitreD3FEND: "D3-HBPI",
					Timestamp:   now.UTC(),
				})
			}
		}
	}

	return findings
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of range [1, 65535]", port)
	}
	return nil
}

func normalizeProtocol(proto string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(proto))
	switch p {
	case "tcp", "udp":
		return p, nil
	default:
		return "", fmt.Errorf("unsupported protocol %q: expected tcp or udp", proto)
	}
}

func normalizeBindAddr(addr string) string {
	s := strings.TrimSpace(addr)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if zoneIdx := strings.Index(s, "%"); zoneIdx != -1 {
		s = s[:zoneIdx]
	}
	if s == "*" {
		return "0.0.0.0"
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// IsWildcardBind reports whether addr listens on all interfaces (IPv4 or IPv6).
func IsWildcardBind(addr string) bool {
	norm := normalizeBindAddr(addr)
	if norm == "0.0.0.0" || norm == "::" || norm == "::0" {
		return true
	}
	ip := net.ParseIP(norm)
	return ip != nil && ip.IsUnspecified()
}

// IsSensitivePort reports whether port corresponds to a well-known administrative or datastore service.
func IsSensitivePort(port int) (string, bool) {
	svc, ok := sensitivePorts[port]
	return svc, ok
}

func ruleAllowsWildcard(rule PortRule) bool {
	if len(rule.AllowedBinds) == 0 {
		return true
	}
	for _, b := range rule.AllowedBinds {
		if IsWildcardBind(b) {
			return true
		}
	}
	return false
}
