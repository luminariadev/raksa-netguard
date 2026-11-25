package baseline

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var wellKnownServiceNames = map[int]string{
	22:    "openssh",
	53:    "dns",
	80:    "http",
	443:   "https",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	6379:  "redis",
	8080:  "http-alt",
	9200:  "elasticsearch",
	27017: "mongodb",
}

// GeneratePolicy builds a draft YAML Policy snapshot from observed host listeners.
// Returned reviewNotes highlight risky sockets (wildcard sensitive or cleartext services)
// that the operator should review before locking down the baseline.
func GeneratePolicy(listeners []Listener, hostRole string) (*Policy, []string) {
	role := strings.TrimSpace(hostRole)
	if role == "" {
		role = "server"
	}

	type group struct {
		port    int
		proto   string
		service string
		binds   map[string]struct{}
	}

	groups := make(map[portKey]*group)
	for _, l := range listeners {
		proto, err := normalizeProtocol(l.Protocol)
		if err != nil || l.Port < 1 || l.Port > 65535 {
			continue
		}
		key := portKey{port: l.Port, proto: proto}
		g, ok := groups[key]
		if !ok {
			g = &group{
				port:  l.Port,
				proto: proto,
				binds: make(map[string]struct{}),
			}
			groups[key] = g
		}
		if g.service == "" {
			g.service = inferServiceName(l)
		}
		bind := normalizeBindAddr(l.BindAddr)
		if bind != "" {
			g.binds[bind] = struct{}{}
		}
	}

	keys := make([]portKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].port != keys[j].port {
			return keys[i].port < keys[j].port
		}
		return keys[i].proto < keys[j].proto
	})

	allowed := make([]PortRule, 0, len(keys))
	allowedSet := make(map[portKey]struct{}, len(keys))
	var notes []string

	for _, k := range keys {
		g := groups[k]
		binds := make([]string, 0, len(g.binds))
		hasWildcard := false
		for b := range g.binds {
			binds = append(binds, b)
			if IsWildcardBind(b) {
				hasWildcard = true
			}
		}
		sort.Strings(binds)

		allowPublic := false
		reason := "Observed active listener during baseline initialization"
		if hasWildcard && (g.port == 80 || g.port == 443) {
			allowPublic = true
			reason = "Public web ingress observed during baseline initialization"
		}

		if svc, insecure := insecureCleartextPorts[g.port]; insecure {
			notes = append(notes, fmt.Sprintf("Cleartext service %s (%d/%s) is active; disable and move to forbidden_ports.", svc, g.port, g.proto))
		} else if svc, sensitive := sensitivePorts[g.port]; sensitive && hasWildcard {
			notes = append(notes, fmt.Sprintf("Sensitive service %s (%d/%s) is bound to a wildcard address; restrict allowed_binds to loopback or private IPs.", svc, g.port, g.proto))
		}

		allowed = append(allowed, PortRule{
			Port:         g.port,
			Protocol:     g.proto,
			Service:      g.service,
			AllowedBinds: binds,
			AllowPublic:  allowPublic,
			Reason:       reason,
		})
		allowedSet[k] = struct{}{}
	}

	defaultForbidden := []ForbiddenPort{
		{Port: 21, Protocol: "tcp", Reason: "Unencrypted FTP prohibited; use SFTP/SSH"},
		{Port: 23, Protocol: "tcp", Reason: "Cleartext Telnet protocol prohibited"},
		{Port: 6379, Protocol: "tcp", Reason: "Redis must not listen directly without explicit policy review"},
	}
	forbidden := make([]ForbiddenPort, 0, len(defaultForbidden))
	for _, fp := range defaultForbidden {
		if _, active := allowedSet[portKey{port: fp.Port, proto: fp.Protocol}]; !active {
			forbidden = append(forbidden, fp)
		}
	}

	ignorePriv := true
	policy := &Policy{
		Version:        "1.0",
		HostRole:       role,
		AllowedPorts:   allowed,
		ForbiddenPorts: forbidden,
		Detector: &DetectorPolicy{
			Window:                     "60s",
			VerticalPortThreshold:      10,
			HorizontalHostThreshold:    8,
			BurstThreshold:             25,
			DistributedSourceThreshold: 8,
			DistributedPortThreshold:   10,
			Cooldown:                   "5m",
			IgnorePrivate:              &ignorePriv,
		},
	}

	return policy, notes
}

// MarshalPolicyYAML serializes p into a cleanly commented YAML baseline document.
func MarshalPolicyYAML(p *Policy) ([]byte, error) {
	body, err := yaml.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal policy yaml: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteString("# Baseline policy created by raksa-netguard init\n")
	buf.WriteString("# Review allowed_binds and sensitive ports before enforcing in CI/production.\n\n")
	buf.Write(body)
	return buf.Bytes(), nil
}

func inferServiceName(l Listener) string {
	if name := strings.TrimSpace(l.ProcessName); name != "" {
		return name
	}
	if name, ok := wellKnownServiceNames[l.Port]; ok {
		return name
	}
	return fmt.Sprintf("port-%d", l.Port)
}
