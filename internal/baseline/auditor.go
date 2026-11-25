package baseline

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/luminariadev/raksa-netguard/internal/schema"
)

// Audit evaluates observed host listeners against a baseline policy and returns posture drift findings.
func Audit(listeners []Listener, policy *Policy, now time.Time) []schema.Finding {
	if policy == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()

	allowed := make(map[portKey]PortRule, len(policy.AllowedPorts))
	for _, r := range policy.AllowedPorts {
		allowed[portKey{port: r.Port, proto: r.Protocol}] = r
	}

	forbidden := make(map[portKey]ForbiddenPort, len(policy.ForbiddenPorts))
	for _, fp := range policy.ForbiddenPorts {
		forbidden[portKey{port: fp.Port, proto: fp.Protocol}] = fp
	}

	findings := make([]schema.Finding, 0)
	for _, l := range listeners {
		key := portKey{port: l.Port, proto: strings.ToLower(l.Protocol)}
		target := formatSocketTarget(l)

		if fp, isForbidden := forbidden[key]; isForbidden {
			sev := schema.SeverityHigh
			if IsWildcardBind(l.BindAddr) {
				sev = schema.SeverityCritical
			}
			desc := fmt.Sprintf("Port %d/%s is listening on %s despite being explicitly prohibited by policy.", l.Port, key.proto, l.BindAddr)
			if strings.TrimSpace(fp.Reason) != "" {
				desc = fmt.Sprintf("%s Policy reason: %s.", desc, fp.Reason)
			}
			findings = append(findings, schema.Finding{
				ID:          findingID("net-001", key.proto, l.BindAddr, l.Port),
				RuleID:      "NET-001",
				Module:      moduleBaseline,
				Layer:       schema.LayerNetwork,
				Severity:    sev,
				Title:       "Forbidden listening port exposed",
				Description: desc,
				Target:      target,
				Evidence:    listenerEvidence(l),
				Remediation: fmt.Sprintf("Stop and disable the process listening on %d/%s (PID %s) and block the port at the host firewall.", l.Port, key.proto, fallbackPID(l.PID)),
				MitreD3FEND: "D3-NI",
				Timestamp:   now,
			})
			continue
		}

		rule, isAllowed := allowed[key]
		if !isAllowed {
			sev := schema.SeverityMedium
			if IsWildcardBind(l.BindAddr) {
				sev = schema.SeverityHigh
			} else if _, sensitive := IsSensitivePort(l.Port); sensitive {
				sev = schema.SeverityHigh
			}
			findings = append(findings, schema.Finding{
				ID:          findingID("net-002", key.proto, l.BindAddr, l.Port),
				RuleID:      "NET-002",
				Module:      moduleBaseline,
				Layer:       schema.LayerNetwork,
				Severity:    sev,
				Title:       "Unauthorized listening port detected",
				Description: fmt.Sprintf("Active socket %d/%s on %s is not authorized in baseline allowed_ports.", l.Port, key.proto, l.BindAddr),
				Target:      target,
				Evidence:    listenerEvidence(l),
				Remediation: fmt.Sprintf("Verify whether PID %s requires %d/%s; either terminate the service or register an explicit allowed_ports entry with restricted allowed_binds.", fallbackPID(l.PID), l.Port, key.proto),
				MitreD3FEND: "D3-HBPI",
				Timestamp:   now,
			})
			continue
		}

		if !bindMatchesRule(l.BindAddr, rule.AllowedBinds) {
			sev := schema.SeverityHigh
			title := "Overly permissive bind address"
			if !IsWildcardBind(l.BindAddr) {
				title = "Socket bound to unapproved interface"
			}
			ev := listenerEvidence(l)
			ev["allowed_binds"] = rule.AllowedBinds

			findings = append(findings, schema.Finding{
				ID:          findingID("net-003", key.proto, l.BindAddr, l.Port),
				RuleID:      "NET-003",
				Module:      moduleBaseline,
				Layer:       schema.LayerNetwork,
				Severity:    sev,
				Title:       title,
				Description: fmt.Sprintf("Port %d/%s (%s) is bound to %s, outside its permitted binds %v.", l.Port, key.proto, fallbackService(rule.Service), l.BindAddr, rule.AllowedBinds),
				Target:      target,
				Evidence:    ev,
				Remediation: fmt.Sprintf("Reconfigure %s to bind strictly to one of %v instead of %s.", fallbackService(rule.Service), rule.AllowedBinds, l.BindAddr),
				MitreD3FEND: "D3-NI",
				Timestamp:   now,
			})
			continue
		}

		if svc, sensitive := IsSensitivePort(l.Port); sensitive && IsWildcardBind(l.BindAddr) && !rule.AllowPublic {
			ev := listenerEvidence(l)
			ev["service"] = svc
			ev["allow_public"] = rule.AllowPublic

			findings = append(findings, schema.Finding{
				ID:          findingID("net-004", key.proto, l.BindAddr, l.Port),
				RuleID:      "NET-004",
				Module:      moduleBaseline,
				Layer:       schema.LayerNetwork,
				Severity:    schema.SeverityMedium,
				Title:       "Sensitive service publicly bound",
				Description: fmt.Sprintf("Sensitive service %s (%d/%s) is listening on wildcard address %s without allow_public: true.", svc, l.Port, key.proto, l.BindAddr),
				Target:      target,
				Evidence:    ev,
				Remediation: fmt.Sprintf("Bind %s to 127.0.0.1 or a private interface, or document allow_public: true with firewall restrictions.", svc),
				MitreD3FEND: "D3-NI",
				Timestamp:   now,
			})
		}
	}

	return findings
}

func bindMatchesRule(actual string, allowedBinds []string) bool {
	if len(allowedBinds) == 0 {
		return true
	}
	normActual := normalizeBindAddr(actual)
	actualIP := net.ParseIP(normActual)

	for _, candidate := range allowedBinds {
		normCand := normalizeBindAddr(candidate)
		if normCand == normActual {
			return true
		}
		// Match address-family-equivalent wildcards only within same family or IP equality.
		if actualIP != nil {
			if candIP := net.ParseIP(normCand); candIP != nil && actualIP.Equal(candIP) {
				return true
			}
		}
	}
	return false
}

func listenerEvidence(l Listener) map[string]any {
	ev := map[string]any{
		"protocol": strings.ToLower(l.Protocol),
		"bind_addr": l.BindAddr,
		"port":     l.Port,
		"state":    l.State,
	}
	if l.PID != "" {
		ev["pid"] = l.PID
	}
	if l.ProcessName != "" {
		ev["process"] = l.ProcessName
	}
	return ev
}

func formatSocketTarget(l Listener) string {
	addr := l.BindAddr
	if strings.Contains(addr, ":") {
		addr = "[" + addr + "]"
	}
	return fmt.Sprintf("%s://%s:%d", strings.ToLower(l.Protocol), addr, l.Port)
}

func findingID(prefix, proto, addr string, port int) string {
	cleanAddr := strings.NewReplacer(":", "_", ".", "-").Replace(addr)
	return fmt.Sprintf("%s-%s-%s-%d", prefix, proto, cleanAddr, port)
}

func fallbackPID(pid string) string {
	if strings.TrimSpace(pid) == "" {
		return "unknown"
	}
	return pid
}

func fallbackService(svc string) string {
	if strings.TrimSpace(svc) == "" {
		return "service"
	}
	return svc
}
