package schema

// RuleInfo describes a built-in defensive rule implemented by raksa-netguard.
type RuleInfo struct {
	RuleID          string `json:"rule_id"`
	Title           string `json:"title"`
	Module          string `json:"module"`
	DefaultSeverity string `json:"default_severity"`
	MitreD3FEND     string `json:"mitre_d3fend"`
	MitreTechnique  string `json:"mitre_technique"`
	Description     string `json:"description"`
}

// RuleCatalog returns the complete deterministic catalog of built-in rules.
func RuleCatalog() []RuleInfo {
	return []RuleInfo{
		{
			RuleID:          "NET-001",
			Title:           "Forbidden listening port exposed",
			Module:          "baseline-auditor",
			DefaultSeverity: "critical / high",
			MitreD3FEND:     "D3-NI",
			MitreTechnique:  "Network Isolation",
			Description:     "Active local listening socket matches a port explicitly prohibited in forbidden_ports.",
		},
		{
			RuleID:          "NET-002",
			Title:           "Unauthorized listening port detected",
			Module:          "baseline-auditor",
			DefaultSeverity: "high / medium",
			MitreD3FEND:     "D3-HBPI",
			MitreTechnique:  "Host-Based Port Inspection",
			Description:     "Active local listening socket is not authorized in the baseline allowed_ports list.",
		},
		{
			RuleID:          "NET-003",
			Title:           "Overly permissive bind address",
			Module:          "baseline-auditor",
			DefaultSeverity: "high",
			MitreD3FEND:     "D3-NI",
			MitreTechnique:  "Network Isolation",
			Description:     "Authorized port is listening on a wildcard or unapproved interface outside allowed_binds.",
		},
		{
			RuleID:          "NET-004",
			Title:           "Sensitive service publicly bound",
			Module:          "baseline-auditor",
			DefaultSeverity: "medium",
			MitreD3FEND:     "D3-NI",
			MitreTechnique:  "Network Isolation",
			Description:     "Well-known administrative or datastore port is listening on a wildcard interface without allow_public: true.",
		},
		{
			RuleID:          "NET-010",
			Title:           "Sensitive port allowed on wildcard address without justification",
			Module:          "baseline-auditor",
			DefaultSeverity: "high",
			MitreD3FEND:     "D3-HBPI",
			MitreTechnique:  "Host-Based Port Inspection",
			Description:     "Baseline YAML permits wildcard binds for a sensitive port without allow_public: true and an explicit reason.",
		},
		{
			RuleID:          "NET-011",
			Title:           "Insecure cleartext protocol permitted in baseline",
			Module:          "baseline-auditor",
			DefaultSeverity: "high",
			MitreD3FEND:     "D3-NI",
			MitreTechnique:  "Network Isolation",
			Description:     "Baseline YAML explicitly allows unencrypted legacy protocols such as FTP, Telnet, TFTP, or rsh.",
		},
		{
			RuleID:          "NET-101",
			Title:           "Vertical port scan detected",
			Module:          "scan-detector",
			DefaultSeverity: "high",
			MitreD3FEND:     "D3-NTA",
			MitreTechnique:  "Network Traffic Analysis",
			Description:     "Single source IP probed distinct destination ports on a host above vertical_port_threshold within the sliding window.",
		},
		{
			RuleID:          "NET-102",
			Title:           "Horizontal network scan detected",
			Module:          "scan-detector",
			DefaultSeverity: "high",
			MitreD3FEND:     "D3-NTA",
			MitreTechnique:  "Network Traffic Analysis",
			Description:     "Single source IP swept the same destination port across distinct hosts above horizontal_host_threshold within the sliding window.",
		},
		{
			RuleID:          "NET-103",
			Title:           "Connection burst anomaly detected",
			Module:          "scan-detector",
			DefaultSeverity: "medium",
			MitreD3FEND:     "D3-NTF",
			MitreTechnique:  "Network Traffic Filtering",
			Description:     "Single source IP generated connection attempts exceeding burst_threshold within the sliding window.",
		},
		{
			RuleID:          "NET-104",
			Title:           "Distributed multi-source port scan detected",
			Module:          "scan-detector",
			DefaultSeverity: "high",
			MitreD3FEND:     "D3-NTA",
			MitreTechnique:  "Network Traffic Analysis",
			Description:     "Single destination host received probes from multiple distinct source IPs across distinct ports within the sliding window.",
		},
	}
}
