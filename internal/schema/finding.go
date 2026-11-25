package schema

import (
	"fmt"
	"strings"
	"time"
)

const (
	SchemaVersion = "1.0"
	ToolName      = "raksa-netguard"
	LayerNetwork  = "network-defense"
)

// Severity represents a normalized finding severity level across the Raksa suite.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// ParseSeverity converts a case-insensitive string into a validated Severity.
func ParseSeverity(raw string) (Severity, error) {
	switch Severity(strings.ToLower(strings.TrimSpace(raw))) {
	case SeverityCritical:
		return SeverityCritical, nil
	case SeverityHigh:
		return SeverityHigh, nil
	case SeverityMedium:
		return SeverityMedium, nil
	case SeverityLow:
		return SeverityLow, nil
	case SeverityInfo:
		return SeverityInfo, nil
	default:
		return "", fmt.Errorf("invalid severity %q: expected critical, high, medium, low, or info", raw)
	}
}

// SeverityRank returns an ordinal weight where higher numbers mean greater risk.
func SeverityRank(s Severity) int {
	switch Severity(strings.ToLower(string(s))) {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// MeetsThreshold reports whether severity s is at or above threshold.
func MeetsThreshold(s, threshold Severity) bool {
	if threshold == "" {
		return false
	}
	return SeverityRank(s) >= SeverityRank(threshold)
}

// Finding represents a single normalized defensive alert or audit finding.
type Finding struct {
	ID          string         `json:"id"`
	RuleID      string         `json:"rule_id"`
	Module      string         `json:"module"`
	Layer       string         `json:"layer"`
	Severity    Severity       `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Target      string         `json:"target"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	Remediation string         `json:"remediation"`
	MitreD3FEND string         `json:"mitre_d3fend"`
	Timestamp   time.Time      `json:"timestamp"`
}

// Summary aggregates finding counts by severity level.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Report is the top-level Raksa Finding Schema v1 document.
type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          string    `json:"tool"`
	Layer         string    `json:"layer"`
	GeneratedAt   time.Time `json:"generated_at"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
}

// NewReport builds a Report and computes its severity summary from findings.
func NewReport(findings []Finding, generatedAt time.Time) Report {
	if findings == nil {
		findings = []Finding{}
	}
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	var sum Summary
	sum.Total = len(findings)
	for _, f := range findings {
		switch Severity(strings.ToLower(string(f.Severity))) {
		case SeverityCritical:
			sum.Critical++
		case SeverityHigh:
			sum.High++
		case SeverityMedium:
			sum.Medium++
		case SeverityLow:
			sum.Low++
		case SeverityInfo:
			sum.Info++
		}
	}

	return Report{
		SchemaVersion: SchemaVersion,
		Tool:          ToolName,
		Layer:         LayerNetwork,
		GeneratedAt:   generatedAt.UTC(),
		Summary:       sum,
		Findings:      findings,
	}
}

// HasThresholdBreach returns true if any finding meets or exceeds threshold.
func (r Report) HasThresholdBreach(threshold Severity) bool {
	if threshold == "" {
		return false
	}
	for _, f := range r.Findings {
		if MeetsThreshold(f.Severity, threshold) {
			return true
		}
	}
	return false
}
