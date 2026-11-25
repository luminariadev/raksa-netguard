package report

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/luminariadev/raksa-netguard/internal/schema"
)

const sarifSchemaURL = "https://json.schemastore.org/sarif-2.1.0.json"

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// WriteReport serializes rep in the requested format ("table", "json", or "sarif").
func WriteReport(w io.Writer, rep schema.Report, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "table":
		return FormatTable(w, rep)
	case "json":
		return FormatJSON(w, rep)
	case "sarif":
		return FormatSARIF(w, rep)
	default:
		return fmt.Errorf("unsupported output format %q: expected table, json, or sarif", format)
	}
}

// FormatTable renders a human-readable tabular report and severity summary.
func FormatTable(w io.Writer, rep schema.Report) error {
	if len(rep.Findings) == 0 {
		if _, err := fmt.Fprintf(w, "No findings detected by %s.\n", rep.Tool); err != nil {
			return err
		}
		_, err := fmt.Fprintf(w, "Summary: total=0 critical=0 high=0 medium=0 low=0 info=0\n")
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SEVERITY\tRULE\tTARGET\tTITLE"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(tw, "--------\t----\t------\t-----"); err != nil {
		return err
	}
	for _, f := range rep.Findings {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			strings.ToUpper(string(f.Severity)),
			sanitizeTerminalText(f.RuleID),
			sanitizeTerminalText(f.Target),
			sanitizeTerminalText(f.Title),
		); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	_, err := fmt.Fprintf(w, "\nSummary: total=%d critical=%d high=%d medium=%d low=%d info=%d\n",
		rep.Summary.Total,
		rep.Summary.Critical,
		rep.Summary.High,
		rep.Summary.Medium,
		rep.Summary.Low,
		rep.Summary.Info,
	)
	return err
}

// FormatJSON renders the canonical Raksa Finding Schema v1 JSON report.
func FormatJSON(w io.Writer, rep schema.Report) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	Help             sarifMessage   `json:"help"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifLogicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// FormatSARIF renders rep as a SARIF 2.1.0 document compatible with GitHub Code Scanning.
func FormatSARIF(w io.Writer, rep schema.Report) error {
	ruleMap := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(rep.Findings))

	for _, f := range rep.Findings {
		if _, exists := ruleMap[f.RuleID]; !exists {
			ruleMap[f.RuleID] = sarifRule{
				ID:               f.RuleID,
				Name:             f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				Help:             sarifMessage{Text: f.Remediation},
				Properties: map[string]any{
					"tags":         []string{"security", "blue-team", f.MitreD3FEND},
					"mitre_d3fend": f.MitreD3FEND,
				},
			}
		}

		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: fmt.Sprintf("%s Target: %s. Remediation: %s", f.Description, f.Target, f.Remediation)},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: sarifURI(f.Target)},
					},
					LogicalLocations: []sarifLogicalLocation{
						{
							FullyQualifiedName: f.Target,
							Kind:               f.Module,
						},
					},
				},
			},
		})
	}

	ruleIDs := make([]string, 0, len(ruleMap))
	for id := range ruleMap {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	rules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, ruleMap[id])
	}

	doc := sarifLog{
		Schema:  sarifSchemaURL,
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           rep.Tool,
						InformationURI: "https://github.com/luminariadev/raksa-netguard",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(sev schema.Severity) string {
	switch strings.ToLower(string(sev)) {
	case string(schema.SeverityCritical), string(schema.SeverityHigh):
		return "error"
	case string(schema.SeverityMedium):
		return "warning"
	default:
		return "note"
	}
}

func sarifURI(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return "network/host"
	}
	return t
}

func sanitizeTerminalText(s string) string {
	cleaned := ansiEscapePattern.ReplaceAllString(s, "")
	var b strings.Builder
	b.Grow(len(cleaned))
	for _, r := range cleaned {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
