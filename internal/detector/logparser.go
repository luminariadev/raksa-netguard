package detector

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Event represents a normalized firewall or network flow record used for scan analysis.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   int       `json:"src_port"`
	DstPort   int       `json:"dst_port"`
	Protocol  string    `json:"proto"`
	Action    string    `json:"action"`
	Raw       string    `json:"-"`
}

type jsonlEvent struct {
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Proto     string `json:"proto"`
	Action    string `json:"action"`
}

// ParseLine parses a single firewall or flow log line into a normalized Event.
// When a line is empty or unrelated to network telemetry, parsed=false and err=nil.
func ParseLine(line string, format string) (Event, bool, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return Event{}, false, nil
	}

	normFmt := strings.ToLower(strings.TrimSpace(format))
	if normFmt == "" {
		normFmt = "auto"
	}

	switch normFmt {
	case "auto":
		if strings.HasPrefix(trimmed, "{") {
			return parseJSONLLine(trimmed)
		}
		if strings.Contains(trimmed, "SRC=") && strings.Contains(trimmed, "DST=") {
			return parseKernelFirewallLine(trimmed)
		}
		return Event{}, false, nil
	case "ufw", "iptables":
		return parseKernelFirewallLine(trimmed)
	case "jsonl":
		return parseJSONLLine(trimmed)
	default:
		return Event{}, false, fmt.Errorf("unsupported log format %q: expected auto, ufw, iptables, or jsonl", format)
	}
}

func parseJSONLLine(line string) (Event, bool, error) {
	var raw jsonlEvent
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return Event{}, false, fmt.Errorf("parse jsonl event: %w", err)
	}

	srcIP := net.ParseIP(strings.TrimSpace(raw.SrcIP))
	dstIP := net.ParseIP(strings.TrimSpace(raw.DstIP))
	if srcIP == nil || dstIP == nil {
		return Event{}, false, fmt.Errorf("jsonl event missing valid src_ip or dst_ip")
	}

	ts := time.Now().UTC()
	if strings.TrimSpace(raw.Timestamp) != "" {
		parsedTS, err := parseFlexibleTimestamp(raw.Timestamp)
		if err != nil {
			return Event{}, false, fmt.Errorf("parse jsonl timestamp %q: %w", raw.Timestamp, err)
		}
		ts = parsedTS
	}

	proto := strings.ToUpper(strings.TrimSpace(raw.Proto))
	if proto == "" {
		proto = "TCP"
	}
	action := strings.ToUpper(strings.TrimSpace(raw.Action))
	if action == "" {
		action = "LOG"
	}

	return Event{
		Timestamp: ts,
		SrcIP:     srcIP.String(),
		DstIP:     dstIP.String(),
		SrcPort:   raw.SrcPort,
		DstPort:   raw.DstPort,
		Protocol:  proto,
		Action:    action,
		Raw:       line,
	}, true, nil
}

func parseKernelFirewallLine(line string) (Event, bool, error) {
	if !strings.Contains(line, "SRC=") || !strings.Contains(line, "DST=") {
		return Event{}, false, nil
	}

	kv := make(map[string]string, 12)
	fields := strings.Fields(line)
	for _, tok := range fields {
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 || eq == len(tok)-1 {
			continue
		}
		key := tok[:eq]
		val := tok[eq+1:]
		kv[key] = val
	}

	srcIP := net.ParseIP(kv["SRC"])
	dstIP := net.ParseIP(kv["DST"])
	if srcIP == nil || dstIP == nil {
		return Event{}, false, fmt.Errorf("kernel firewall line missing valid SRC/DST IP")
	}

	srcPort := parseOptionalPort(kv["SPT"])
	dstPort := parseOptionalPort(kv["DPT"])

	proto := strings.ToUpper(strings.TrimSpace(kv["PROTO"]))
	if proto == "" {
		proto = "UNKNOWN"
	}

	ts := extractSyslogOrISOTimestamp(fields)
	action := extractFirewallAction(line)

	return Event{
		Timestamp: ts,
		SrcIP:     srcIP.String(),
		DstIP:     dstIP.String(),
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  proto,
		Action:    action,
		Raw:       line,
	}, true, nil
}

func extractSyslogOrISOTimestamp(fields []string) time.Time {
	if len(fields) > 0 {
		if ts, err := parseFlexibleTimestamp(fields[0]); err == nil {
			return ts
		}
	}
	// Traditional BSD syslog timestamp: "Nov 25 14:20:01"
	if len(fields) >= 3 {
		bsd := strings.Join(fields[:3], " ")
		if t, err := time.Parse("Jan _2 15:04:05", bsd); err == nil {
			now := time.Now().UTC()
			return time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
		}
	}
	return time.Now().UTC()
}

func parseFlexibleTimestamp(raw string) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	}
	s := strings.TrimSpace(raw)
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp %q", raw)
}

func extractFirewallAction(line string) string {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "[UFW BLOCK]") || strings.Contains(upper, " ACTION=DROP") || strings.Contains(upper, " DROP "):
		return "BLOCK"
	case strings.Contains(upper, "[UFW REJECT]") || strings.Contains(upper, " REJECT "):
		return "REJECT"
	case strings.Contains(upper, "[UFW ALLOW]") || strings.Contains(upper, " ACCEPT "):
		return "ALLOW"
	case strings.Contains(upper, "[UFW AUDIT]"):
		return "AUDIT"
	default:
		return "LOG"
	}
}

func parseOptionalPort(s string) int {
	if s == "" {
		return 0
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 0 || p > 65535 {
		return 0
	}
	return p
}
