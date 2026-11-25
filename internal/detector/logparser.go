package detector

import (
	"encoding/json"
	"fmt"
	"net/netip"
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
		if looksLikeWindowsFirewallLine(trimmed) {
			return parseWindowsFirewallLine(trimmed)
		}
		return Event{}, false, nil
	case "ufw", "iptables", "nftables":
		return parseKernelFirewallLine(trimmed)
	case "windows-fw", "pfirewall":
		return parseWindowsFirewallLine(trimmed)
	case "jsonl":
		return parseJSONLLine(trimmed)
	default:
		return Event{}, false, fmt.Errorf("unsupported log format %q: expected auto, ufw, iptables, nftables, windows-fw, or jsonl", format)
	}
}

func parseJSONLLine(line string) (Event, bool, error) {
	var raw jsonlEvent
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return Event{}, false, fmt.Errorf("parse jsonl event: %w", err)
	}

	srcAddr, err := netip.ParseAddr(strings.TrimSpace(raw.SrcIP))
	if err != nil {
		return Event{}, false, fmt.Errorf("jsonl event missing valid src_ip")
	}
	dstAddr, err := netip.ParseAddr(strings.TrimSpace(raw.DstIP))
	if err != nil {
		return Event{}, false, fmt.Errorf("jsonl event missing valid dst_ip")
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
		SrcIP:     srcAddr.Unmap().String(),
		DstIP:     dstAddr.Unmap().String(),
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

	srcAddr, err := netip.ParseAddr(kv["SRC"])
	if err != nil {
		return Event{}, false, fmt.Errorf("kernel firewall line missing valid SRC IP")
	}
	dstAddr, err := netip.ParseAddr(kv["DST"])
	if err != nil {
		return Event{}, false, fmt.Errorf("kernel firewall line missing valid DST IP")
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
		SrcIP:     srcAddr.Unmap().String(),
		DstIP:     dstAddr.Unmap().String(),
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  proto,
		Action:    action,
		Raw:       line,
	}, true, nil
}

func looksLikeWindowsFirewallLine(line string) bool {
	if len(line) < 20 || line[4] != '-' || line[7] != '-' || line[10] != ' ' {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) < 8 {
		return false
	}
	act := strings.ToUpper(fields[2])
	return act == "DROP" || act == "ALLOW" || act == "INFO" || act == "OPEN" || act == "CLOSE"
}

func parseWindowsFirewallLine(line string) (Event, bool, error) {
	// W3C Windows Defender Firewall format:
	// date time action protocol src-ip dst-ip src-port dst-port ...
	fields := strings.Fields(line)
	if len(fields) < 8 {
		return Event{}, false, fmt.Errorf("windows-fw line has fewer than 8 fields")
	}

	ts, err := time.Parse("2006-01-02 15:04:05", fields[0]+" "+fields[1])
	if err != nil {
		return Event{}, false, fmt.Errorf("windows-fw invalid timestamp: %w", err)
	}

	srcAddr, err := netip.ParseAddr(fields[4])
	if err != nil {
		return Event{}, false, fmt.Errorf("windows-fw invalid src-ip %q", fields[4])
	}
	dstAddr, err := netip.ParseAddr(fields[5])
	if err != nil {
		return Event{}, false, fmt.Errorf("windows-fw invalid dst-ip %q", fields[5])
	}

	action := strings.ToUpper(fields[2])
	if action == "DROP" {
		action = "BLOCK"
	}
	proto := strings.ToUpper(fields[3])
	if proto == "" || proto == "-" {
		proto = "UNKNOWN"
	}

	return Event{
		Timestamp: ts.UTC(),
		SrcIP:     srcAddr.Unmap().String(),
		DstIP:     dstAddr.Unmap().String(),
		SrcPort:   parseOptionalPort(fields[6]),
		DstPort:   parseOptionalPort(fields[7]),
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
	case strings.Contains(upper, "[UFW BLOCK]") || strings.Contains(upper, "NFT-DROP") || strings.Contains(upper, "NFT_DROP") || strings.Contains(upper, " ACTION=DROP") || strings.Contains(upper, " DROP "):
		return "BLOCK"
	case strings.Contains(upper, "[UFW REJECT]") || strings.Contains(upper, "NFT-REJECT") || strings.Contains(upper, "NFT_REJECT") || strings.Contains(upper, " REJECT "):
		return "REJECT"
	case strings.Contains(upper, "[UFW ALLOW]") || strings.Contains(upper, "NFT-ALLOW") || strings.Contains(upper, "NFT_ALLOW") || strings.Contains(upper, "NFT-ACCEPT") || strings.Contains(upper, "NFT_ACCEPT") || strings.Contains(upper, " ACCEPT "):
		return "ALLOW"
	case strings.Contains(upper, "[UFW AUDIT]"):
		return "AUDIT"
	default:
		return "LOG"
	}
}

func parseOptionalPort(s string) int {
	if s == "" || s == "-" {
		return 0
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 0 || p > 65535 {
		return 0
	}
	return p
}
