package detector

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa-netguard/internal/schema"
)

const moduleDetector = "scan-detector"

// Config controls sliding-window scan detection thresholds and suppression.
type Config struct {
	Window                  time.Duration
	VerticalPortThreshold   int
	HorizontalHostThreshold int
	BurstThreshold          int
	Cooldown                time.Duration
	IgnorePrivate           bool
}

// DefaultConfig returns defensive detection defaults suitable for typical edge/API nodes.
func DefaultConfig() Config {
	return Config{
		Window:                  60 * time.Second,
		VerticalPortThreshold:   10,
		HorizontalHostThreshold: 8,
		BurstThreshold:          25,
		Cooldown:                5 * time.Minute,
		IgnorePrivate:           true,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.Window <= 0 {
		c.Window = d.Window
	}
	if c.VerticalPortThreshold <= 0 {
		c.VerticalPortThreshold = d.VerticalPortThreshold
	}
	if c.HorizontalHostThreshold <= 0 {
		c.HorizontalHostThreshold = d.HorizontalHostThreshold
	}
	if c.BurstThreshold <= 0 {
		c.BurstThreshold = d.BurstThreshold
	}
	if c.Cooldown < 0 {
		c.Cooldown = d.Cooldown
	}
	return c
}

// Stats summarizes log processing counts during batch analysis.
type Stats struct {
	LinesRead    int `json:"lines_read"`
	EventsParsed int `json:"events_parsed"`
	LinesSkipped int `json:"lines_skipped"`
	ParseErrors  int `json:"parse_errors"`
}

type alertKey struct {
	srcIP  string
	ruleID string
}

type sourceWindow struct {
	latest time.Time
	events []Event
}

// Detector tracks per-source network telemetry over a bounded sliding window.
type Detector struct {
	cfg       Config
	mu        sync.Mutex
	sources   map[string]*sourceWindow
	lastAlert map[alertKey]time.Time
}

// New creates a thread-safe Detector configured with cfg.
func New(cfg Config) *Detector {
	return &Detector{
		cfg:       cfg.withDefaults(),
		sources:   make(map[string]*sourceWindow),
		lastAlert: make(map[alertKey]time.Time),
	}
}

// Ingest processes a single Event and returns any triggered scan or anomaly findings.
func (d *Detector) Ingest(ev Event) []schema.Finding {
	if ev.SrcIP == "" {
		return nil
	}
	if d.cfg.IgnorePrivate && isPrivateOrLoopbackIP(ev.SrcIP) {
		return nil
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	ts := ev.Timestamp.UTC()
	ev.Timestamp = ts

	d.mu.Lock()
	defer d.mu.Unlock()

	sw, ok := d.sources[ev.SrcIP]
	if !ok {
		sw = &sourceWindow{}
		d.sources[ev.SrcIP] = sw
	}

	if ts.After(sw.latest) {
		sw.latest = ts
	}
	cutoff := sw.latest.Add(-d.cfg.Window)
	if ts.Before(cutoff) {
		// Drop events older than the active sliding window.
		return nil
	}

	sw.events = append(sw.events, ev)
	sw.events = pruneEvents(sw.events, cutoff)

	var findings []schema.Finding

	if f, triggered := d.checkVerticalScan(ev, sw.events); triggered {
		findings = append(findings, f)
	}
	if f, triggered := d.checkHorizontalScan(ev, sw.events); triggered {
		findings = append(findings, f)
	}
	if f, triggered := d.checkBurst(ev, sw.events); triggered {
		findings = append(findings, f)
	}

	return findings
}

func (d *Detector) checkVerticalScan(latest Event, events []Event) (schema.Finding, bool) {
	if latest.DstPort <= 0 || latest.DstIP == "" {
		return schema.Finding{}, false
	}

	portsByDst := make(map[string]map[int]struct{})
	for _, e := range events {
		if e.DstPort <= 0 || e.DstIP == "" {
			continue
		}
		set, ok := portsByDst[e.DstIP]
		if !ok {
			set = make(map[int]struct{})
			portsByDst[e.DstIP] = set
		}
		set[e.DstPort] = struct{}{}
	}

	var matchedDst string
	var uniquePorts []int
	for dstIP, portSet := range portsByDst {
		if len(portSet) >= d.cfg.VerticalPortThreshold {
			if len(portSet) > len(uniquePorts) {
				matchedDst = dstIP
				uniquePorts = mapKeysSorted(portSet)
			}
		}
	}

	if matchedDst == "" {
		return schema.Finding{}, false
	}
	if !d.canEmit(latest.SrcIP, "NET-101", latest.Timestamp) {
		return schema.Finding{}, false
	}

	sample := uniquePorts
	if len(sample) > 15 {
		sample = sample[:15]
	}

	return schema.Finding{
		ID:          fmt.Sprintf("net-101-%s-%d", sanitizeIPForID(latest.SrcIP), latest.Timestamp.Unix()),
		RuleID:      "NET-101",
		Module:      moduleDetector,
		Layer:       schema.LayerNetwork,
		Severity:    schema.SeverityHigh,
		Title:       "Vertical port scan detected",
		Description: fmt.Sprintf("Source %s probed %d distinct destination ports on %s within %s.", latest.SrcIP, len(uniquePorts), matchedDst, d.cfg.Window),
		Target:      fmt.Sprintf("ip://%s->%s", latest.SrcIP, matchedDst),
		Evidence: map[string]any{
			"src_ip":       latest.SrcIP,
			"dst_ip":       matchedDst,
			"unique_ports": len(uniquePorts),
			"sample_ports": sample,
			"window":       d.cfg.Window.String(),
		},
		Remediation: fmt.Sprintf("Inspect firewall rules and consider temporarily blocking or rate-limiting source IP %s.", latest.SrcIP),
		MitreD3FEND: "D3-NTA",
		Timestamp:   latest.Timestamp,
	}, true
}

func (d *Detector) checkHorizontalScan(latest Event, events []Event) (schema.Finding, bool) {
	if latest.DstPort <= 0 {
		return schema.Finding{}, false
	}

	hostsByPort := make(map[int]map[string]struct{})
	for _, e := range events {
		if e.DstPort <= 0 || e.DstIP == "" {
			continue
		}
		set, ok := hostsByPort[e.DstPort]
		if !ok {
			set = make(map[string]struct{})
			hostsByPort[e.DstPort] = set
		}
		set[e.DstIP] = struct{}{}
	}

	var matchedPort int
	var uniqueHosts []string
	for port, hostSet := range hostsByPort {
		if len(hostSet) >= d.cfg.HorizontalHostThreshold {
			if len(hostSet) > len(uniqueHosts) {
				matchedPort = port
				uniqueHosts = stringKeysSorted(hostSet)
			}
		}
	}

	if matchedPort == 0 {
		return schema.Finding{}, false
	}
	if !d.canEmit(latest.SrcIP, "NET-102", latest.Timestamp) {
		return schema.Finding{}, false
	}

	sample := uniqueHosts
	if len(sample) > 10 {
		sample = sample[:10]
	}

	return schema.Finding{
		ID:          fmt.Sprintf("net-102-%s-%d", sanitizeIPForID(latest.SrcIP), latest.Timestamp.Unix()),
		RuleID:      "NET-102",
		Module:      moduleDetector,
		Layer:       schema.LayerNetwork,
		Severity:    schema.SeverityHigh,
		Title:       "Horizontal network scan detected",
		Description: fmt.Sprintf("Source %s swept port %d across %d distinct destination hosts within %s.", latest.SrcIP, matchedPort, len(uniqueHosts), d.cfg.Window),
		Target:      fmt.Sprintf("ip://%s->*:%d", latest.SrcIP, matchedPort),
		Evidence: map[string]any{
			"src_ip":       latest.SrcIP,
			"dst_port":     matchedPort,
			"unique_hosts": len(uniqueHosts),
			"sample_hosts": sample,
			"window":       d.cfg.Window.String(),
		},
		Remediation: fmt.Sprintf("Review network ingress logs for %s and enforce perimeter ACLs on port %d.", latest.SrcIP, matchedPort),
		MitreD3FEND: "D3-NTA",
		Timestamp:   latest.Timestamp,
	}, true
}

func (d *Detector) checkBurst(latest Event, events []Event) (schema.Finding, bool) {
	if len(events) < d.cfg.BurstThreshold {
		return schema.Finding{}, false
	}
	if !d.canEmit(latest.SrcIP, "NET-103", latest.Timestamp) {
		return schema.Finding{}, false
	}

	return schema.Finding{
		ID:          fmt.Sprintf("net-103-%s-%d", sanitizeIPForID(latest.SrcIP), latest.Timestamp.Unix()),
		RuleID:      "NET-103",
		Module:      moduleDetector,
		Layer:       schema.LayerNetwork,
		Severity:    schema.SeverityMedium,
		Title:       "Connection burst anomaly detected",
		Description: fmt.Sprintf("Source %s generated %d logged connection attempts within %s (threshold: %d).", latest.SrcIP, len(events), d.cfg.Window, d.cfg.BurstThreshold),
		Target:      fmt.Sprintf("ip://%s", latest.SrcIP),
		Evidence: map[string]any{
			"src_ip":      latest.SrcIP,
			"event_count": len(events),
			"threshold":   d.cfg.BurstThreshold,
			"window":      d.cfg.Window.String(),
		},
		Remediation: fmt.Sprintf("Apply connection rate limiting or fail2ban rules targeting %s if traffic is unexpected.", latest.SrcIP),
		MitreD3FEND: "D3-NTF",
		Timestamp:   latest.Timestamp,
	}, true
}

func (d *Detector) canEmit(srcIP, ruleID string, ts time.Time) bool {
	key := alertKey{srcIP: srcIP, ruleID: ruleID}
	prev, exists := d.lastAlert[key]
	if exists && d.cfg.Cooldown > 0 && ts.Sub(prev) < d.cfg.Cooldown {
		return false
	}
	d.lastAlert[key] = ts
	return true
}

// AnalyzeReader streams log lines from r through the detector and aggregates findings.
func (d *Detector) AnalyzeReader(r io.Reader, format string) ([]schema.Finding, Stats, error) {
	normFmt := strings.ToLower(strings.TrimSpace(format))
	if normFmt == "" {
		normFmt = "auto"
	}
	switch normFmt {
	case "auto", "ufw", "iptables", "jsonl":
	default:
		return nil, Stats{}, fmt.Errorf("unsupported log format %q: expected auto, ufw, iptables, or jsonl", format)
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 512*1024)

	var stats Stats
	findings := make([]schema.Finding, 0)

	for scanner.Scan() {
		stats.LinesRead++
		line := scanner.Text()
		ev, parsed, err := ParseLine(line, normFmt)
		if err != nil {
			stats.ParseErrors++
			continue
		}
		if !parsed {
			stats.LinesSkipped++
			continue
		}
		stats.EventsParsed++
		findings = append(findings, d.Ingest(ev)...)
	}

	if err := scanner.Err(); err != nil {
		return nil, stats, fmt.Errorf("read log stream: %w", err)
	}
	return findings, stats, nil
}

func pruneEvents(events []Event, cutoff time.Time) []Event {
	kept := events[:0]
	for _, e := range events {
		if !e.Timestamp.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	return kept
}

func isPrivateOrLoopbackIP(raw string) bool {
	ip := net.ParseIP(raw)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func mapKeysSorted(m map[int]struct{}) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func stringKeysSorted(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sanitizeIPForID(ip string) string {
	return strings.NewReplacer(":", "_", ".", "-").Replace(ip)
}
