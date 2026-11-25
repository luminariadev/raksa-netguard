package detector

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa-netguard/internal/schema"
)

const moduleDetector = "scan-detector"

// Config controls sliding-window scan detection thresholds and suppression.
type Config struct {
	Window                     time.Duration
	VerticalPortThreshold      int
	HorizontalHostThreshold    int
	BurstThreshold             int
	DistributedSourceThreshold int
	DistributedPortThreshold   int
	Cooldown                   time.Duration
	IgnorePrivate              bool
	MaxTrackedSources          int
	MaxTrackedTargets          int
	MaxEventsPerSource         int
}

// DefaultConfig returns defensive detection defaults suitable for typical edge/API nodes.
func DefaultConfig() Config {
	return Config{
		Window:                     60 * time.Second,
		VerticalPortThreshold:      10,
		HorizontalHostThreshold:    8,
		BurstThreshold:             25,
		DistributedSourceThreshold: 8,
		DistributedPortThreshold:   10,
		Cooldown:                   5 * time.Minute,
		IgnorePrivate:              true,
		MaxTrackedSources:          10000,
		MaxTrackedTargets:          1000,
		MaxEventsPerSource:         1000,
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
	if c.DistributedSourceThreshold <= 0 {
		c.DistributedSourceThreshold = d.DistributedSourceThreshold
	}
	if c.DistributedPortThreshold <= 0 {
		c.DistributedPortThreshold = d.DistributedPortThreshold
	}
	if c.Cooldown < 0 {
		c.Cooldown = d.Cooldown
	}
	if c.MaxTrackedSources <= 0 {
		c.MaxTrackedSources = d.MaxTrackedSources
	}
	if c.MaxTrackedTargets <= 0 {
		c.MaxTrackedTargets = d.MaxTrackedTargets
	}
	if c.MaxEventsPerSource <= 0 {
		c.MaxEventsPerSource = d.MaxEventsPerSource
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

type windowHolder interface {
	latestTime() time.Time
}

// eventRing maintains events ordered by timestamp with amortized O(1) head eviction.
type eventRing struct {
	latest time.Time
	events []Event
	head   int
}

func (r *eventRing) latestTime() time.Time {
	return r.latest
}

func (r *eventRing) activeLen() int {
	return len(r.events) - r.head
}

func (r *eventRing) insertSorted(ev Event) {
	n := len(r.events)
	if n == r.head || !ev.Timestamp.Before(r.events[n-1].Timestamp) {
		r.events = append(r.events, ev)
		return
	}
	r.events = append(r.events, ev)
	i := n
	for i > r.head && ev.Timestamp.Before(r.events[i-1].Timestamp) {
		r.events[i] = r.events[i-1]
		i--
	}
	r.events[i] = ev
}

func (r *eventRing) evict(cutoff time.Time, maxEvents int, onEvict func(Event)) {
	for r.head < len(r.events) && r.events[r.head].Timestamp.Before(cutoff) {
		if onEvict != nil {
			onEvict(r.events[r.head])
		}
		r.head++
	}
	for len(r.events)-r.head > maxEvents {
		if onEvict != nil {
			onEvict(r.events[r.head])
		}
		r.head++
	}
	if r.head > 64 && r.head*2 >= len(r.events) {
		remaining := copy(r.events, r.events[r.head:])
		r.events = r.events[:remaining]
		r.head = 0
	}
}

type sourceWindow struct {
	eventRing
	dstPortCounts  map[string]map[int]int
	portHostCounts map[int]map[string]int
}

func newSourceWindow() *sourceWindow {
	return &sourceWindow{
		dstPortCounts:  make(map[string]map[int]int),
		portHostCounts: make(map[int]map[string]int),
	}
}

func (sw *sourceWindow) add(ev Event, window time.Duration, maxEvents int) bool {
	if ev.Timestamp.After(sw.latest) {
		sw.latest = ev.Timestamp
	}
	cutoff := sw.latest.Add(-window)
	if ev.Timestamp.Before(cutoff) {
		return false
	}

	sw.insertSorted(ev)
	sw.incrementCounts(ev)
	sw.evict(cutoff, maxEvents, sw.decrementCounts)
	return true
}

func (sw *sourceWindow) incrementCounts(ev Event) {
	if ev.DstPort <= 0 || ev.DstIP == "" {
		return
	}
	ports := sw.dstPortCounts[ev.DstIP]
	if ports == nil {
		ports = make(map[int]int)
		sw.dstPortCounts[ev.DstIP] = ports
	}
	ports[ev.DstPort]++

	hosts := sw.portHostCounts[ev.DstPort]
	if hosts == nil {
		hosts = make(map[string]int)
		sw.portHostCounts[ev.DstPort] = hosts
	}
	hosts[ev.DstIP]++
}

func (sw *sourceWindow) decrementCounts(ev Event) {
	if ev.DstPort <= 0 || ev.DstIP == "" {
		return
	}
	if ports := sw.dstPortCounts[ev.DstIP]; ports != nil {
		if count := ports[ev.DstPort]; count <= 1 {
			delete(ports, ev.DstPort)
			if len(ports) == 0 {
				delete(sw.dstPortCounts, ev.DstIP)
			}
		} else {
			ports[ev.DstPort] = count - 1
		}
	}
	if hosts := sw.portHostCounts[ev.DstPort]; hosts != nil {
		if count := hosts[ev.DstIP]; count <= 1 {
			delete(hosts, ev.DstIP)
			if len(hosts) == 0 {
				delete(sw.portHostCounts, ev.DstPort)
			}
		} else {
			hosts[ev.DstIP] = count - 1
		}
	}
}

type targetWindow struct {
	eventRing
	srcCounts  map[string]int
	portCounts map[int]int
}

func newTargetWindow() *targetWindow {
	return &targetWindow{
		srcCounts:  make(map[string]int),
		portCounts: make(map[int]int),
	}
}

func (tw *targetWindow) add(ev Event, window time.Duration, maxEvents int) bool {
	if ev.Timestamp.After(tw.latest) {
		tw.latest = ev.Timestamp
	}
	cutoff := tw.latest.Add(-window)
	if ev.Timestamp.Before(cutoff) {
		return false
	}

	tw.insertSorted(ev)
	if ev.SrcIP != "" {
		tw.srcCounts[ev.SrcIP]++
	}
	if ev.DstPort > 0 {
		tw.portCounts[ev.DstPort]++
	}
	tw.evict(cutoff, maxEvents, tw.decrementCounts)
	return true
}

func (tw *targetWindow) decrementCounts(ev Event) {
	if ev.SrcIP != "" {
		if c := tw.srcCounts[ev.SrcIP]; c <= 1 {
			delete(tw.srcCounts, ev.SrcIP)
		} else {
			tw.srcCounts[ev.SrcIP] = c - 1
		}
	}
	if ev.DstPort > 0 {
		if c := tw.portCounts[ev.DstPort]; c <= 1 {
			delete(tw.portCounts, ev.DstPort)
		} else {
			tw.portCounts[ev.DstPort] = c - 1
		}
	}
}

// Detector tracks per-source and per-target network telemetry over bounded sliding windows.
type Detector struct {
	cfg       Config
	mu        sync.Mutex
	sources   map[string]*sourceWindow
	targets   map[string]*targetWindow
	lastAlert map[alertKey]time.Time
}

// New creates a thread-safe Detector configured with cfg.
func New(cfg Config) *Detector {
	return &Detector{
		cfg:       cfg.withDefaults(),
		sources:   make(map[string]*sourceWindow),
		targets:   make(map[string]*targetWindow),
		lastAlert: make(map[alertKey]time.Time),
	}
}

// Ingest processes a single Event and returns any triggered scan or anomaly findings.
func (d *Detector) Ingest(ev Event) []schema.Finding {
	ev.SrcIP = canonicalIPString(ev.SrcIP)
	ev.DstIP = canonicalIPString(ev.DstIP)
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
		if len(d.sources) >= d.cfg.MaxTrackedSources {
			evictWindowMapLocked(d.sources, d.cfg.MaxTrackedSources, d.cfg.Window, d.cfg.Cooldown, d.lastAlert, ts)
		}
		sw = newSourceWindow()
		d.sources[ev.SrcIP] = sw
	}
	srcActive := sw.add(ev, d.cfg.Window, d.cfg.MaxEventsPerSource)

	var tw *targetWindow
	tgtActive := false
	if ev.DstIP != "" && ev.DstPort > 0 {
		var tok bool
		tw, tok = d.targets[ev.DstIP]
		if !tok {
			if len(d.targets) >= d.cfg.MaxTrackedTargets {
				evictWindowMapLocked(d.targets, d.cfg.MaxTrackedTargets, d.cfg.Window, d.cfg.Cooldown, d.lastAlert, ts)
			}
			tw = newTargetWindow()
			d.targets[ev.DstIP] = tw
		}
		tgtActive = tw.add(ev, d.cfg.Window, d.cfg.MaxEventsPerSource)
	}

	var findings []schema.Finding
	if srcActive {
		if f, triggered := d.checkVerticalScan(ev, sw); triggered {
			findings = append(findings, f)
		}
		if f, triggered := d.checkHorizontalScan(ev, sw); triggered {
			findings = append(findings, f)
		}
		if f, triggered := d.checkBurst(ev, sw); triggered {
			findings = append(findings, f)
		}
	}
	if tgtActive {
		if f, triggered := d.checkDistributedScan(ev, tw); triggered {
			findings = append(findings, f)
		}
	}

	return findings
}

func evictWindowMapLocked[W windowHolder](store map[string]W, maxTracked int, window, cooldown time.Duration, lastAlert map[alertKey]time.Time, now time.Time) {
	for k, w := range store {
		if now.Sub(w.latestTime()) > window {
			delete(store, k)
		}
	}
	if cooldown > 0 {
		for k, prev := range lastAlert {
			if now.Sub(prev) > cooldown {
				delete(lastAlert, k)
			}
		}
	}
	for len(store) >= maxTracked {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, w := range store {
			wt := w.latestTime()
			if first || wt.Before(oldestTime) {
				oldestKey = k
				oldestTime = wt
				first = false
			}
		}
		if !first {
			delete(store, oldestKey)
		} else {
			break
		}
	}
}

func canonicalIPString(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return addr.Unmap().String()
	}
	return trimmed
}

func (d *Detector) checkVerticalScan(latest Event, sw *sourceWindow) (schema.Finding, bool) {
	if latest.DstPort <= 0 || latest.DstIP == "" {
		return schema.Finding{}, false
	}
	portSet := sw.dstPortCounts[latest.DstIP]
	if len(portSet) < d.cfg.VerticalPortThreshold {
		return schema.Finding{}, false
	}
	if !d.canEmit(latest.SrcIP, "NET-101", latest.Timestamp) {
		return schema.Finding{}, false
	}

	uniquePorts := intMapKeysSorted(portSet)
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
		Description: fmt.Sprintf("Source %s probed %d distinct destination ports on %s within %s.", latest.SrcIP, len(uniquePorts), latest.DstIP, d.cfg.Window),
		Target:      fmt.Sprintf("ip://%s->%s", latest.SrcIP, latest.DstIP),
		Evidence: map[string]any{
			"src_ip":       latest.SrcIP,
			"dst_ip":       latest.DstIP,
			"unique_ports": len(uniquePorts),
			"sample_ports": sample,
			"window":       d.cfg.Window.String(),
		},
		Remediation: fmt.Sprintf("Inspect firewall rules and consider temporarily blocking or rate-limiting source IP %s.", latest.SrcIP),
		MitreD3FEND: "D3-NTA",
		Timestamp:   latest.Timestamp,
	}, true
}

func (d *Detector) checkHorizontalScan(latest Event, sw *sourceWindow) (schema.Finding, bool) {
	if latest.DstPort <= 0 {
		return schema.Finding{}, false
	}
	hostSet := sw.portHostCounts[latest.DstPort]
	if len(hostSet) < d.cfg.HorizontalHostThreshold {
		return schema.Finding{}, false
	}
	if !d.canEmit(latest.SrcIP, "NET-102", latest.Timestamp) {
		return schema.Finding{}, false
	}

	uniqueHosts := stringMapKeysSorted(hostSet)
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
		Description: fmt.Sprintf("Source %s swept port %d across %d distinct destination hosts within %s.", latest.SrcIP, latest.DstPort, len(uniqueHosts), d.cfg.Window),
		Target:      fmt.Sprintf("ip://%s->*:%d", latest.SrcIP, latest.DstPort),
		Evidence: map[string]any{
			"src_ip":       latest.SrcIP,
			"dst_port":     latest.DstPort,
			"unique_hosts": len(uniqueHosts),
			"sample_hosts": sample,
			"window":       d.cfg.Window.String(),
		},
		Remediation: fmt.Sprintf("Review network ingress logs for %s and enforce perimeter ACLs on port %d.", latest.SrcIP, latest.DstPort),
		MitreD3FEND: "D3-NTA",
		Timestamp:   latest.Timestamp,
	}, true
}

func (d *Detector) checkBurst(latest Event, sw *sourceWindow) (schema.Finding, bool) {
	count := sw.activeLen()
	if count < d.cfg.BurstThreshold {
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
		Description: fmt.Sprintf("Source %s generated %d logged connection attempts within %s (threshold: %d).", latest.SrcIP, count, d.cfg.Window, d.cfg.BurstThreshold),
		Target:      fmt.Sprintf("ip://%s", latest.SrcIP),
		Evidence: map[string]any{
			"src_ip":      latest.SrcIP,
			"event_count": count,
			"threshold":   d.cfg.BurstThreshold,
			"window":      d.cfg.Window.String(),
		},
		Remediation: fmt.Sprintf("Apply connection rate limiting or fail2ban rules targeting %s if traffic is unexpected.", latest.SrcIP),
		MitreD3FEND: "D3-NTF",
		Timestamp:   latest.Timestamp,
	}, true
}

func (d *Detector) checkDistributedScan(latest Event, tw *targetWindow) (schema.Finding, bool) {
	if latest.DstIP == "" || latest.DstPort <= 0 {
		return schema.Finding{}, false
	}
	if len(tw.srcCounts) < d.cfg.DistributedSourceThreshold || len(tw.portCounts) < d.cfg.DistributedPortThreshold {
		return schema.Finding{}, false
	}
	if !d.canEmit("dst:"+latest.DstIP, "NET-104", latest.Timestamp) {
		return schema.Finding{}, false
	}

	uniqueSources := stringMapKeysSorted(tw.srcCounts)
	sampleSources := uniqueSources
	if len(sampleSources) > 10 {
		sampleSources = sampleSources[:10]
	}
	uniquePorts := intMapKeysSorted(tw.portCounts)
	samplePorts := uniquePorts
	if len(samplePorts) > 15 {
		samplePorts = samplePorts[:15]
	}

	return schema.Finding{
		ID:          fmt.Sprintf("net-104-%s-%d", sanitizeIPForID(latest.DstIP), latest.Timestamp.Unix()),
		RuleID:      "NET-104",
		Module:      moduleDetector,
		Layer:       schema.LayerNetwork,
		Severity:    schema.SeverityHigh,
		Title:       "Distributed multi-source port scan detected",
		Description: fmt.Sprintf("Target %s received probes from %d distinct source IPs across %d distinct ports within %s.", latest.DstIP, len(uniqueSources), len(uniquePorts), d.cfg.Window),
		Target:      fmt.Sprintf("host://%s", latest.DstIP),
		Evidence: map[string]any{
			"dst_ip":         latest.DstIP,
			"unique_sources": len(uniqueSources),
			"unique_ports":   len(uniquePorts),
			"sample_sources": sampleSources,
			"sample_ports":   samplePorts,
			"window":         d.cfg.Window.String(),
		},
		Remediation: fmt.Sprintf("Inspect perimeter firewall logs for %s, correlate probing source ranges, and enforce strict ingress allowlists.", latest.DstIP),
		MitreD3FEND: "D3-NTA",
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
	if !IsSupportedLogFormat(normFmt) {
		return nil, Stats{}, fmt.Errorf("unsupported log format %q: expected auto, ufw, iptables, nftables, windows-fw, or jsonl", format)
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

// IsSupportedLogFormat reports whether format is accepted by ParseLine and AnalyzeReader.
func IsSupportedLogFormat(format string) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "auto", "ufw", "iptables", "nftables", "windows-fw", "pfirewall", "jsonl":
		return true
	default:
		return false
	}
}

func isPrivateOrLoopbackIP(raw string) bool {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()
}

func intMapKeysSorted(m map[int]int) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func stringMapKeysSorted(m map[string]int) []string {
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
