package detector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luminariadev/raksa-netguard/internal/schema"
)

func TestParseLine(t *testing.T) {
	t.Run("parses UFW block line in auto mode", func(t *testing.T) {
		line := "2026-11-25T14:20:01Z host kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.42 DST=192.0.2.10 PROTO=TCP SPT=51234 DPT=22"
		ev, ok, err := ParseLine(line, "auto")
		if err != nil || !ok {
			t.Fatalf("expected parsed event, got ok=%v err=%v", ok, err)
		}
		if ev.SrcIP != "198.51.100.42" || ev.DstIP != "192.0.2.10" {
			t.Fatalf("unexpected IPs: %+v", ev)
		}
		if ev.SrcPort != 51234 || ev.DstPort != 22 || ev.Protocol != "TCP" || ev.Action != "BLOCK" {
			t.Fatalf("unexpected event fields: %+v", ev)
		}
	})

	t.Run("parses JSONL line", func(t *testing.T) {
		line := `{"timestamp":"2026-11-25T14:25:05Z","src_ip":"198.51.100.77","dst_ip":"192.0.2.20","src_port":42001,"dst_port":5432,"proto":"tcp","action":"block"}`
		ev, ok, err := ParseLine(line, "jsonl")
		if err != nil || !ok {
			t.Fatalf("expected parsed event, got ok=%v err=%v", ok, err)
		}
		if ev.DstPort != 5432 || ev.Protocol != "TCP" || ev.Action != "BLOCK" {
			t.Fatalf("unexpected JSONL fields: %+v", ev)
		}
	})

	t.Run("skips non-firewall syslog lines without error", func(t *testing.T) {
		line := "Nov 25 14:19:50 edge-fw-01 systemd[1]: Started Daily apt download activities."
		_, ok, err := ParseLine(line, "auto")
		if err != nil || ok {
			t.Fatalf("expected ok=false err=nil, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("rejects malformed JSONL and unknown format", func(t *testing.T) {
		if _, _, err := ParseLine("{bad json", "jsonl"); err == nil {
			t.Fatal("expected error for malformed JSONL")
		}
		if _, _, err := ParseLine("{}", "csv"); err == nil {
			t.Fatal("expected error for unsupported format")
		}
	})
}

func TestDetector_Fixtures(t *testing.T) {
	t.Run("detects vertical and horizontal scans in UFW fixture", func(t *testing.T) {
		f, err := os.Open(filepath.Join("..", "..", "testdata", "ufw_mixed.log"))
		if err != nil {
			t.Fatalf("open ufw fixture: %v", err)
		}
		defer f.Close()

		det := New(DefaultConfig())
		findings, stats, err := det.AnalyzeReader(f, "auto")
		if err != nil {
			t.Fatalf("AnalyzeReader: %v", err)
		}
		if stats.LinesSkipped != 1 || stats.EventsParsed != 23 {
			t.Fatalf("unexpected stats: %+v", stats)
		}

		rules := map[string]bool{}
		for _, finding := range findings {
			rules[finding.RuleID] = true
		}
		if !rules["NET-101"] || !rules["NET-102"] {
			t.Fatalf("expected NET-101 and NET-102 findings, got %+v", findings)
		}
	})

	t.Run("detects vertical scan and connection burst in JSONL fixture", func(t *testing.T) {
		f, err := os.Open(filepath.Join("..", "..", "testdata", "flows_scan.jsonl"))
		if err != nil {
			t.Fatalf("open jsonl fixture: %v", err)
		}
		defer f.Close()

		det := New(DefaultConfig())
		findings, stats, err := det.AnalyzeReader(f, "jsonl")
		if err != nil {
			t.Fatalf("AnalyzeReader: %v", err)
		}
		if stats.EventsParsed != 28 {
			t.Fatalf("expected 28 parsed events, got %+v", stats)
		}

		rules := map[string]bool{}
		for _, finding := range findings {
			rules[finding.RuleID] = true
		}
		if !rules["NET-101"] || !rules["NET-103"] {
			t.Fatalf("expected NET-101 and NET-103 findings, got %+v", findings)
		}
	})
}

func TestDetector_CooldownWindowAndConcurrency(t *testing.T) {
	t.Run("cooldown deduplicates repeated alerts and resets after window", func(t *testing.T) {
		det := New(Config{
			Window:                  10 * time.Second,
			VerticalPortThreshold:   3,
			HorizontalHostThreshold: 100,
			BurstThreshold:          100,
			Cooldown:                30 * time.Second,
			IgnorePrivate:           true,
		})

		base := time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC)
		var total []schema.Finding
		for i := 0; i < 5; i++ {
			total = append(total, det.Ingest(Event{
				Timestamp: base.Add(time.Duration(i) * time.Second),
				SrcIP:     "198.51.100.10",
				DstIP:     "192.0.2.1",
				DstPort:   8000 + i,
				Protocol:  "TCP",
				Action:    "BLOCK",
			})...)
		}
		if len(total) != 1 {
			t.Fatalf("expected exactly 1 finding during cooldown, got %d", len(total))
		}

		// Feed 3 new ports after cooldown expires and outside previous window.
		later := base.Add(40 * time.Second)
		var secondWave []schema.Finding
		for i := 0; i < 3; i++ {
			secondWave = append(secondWave, det.Ingest(Event{
				Timestamp: later.Add(time.Duration(i) * time.Second),
				SrcIP:     "198.51.100.10",
				DstIP:     "192.0.2.1",
				DstPort:   9000 + i,
				Protocol:  "TCP",
				Action:    "BLOCK",
			})...)
		}
		if len(secondWave) != 1 {
			t.Fatalf("expected 1 finding after cooldown elapsed, got %d", len(secondWave))
		}
	})

	t.Run("window expiration prevents false positive across spaced probes", func(t *testing.T) {
		det := New(Config{
			Window:                  10 * time.Second,
			VerticalPortThreshold:   3,
			HorizontalHostThreshold: 100,
			BurstThreshold:          100,
			Cooldown:                time.Minute,
		})

		base := time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC)
		for i := 0; i < 5; i++ {
			findings := det.Ingest(Event{
				Timestamp: base.Add(time.Duration(i*15) * time.Second),
				SrcIP:     "198.51.100.99",
				DstIP:     "192.0.2.5",
				DstPort:   100 + i,
				Protocol:  "TCP",
			})
			if len(findings) != 0 {
				t.Fatalf("expected no findings for spaced probes, got %+v", findings)
			}
		}
	})

	t.Run("safe under concurrent ingestion", func(t *testing.T) {
		det := New(Config{
			Window:                  30 * time.Second,
			VerticalPortThreshold:   5,
			HorizontalHostThreshold: 5,
			BurstThreshold:          10,
			Cooldown:                time.Minute,
		})

		var wg sync.WaitGroup
		base := time.Now().UTC()
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(worker int) {
				defer wg.Done()
				src := fmt.Sprintf("198.51.100.%d", 10+worker)
				for p := 1; p <= 12; p++ {
					_ = det.Ingest(Event{
						Timestamp: base.Add(time.Duration(p) * time.Millisecond),
						SrcIP:     src,
						DstIP:     "192.0.2.50",
						DstPort:   p,
						Protocol:  "TCP",
					})
				}
			}(g)
		}
		wg.Wait()
	})
}

func TestWatchFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "ufw.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatalf("create temp log: %v", err)
	}

	det := New(Config{
		Window:                  time.Minute,
		VerticalPortThreshold:   4,
		HorizontalHostThreshold: 20,
		BurstThreshold:          50,
		Cooldown:                time.Minute,
		IgnorePrivate:           true,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var got []schema.Finding
	doneCh := make(chan error, 1)

	go func() {
		doneCh <- WatchFile(ctx, logPath, "auto", det, 20*time.Millisecond, func(f schema.Finding) {
			mu.Lock()
			got = append(got, f)
			mu.Unlock()
		})
	}()

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open temp log for append: %v", err)
	}
	base := time.Now().UTC()
	for p := 2001; p <= 2004; p++ {
		line := fmt.Sprintf(`{"timestamp":"%s","src_ip":"203.0.113.88","dst_ip":"192.0.2.10","src_port":50000,"dst_port":%d,"proto":"TCP","action":"BLOCK"}`+"\n",
			base.Add(time.Duration(p-2000)*time.Second).Format(time.RFC3339), p)
		if _, err := f.WriteString(line); err != nil {
			t.Fatalf("append line: %v", err)
		}
	}
	_ = f.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := len(got)
		mu.Unlock()
		if count > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	if watchErr := <-doneCh; watchErr != nil {
		t.Fatalf("WatchFile returned unexpected error: %v", watchErr)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].RuleID != "NET-101" {
		t.Fatalf("expected 1 NET-101 finding from WatchFile, got %+v", got)
	}
}

func TestAdversarialResilience(t *testing.T) {
	t.Run("bounds memory under spoofed random-IP log flood while keeping detection active", func(t *testing.T) {
		det := New(Config{
			Window:                  30 * time.Second,
			VerticalPortThreshold:   4,
			HorizontalHostThreshold: 100,
			BurstThreshold:          100,
			Cooldown:                time.Minute,
			MaxTrackedSources:       64,
			MaxEventsPerSource:      32,
		})

		base := time.Date(2026, 11, 25, 16, 0, 0, 0, time.UTC)
		for i := 0; i < 500; i++ {
			ip := fmt.Sprintf("198.18.%d.%d", i/256, i%256)
			_ = det.Ingest(Event{
				Timestamp: base.Add(time.Duration(i) * time.Millisecond),
				SrcIP:     ip,
				DstIP:     "192.0.2.10",
				DstPort:   443,
				Protocol:  "TCP",
			})
		}

		det.mu.Lock()
		tracked := len(det.sources)
		det.mu.Unlock()
		if tracked > 64 {
			t.Fatalf("expected tracked sources <= 64 under IP flood, got %d", tracked)
		}

		// Real vertical scan immediately following flood must still trigger NET-101.
		var realAlerts []schema.Finding
		for p := 1; p <= 4; p++ {
			realAlerts = append(realAlerts, det.Ingest(Event{
				Timestamp: base.Add(time.Duration(500+p) * time.Millisecond),
				SrcIP:     "198.51.100.200",
				DstIP:     "192.0.2.10",
				DstPort:   20 + p,
				Protocol:  "TCP",
			})...)
		}
		if len(realAlerts) != 1 || realAlerts[0].RuleID != "NET-101" {
			t.Fatalf("expected NET-101 detection after IP flood eviction, got %+v", realAlerts)
		}
	})

	t.Run("detects IPv6 and IPv4-mapped IPv6 split evasion scans", func(t *testing.T) {
		det := New(Config{
			Window:                  time.Minute,
			VerticalPortThreshold:   4,
			HorizontalHostThreshold: 50,
			BurstThreshold:          50,
			Cooldown:                time.Minute,
			IgnorePrivate:           true,
		})
		base := time.Date(2026, 11, 25, 16, 5, 0, 0, time.UTC)

		// Pure IPv6 vertical scan
		var v6Alerts []schema.Finding
		for i, port := range []int{22, 80, 443, 8443} {
			v6Alerts = append(v6Alerts, det.Ingest(Event{
				Timestamp: base.Add(time.Duration(i) * time.Second),
				SrcIP:     "2001:db8::42",
				DstIP:     "2001:db8::10",
				DstPort:   port,
				Protocol:  "TCP",
			})...)
		}
		if len(v6Alerts) != 1 || v6Alerts[0].RuleID != "NET-101" {
			t.Fatalf("expected IPv6 NET-101 alert, got %+v", v6Alerts)
		}

		// Split notation evasion: ::ffff:198.51.100.42 + 198.51.100.42
		var mappedAlerts []schema.Finding
		sources := []string{"::ffff:198.51.100.42", "198.51.100.42", "::ffff:198.51.100.42", "198.51.100.42"}
		for i, port := range []int{21, 22, 23, 3389} {
			mappedAlerts = append(mappedAlerts, det.Ingest(Event{
				Timestamp: base.Add(time.Duration(i) * time.Second),
				SrcIP:     sources[i],
				DstIP:     "192.0.2.10",
				DstPort:   port,
				Protocol:  "TCP",
			})...)
		}
		if len(mappedAlerts) != 1 || mappedAlerts[0].RuleID != "NET-101" {
			t.Fatalf("expected canonicalized IPv4-mapped scan detection, got %+v", mappedAlerts)
		}
	})

	t.Run("detects UDP sweep and out-of-order timestamps", func(t *testing.T) {
		det := New(Config{
			Window:                  30 * time.Second,
			VerticalPortThreshold:   4,
			HorizontalHostThreshold: 50,
			BurstThreshold:          50,
			Cooldown:                time.Minute,
		})
		base := time.Date(2026, 11, 25, 16, 10, 0, 0, time.UTC)
		offsets := []int{8, 2, 10, 4}
		ports := []int{53, 123, 161, 500}

		var got []schema.Finding
		for i := range offsets {
			got = append(got, det.Ingest(Event{
				Timestamp: base.Add(time.Duration(offsets[i]) * time.Second),
				SrcIP:     "203.0.113.55",
				DstIP:     "192.0.2.30",
				DstPort:   ports[i],
				Protocol:  "UDP",
				Action:    "BLOCK",
			})...)
		}
		if len(got) != 1 || got[0].RuleID != "NET-101" {
			t.Fatalf("expected UDP out-of-order NET-101 finding, got %+v", got)
		}
	})

	t.Run("handles hostile and malformed log inputs without panics", func(t *testing.T) {
		hostile := strings.Join([]string{
			"",
			"   \x00\x1b[31mgarbage\x1b[0m",
			`{"timestamp":"2026-11-25T16:12:00Z","src_ip":"999.999.1.1","dst_ip":"192.0.2.1","dst_port":80}`,
			`{"timestamp":"not-a-time","src_ip":"198.51.100.1","dst_ip":"192.0.2.1","dst_port":80}`,
			`{"truncated":`,
			"Nov 25 16:12:01 fw kernel: [UFW BLOCK] SRC=invalid DST=192.0.2.1 PROTO=TCP DPT=-5",
			"Nov 25 16:12:02 fw kernel: [UFW BLOCK] SRC=198.51.100.10 DST=192.0.2.1 PROTO=TCP SPT=99999 DPT=443",
		}, "\n")

		det := New(DefaultConfig())
		findings, stats, err := det.AnalyzeReader(strings.NewReader(hostile), "auto")
		if err != nil {
			t.Fatalf("AnalyzeReader unexpected error: %v", err)
		}
		if len(findings) != 0 || stats.EventsParsed != 1 || stats.ParseErrors == 0 {
			t.Fatalf("unexpected hostile log handling: findings=%d stats=%+v", len(findings), stats)
		}
	})

	t.Run("WatchFile recovers from log truncation and rotation", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "rotated.log")
		seed := strings.Repeat("Nov 25 16:15:00 fw systemd[1]: heartbeat normal background line\n", 20)
		if err := os.WriteFile(logPath, []byte(seed), 0o600); err != nil {
			t.Fatalf("seed log file: %v", err)
		}

		det := New(Config{
			Window:                  time.Minute,
			VerticalPortThreshold:   3,
			HorizontalHostThreshold: 50,
			BurstThreshold:          50,
			Cooldown:                time.Minute,
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var mu sync.Mutex
		var got []schema.Finding
		doneCh := make(chan error, 1)

		go func() {
			doneCh <- WatchFile(ctx, logPath, "auto", det, 15*time.Millisecond, func(f schema.Finding) {
				mu.Lock()
				got = append(got, f)
				mu.Unlock()
			})
		}()

		time.Sleep(40 * time.Millisecond)
		// Truncate file to zero bytes to simulate copytruncate log rotation, then write smaller scan lines.
		if err := os.Truncate(logPath, 0); err != nil {
			t.Fatalf("truncate log: %v", err)
		}
		var sb strings.Builder
		base := time.Now().UTC()
		for i, p := range []int{22, 80, 443} {
			fmt.Fprintf(&sb, `{"timestamp":"%s","src_ip":"198.51.100.123","dst_ip":"192.0.2.10","dst_port":%d,"proto":"TCP","action":"BLOCK"}`+"\n",
				base.Add(time.Duration(i)*time.Second).Format(time.RFC3339), p)
		}
		if err := os.WriteFile(logPath, []byte(sb.String()), 0o600); err != nil {
			t.Fatalf("rewrite truncated log: %v", err)
		}

		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			n := len(got)
			mu.Unlock()
			if n > 0 {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}

		cancel()
		if err := <-doneCh; err != nil {
			t.Fatalf("WatchFile error: %v", err)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(got) != 1 || got[0].RuleID != "NET-101" {
			t.Fatalf("expected 1 NET-101 finding after log truncation, got %+v", got)
		}
	})
}

func TestDetector_DistributedScanNET104(t *testing.T) {
	t.Run("detects distributed multi-source scan fixture without single-source false triggers", func(t *testing.T) {
		f, err := os.Open(filepath.Join("..", "..", "testdata", "distributed_scan.jsonl"))
		if err != nil {
			t.Fatalf("open distributed_scan fixture: %v", err)
		}
		defer f.Close()

		det := New(DefaultConfig())
		findings, stats, err := det.AnalyzeReader(f, "jsonl")
		if err != nil {
			t.Fatalf("AnalyzeReader: %v", err)
		}
		if stats.EventsParsed != 12 {
			t.Fatalf("expected 12 parsed events, got %+v", stats)
		}
		if len(findings) != 1 || findings[0].RuleID != "NET-104" {
			t.Fatalf("expected exactly 1 NET-104 finding (cooldown deduplicated), got %+v", findings)
		}
		if findings[0].Target != "host://192.0.2.50" || findings[0].MitreD3FEND != "D3-NTA" {
			t.Fatalf("unexpected NET-104 metadata: %+v", findings[0])
		}
	})

	t.Run("bounds tracked targets under destination IP flood", func(t *testing.T) {
		det := New(Config{
			Window:                     30 * time.Second,
			DistributedSourceThreshold: 8,
			DistributedPortThreshold:   10,
			MaxTrackedTargets:          16,
		})

		base := time.Date(2026, 11, 25, 16, 30, 0, 0, time.UTC)
		for i := 0; i < 60; i++ {
			_ = det.Ingest(Event{
				Timestamp: base.Add(time.Duration(i) * time.Millisecond),
				SrcIP:     "198.51.100.1",
				DstIP:     fmt.Sprintf("192.0.2.%d", i+1),
				DstPort:   443,
				Protocol:  "TCP",
			})
		}

		det.mu.Lock()
		targetCount := len(det.targets)
		det.mu.Unlock()
		if targetCount > 16 {
			t.Fatalf("expected tracked targets <= 16, got %d", targetCount)
		}
	})
}

func TestParsers_NftablesAndWindowsFirewall(t *testing.T) {
	t.Run("parses nftables prefix drop and accept lines", func(t *testing.T) {
		dropLine := "2026-11-25T15:00:01Z fw01 kernel: [900.1] NFT-DROP IN=eth0 SRC=198.51.100.88 DST=192.0.2.10 PROTO=TCP SPT=51000 DPT=22"
		ev, ok, err := ParseLine(dropLine, "nftables")
		if err != nil || !ok {
			t.Fatalf("expected nftables drop line parsed, got ok=%v err=%v", ok, err)
		}
		if ev.Action != "BLOCK" || ev.SrcIP != "198.51.100.88" || ev.DstPort != 22 {
			t.Fatalf("unexpected nftables event: %+v", ev)
		}

		allowLine := "2026-11-25T15:00:02Z fw01 kernel: [901.2] NFT_ALLOW IN=eth0 SRC=198.51.100.89 DST=192.0.2.10 PROTO=UDP SPT=51001 DPT=53"
		ev2, ok2, err2 := ParseLine(allowLine, "auto")
		if err2 != nil || !ok2 || ev2.Action != "ALLOW" || ev2.Protocol != "UDP" {
			t.Fatalf("unexpected nftables allow event: ok=%v err=%v ev=%+v", ok2, err2, ev2)
		}
	})

	t.Run("detects vertical scan in Windows Defender Firewall pfirewall.log", func(t *testing.T) {
		for _, fmtMode := range []string{"auto", "windows-fw", "pfirewall"} {
			f, err := os.Open(filepath.Join("..", "..", "testdata", "windows_pfirewall.log"))
			if err != nil {
				t.Fatalf("open pfirewall fixture: %v", err)
			}
			det := New(DefaultConfig())
			findings, stats, err := det.AnalyzeReader(f, fmtMode)
			_ = f.Close()
			if err != nil {
				t.Fatalf("AnalyzeReader(%s): %v", fmtMode, err)
			}
			if stats.EventsParsed != 14 || stats.ParseErrors != 0 {
				t.Fatalf("format %s unexpected stats: %+v", fmtMode, stats)
			}
			if len(findings) != 1 || findings[0].RuleID != "NET-101" {
				t.Fatalf("format %s expected 1 NET-101 finding, got %+v", fmtMode, findings)
			}
		}
	})
}
