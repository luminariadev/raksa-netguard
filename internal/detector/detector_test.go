package detector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
