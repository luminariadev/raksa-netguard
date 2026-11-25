package detector

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func BenchmarkDetectorIngest(b *testing.B) {
	det := New(DefaultConfig())
	base := time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC)

	events := make([]Event, 1024)
	for i := range events {
		events[i] = Event{
			Timestamp: base.Add(time.Duration(i) * time.Millisecond),
			SrcIP:     fmt.Sprintf("198.51.100.%d", (i%200)+1),
			DstIP:     "192.0.2.10",
			SrcPort:   45000 + (i % 1000),
			DstPort:   1000 + (i % 50),
			Protocol:  "TCP",
			Action:    "BLOCK",
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := events[i&1023]
		ev.Timestamp = base.Add(time.Duration(i) * time.Millisecond)
		_ = det.Ingest(ev)
	}
}

func BenchmarkAnalyzeJSONL(b *testing.B) {
	var sb strings.Builder
	base := time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC)
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&sb, `{"timestamp":"%s","src_ip":"198.51.100.%d","dst_ip":"192.0.2.10","src_port":45000,"dst_port":%d,"proto":"TCP","action":"BLOCK"}`+"\n",
			base.Add(time.Duration(i)*time.Millisecond).Format(time.RFC3339Nano),
			(i%100)+1,
			1000+(i%50),
		)
	}
	payload := sb.String()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		det := New(DefaultConfig())
		if _, _, err := det.AnalyzeReader(strings.NewReader(payload), "jsonl"); err != nil {
			b.Fatalf("AnalyzeReader: %v", err)
		}
	}
}

func BenchmarkAnalyzeUFW(b *testing.B) {
	var sb strings.Builder
	base := time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC)
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&sb, "%s fw kernel: [100.0] [UFW BLOCK] IN=eth0 SRC=198.51.100.%d DST=192.0.2.10 PROTO=TCP SPT=51000 DPT=%d\n",
			base.Add(time.Duration(i)*time.Millisecond).Format(time.RFC3339),
			(i%100)+1,
			1000+(i%50),
		)
	}
	payload := sb.String()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		det := New(DefaultConfig())
		if _, _, err := det.AnalyzeReader(strings.NewReader(payload), "ufw"); err != nil {
			b.Fatalf("AnalyzeReader: %v", err)
		}
	}
}
