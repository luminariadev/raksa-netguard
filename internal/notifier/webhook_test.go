package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luminariadev/raksa-netguard/internal/schema"
)

func sampleFinding() schema.Finding {
	return schema.Finding{
		ID:          "net-101-198-51-100-42-1",
		RuleID:      "NET-101",
		Module:      "scan-detector",
		Layer:       schema.LayerNetwork,
		Severity:    schema.SeverityHigh,
		Title:       "Vertical port scan detected",
		Description: "Source 198.51.100.42 probed 12 distinct ports.",
		Target:      "ip://198.51.100.42->192.0.2.10",
		Remediation: "Block source at perimeter firewall.",
		MitreD3FEND: "D3-NTA",
		Timestamp:   time.Date(2026, 11, 25, 15, 0, 0, 0, time.UTC),
	}
}

func TestWebhookSink_FormatsAndHeaders(t *testing.T) {
	cases := []struct {
		name      string
		format    string
		wantField string
	}{
		{name: "generic json", format: "generic", wantField: `"finding"`},
		{name: "slack text", format: "slack", wantField: `"text"`},
		{name: "discord content", format: "discord", wantField: `"content"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotAuth string
			var gotCustom string
			var gotBody string

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				gotCustom = r.Header.Get("X-Raksa-Env")
				raw, _ := io.ReadAll(r.Body)
				gotBody = string(raw)
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			sink, err := NewWebhookSink(WebhookConfig{
				URL:         srv.URL,
				Format:      tc.format,
				BearerToken: "secret-token",
				Headers:     map[string]string{"X-Raksa-Env": "staging"},
			})
			if err != nil {
				t.Fatalf("NewWebhookSink: %v", err)
			}

			if err := sink.Send(context.Background(), sampleFinding()); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if gotAuth != "Bearer secret-token" || gotCustom != "staging" {
				t.Fatalf("unexpected headers auth=%q custom=%q", gotAuth, gotCustom)
			}
			if !strings.Contains(gotBody, tc.wantField) || !strings.Contains(gotBody, "NET-101") {
				t.Fatalf("unexpected payload %s", gotBody)
			}
			if !json.Valid([]byte(gotBody)) {
				t.Fatalf("payload is not valid JSON: %s", gotBody)
			}
		})
	}
}

func TestWebhookSink_RetriesAndErrors(t *testing.T) {
	t.Run("retries once on 5xx and succeeds", func(t *testing.T) {
		var attempts atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if attempts.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		}))
		defer srv.Close()

		sink, err := NewWebhookSink(WebhookConfig{
			URL:       srv.URL,
			RetryWait: 5 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewWebhookSink: %v", err)
		}
		if err := sink.Send(context.Background(), sampleFinding()); err != nil {
			t.Fatalf("expected retry to succeed, got %v", err)
		}
		if attempts.Load() != 2 {
			t.Fatalf("expected 2 attempts, got %d", attempts.Load())
		}
	})

	t.Run("does not retry 4xx errors", func(t *testing.T) {
		var attempts atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts.Add(1)
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer srv.Close()

		sink, err := NewWebhookSink(WebhookConfig{
			URL:       srv.URL,
			RetryWait: 5 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewWebhookSink: %v", err)
		}
		err = sink.Send(context.Background(), sampleFinding())
		if err == nil || !strings.Contains(err.Error(), "HTTP 400") {
			t.Fatalf("expected HTTP 400 error, got %v", err)
		}
		if attempts.Load() != 1 {
			t.Fatalf("expected 1 attempt for 4xx, got %d", attempts.Load())
		}
	})

	t.Run("enforces client timeout", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(150 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		sink, err := NewWebhookSink(WebhookConfig{
			URL:       srv.URL,
			Timeout:   30 * time.Millisecond,
			RetryWait: 5 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewWebhookSink: %v", err)
		}
		if err := sink.Send(context.Background(), sampleFinding()); err == nil {
			t.Fatal("expected timeout error, got nil")
		}
	})

	t.Run("validates config", func(t *testing.T) {
		if _, err := NewWebhookSink(WebhookConfig{}); err == nil {
			t.Fatal("expected error for empty URL")
		}
		if _, err := NewWebhookSink(WebhookConfig{URL: "https://example.invalid", Format: "teams"}); err == nil {
			t.Fatal("expected error for unsupported webhook format")
		}
	})
}
