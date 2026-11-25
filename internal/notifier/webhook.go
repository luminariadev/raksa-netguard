package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luminariadev/raksa-netguard/internal/schema"
)

// WebhookConfig configures HTTP alert delivery for real-time findings.
type WebhookConfig struct {
	URL         string
	Format      string
	BearerToken string
	Headers     map[string]string
	Timeout     time.Duration
	RetryWait   time.Duration
}

// WebhookSink sends Raksa findings to generic, Slack, or Discord webhooks.
type WebhookSink struct {
	cfg    WebhookConfig
	client *http.Client
}

// NewWebhookSink validates cfg and builds a WebhookSink with bounded request timeouts.
func NewWebhookSink(cfg WebhookConfig) (*WebhookSink, error) {
	rawURL := strings.TrimSpace(cfg.URL)
	if rawURL == "" {
		return nil, errors.New("webhook URL must not be empty")
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook URL: %w", err)
	}
	scheme := strings.ToLower(parsedURL.Scheme)
	if (scheme != "http" && scheme != "https") || parsedURL.Host == "" {
		return nil, fmt.Errorf("webhook URL must use http or https with a valid host")
	}
	cfg.URL = parsedURL.String()
	fmtName := strings.ToLower(strings.TrimSpace(cfg.Format))
	if fmtName == "" {
		fmtName = "generic"
	}
	switch fmtName {
	case "generic", "slack", "discord":
	default:
		return nil, fmt.Errorf("unsupported webhook format %q: expected generic, slack, or discord", cfg.Format)
	}
	cfg.Format = fmtName

	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.RetryWait <= 0 {
		cfg.RetryWait = 250 * time.Millisecond
	}

	return &WebhookSink{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
	}, nil
}

// Send delivers a single finding to the configured webhook, retrying once on 5xx responses.
func (s *WebhookSink) Send(ctx context.Context, finding schema.Finding) error {
	payload, err := s.buildPayload(finding)
	if err != nil {
		return err
	}

	const maxAttempts = 2
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		statusCode, reqErr := s.postOnce(ctx, payload)
		if reqErr == nil {
			return nil
		}
		lastErr = reqErr

		if attempt == maxAttempts || (statusCode > 0 && statusCode < 500) || ctx.Err() != nil {
			break
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.cfg.RetryWait):
		}
	}

	return lastErr
}

func (s *WebhookSink) postOnce(ctx context.Context, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "raksa-netguard/1.0")
	if strings.TrimSpace(s.cfg.BearerToken) != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.BearerToken)
	}
	for k, v := range s.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("send webhook request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
}

func (s *WebhookSink) buildPayload(f schema.Finding) ([]byte, error) {
	summary := fmt.Sprintf("[%s] %s (%s) - %s | Target: %s | MITRE: %s",
		strings.ToUpper(string(f.Severity)),
		f.RuleID,
		f.Title,
		f.Description,
		f.Target,
		f.MitreD3FEND,
	)

	switch s.cfg.Format {
	case "slack":
		return json.Marshal(map[string]any{
			"text": summary,
		})
	case "discord":
		return json.Marshal(map[string]any{
			"content": summary,
		})
	default:
		return json.Marshal(map[string]any{
			"schema_version": schema.SchemaVersion,
			"tool":           schema.ToolName,
			"finding":        f,
		})
	}
}
