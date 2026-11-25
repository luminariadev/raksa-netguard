package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/luminariadev/raksa-netguard/internal/baseline"
	"github.com/luminariadev/raksa-netguard/internal/detector"
	"github.com/luminariadev/raksa-netguard/internal/schema"
)

const (
	defaultProtocolVersion = "2024-11-05"
	maxInlineLogBytes      = 2 << 20 // 2 MiB inline log input limit
)

// Server implements a stdio JSON-RPC 2.0 Model Context Protocol (MCP) server
// exposing strictly defensive raksa-netguard tools.
type Server struct {
	version   string
	collector baseline.Collector
}

// NewServer constructs an MCP Server with version metadata and socket collector.
func NewServer(version string, collector baseline.Collector) *Server {
	if strings.TrimSpace(version) == "" {
		version = "0.3.0"
	}
	if collector == nil {
		collector = baseline.DefaultCollector()
	}
	return &Server{
		version:   version,
		collector: collector,
	}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type toolResult struct {
	Content []textContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Serve reads newline-delimited JSON-RPC 2.0 requests from r and writes responses to w.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		resp, shouldReply := s.handleMessage(ctx, line)
		if !shouldReply {
			continue
		}
		if err := writeJSONLine(w, resp); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read mcp input: %w", err)
	}
	return nil
}

func (s *Server) handleMessage(ctx context.Context, raw []byte) (rpcResponse, bool) {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      json.RawMessage("null"),
			Error:   &rpcError{Code: -32700, Message: "parse error: invalid JSON"},
		}, true
	}

	isNotification := len(bytes.TrimSpace(req.ID)) == 0 || string(bytes.TrimSpace(req.ID)) == "null"
	if req.JSONRPC != "2.0" || strings.TrimSpace(req.Method) == "" {
		if isNotification {
			return rpcResponse{}, false
		}
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32600, Message: "invalid request"},
		}, true
	}

	if strings.HasPrefix(req.Method, "notifications/") || isNotification {
		return rpcResponse{}, false
	}

	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &params)
		protoVer := strings.TrimSpace(params.ProtocolVersion)
		if protoVer == "" {
			protoVer = defaultProtocolVersion
		}
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": protoVer,
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
				"serverInfo": map[string]any{
					"name":    schema.ToolName,
					"version": s.version,
				},
			},
		}, true

	case "ping":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{},
		}, true

	case "tools/list":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": s.toolDefinitions(),
			},
		}, true

	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || strings.TrimSpace(params.Name) == "" {
			return rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &rpcError{Code: -32602, Message: "invalid params: expected tool name"},
			}, true
		}
		res := s.callTool(ctx, params.Name, params.Arguments)
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  res,
		}, true

	default:
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)},
		}, true
	}
}

func (s *Server) toolDefinitions() []toolDefinition {
	return []toolDefinition{
		{
			Name:        "netguard_list_rules",
			Description: "List all built-in defensive baseline and scan-detection rules with MITRE D3FEND mappings.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "netguard_check_policy",
			Description: "Validate a YAML baseline policy for unsafe wildcard binds or insecure cleartext protocols.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"policy_path": map[string]any{"type": "string", "description": "Path to a YAML baseline policy file."},
					"policy_yaml": map[string]any{"type": "string", "description": "Inline YAML baseline policy content."},
				},
			},
		},
		{
			Name:        "netguard_audit_host",
			Description: "Audit local host TCP/UDP listening sockets against a YAML baseline policy.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"policy_path": map[string]any{"type": "string", "description": "Path to a YAML baseline policy file."},
					"policy_yaml": map[string]any{"type": "string", "description": "Inline YAML baseline policy content."},
				},
			},
		},
		{
			Name:        "netguard_generate_baseline",
			Description: "Generate a draft YAML baseline policy snapshot from active local listening sockets.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host_role": map[string]any{"type": "string", "description": "Optional host role label (default: server)."},
				},
			},
		},
		{
			Name:        "netguard_analyze_logs",
			Description: "Analyze firewall or flow logs (UFW, iptables, nftables, Windows Firewall, JSONL) for vertical, horizontal, burst, and distributed port scans.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"log_path":             map[string]any{"type": "string", "description": "Path to local firewall or flow log file."},
					"log_content":          map[string]any{"type": "string", "description": "Inline firewall or flow log lines."},
					"log_format":           map[string]any{"type": "string", "description": "Log format: auto, ufw, iptables, nftables, windows-fw, or jsonl."},
					"policy_path":          map[string]any{"type": "string", "description": "Optional YAML policy supplying detector thresholds."},
					"window":               map[string]any{"type": "string", "description": "Sliding window duration (e.g. 60s)."},
					"vertical_threshold":   map[string]any{"type": "integer", "description": "Unique destination ports threshold for NET-101."},
					"horizontal_threshold": map[string]any{"type": "integer", "description": "Unique destination hosts threshold for NET-102."},
					"burst_threshold":      map[string]any{"type": "integer", "description": "Connection burst threshold for NET-103."},
					"distributed_sources":  map[string]any{"type": "integer", "description": "Unique sources threshold for NET-104."},
					"distributed_ports":    map[string]any{"type": "integer", "description": "Unique ports threshold for NET-104."},
				},
			},
		},
	}
}

func (s *Server) callTool(ctx context.Context, name string, rawArgs json.RawMessage) toolResult {
	switch name {
	case "netguard_list_rules":
		return jsonToolResult(map[string]any{"rules": schema.RuleCatalog()})

	case "netguard_check_policy":
		var args struct {
			PolicyPath string `json:"policy_path"`
			PolicyYAML string `json:"policy_yaml"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return errorToolResult(err)
		}
		pol, err := loadPolicyInput(args.PolicyPath, args.PolicyYAML)
		if err != nil {
			return errorToolResult(err)
		}
		now := time.Now().UTC()
		findings := baseline.ValidatePolicy(pol, now)
		return jsonToolResult(schema.NewReport(findings, now))

	case "netguard_audit_host":
		var args struct {
			PolicyPath string `json:"policy_path"`
			PolicyYAML string `json:"policy_yaml"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return errorToolResult(err)
		}
		pol, err := loadPolicyInput(args.PolicyPath, args.PolicyYAML)
		if err != nil {
			return errorToolResult(err)
		}
		auditCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		listeners, err := s.collector.Collect(auditCtx)
		if err != nil {
			return errorToolResult(fmt.Errorf("collect local sockets: %w", err))
		}
		now := time.Now().UTC()
		findings := baseline.Audit(listeners, pol, now)
		return jsonToolResult(schema.NewReport(findings, now))

	case "netguard_generate_baseline":
		var args struct {
			HostRole string `json:"host_role"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return errorToolResult(err)
		}
		collectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		listeners, err := s.collector.Collect(collectCtx)
		if err != nil {
			return errorToolResult(fmt.Errorf("collect local sockets: %w", err))
		}
		pol, notes := baseline.GeneratePolicy(listeners, args.HostRole)
		rawYAML, err := baseline.MarshalPolicyYAML(pol)
		if err != nil {
			return errorToolResult(err)
		}
		return jsonToolResult(map[string]any{
			"host_role":    pol.HostRole,
			"review_notes": notes,
			"policy_yaml":  string(rawYAML),
		})

	case "netguard_analyze_logs":
		return s.runAnalyzeLogsTool(rawArgs)

	default:
		return errorToolResult(fmt.Errorf("unknown tool %q", name))
	}
}

func (s *Server) runAnalyzeLogsTool(rawArgs json.RawMessage) toolResult {
	var args struct {
		LogPath              string `json:"log_path"`
		LogContent           string `json:"log_content"`
		LogFormat            string `json:"log_format"`
		PolicyPath           string `json:"policy_path"`
		Window               string `json:"window"`
		VerticalThreshold    int    `json:"vertical_threshold"`
		HorizontalThreshold  int    `json:"horizontal_threshold"`
		BurstThreshold       int    `json:"burst_threshold"`
		DistributedSources   int    `json:"distributed_sources"`
		DistributedPorts     int    `json:"distributed_ports"`
	}
	if err := decodeArgs(rawArgs, &args); err != nil {
		return errorToolResult(err)
	}

	cfg := detector.DefaultConfig()
	if strings.TrimSpace(args.PolicyPath) != "" {
		pol, err := baseline.LoadPolicy(args.PolicyPath)
		if err != nil {
			return errorToolResult(err)
		}
		if pol.Detector != nil {
			if strings.TrimSpace(pol.Detector.Window) != "" {
				d, err := time.ParseDuration(pol.Detector.Window)
				if err != nil {
					return errorToolResult(fmt.Errorf("invalid policy detector.window: %w", err))
				}
				cfg.Window = d
			}
			if pol.Detector.VerticalPortThreshold > 0 {
				cfg.VerticalPortThreshold = pol.Detector.VerticalPortThreshold
			}
			if pol.Detector.HorizontalHostThreshold > 0 {
				cfg.HorizontalHostThreshold = pol.Detector.HorizontalHostThreshold
			}
			if pol.Detector.BurstThreshold > 0 {
				cfg.BurstThreshold = pol.Detector.BurstThreshold
			}
			if pol.Detector.DistributedSourceThreshold > 0 {
				cfg.DistributedSourceThreshold = pol.Detector.DistributedSourceThreshold
			}
			if pol.Detector.DistributedPortThreshold > 0 {
				cfg.DistributedPortThreshold = pol.Detector.DistributedPortThreshold
			}
			if strings.TrimSpace(pol.Detector.Cooldown) != "" {
				d, err := time.ParseDuration(pol.Detector.Cooldown)
				if err != nil {
					return errorToolResult(fmt.Errorf("invalid policy detector.cooldown: %w", err))
				}
				cfg.Cooldown = d
			}
			if pol.Detector.IgnorePrivate != nil {
				cfg.IgnorePrivate = *pol.Detector.IgnorePrivate
			}
		}
	}

	if strings.TrimSpace(args.Window) != "" {
		d, err := time.ParseDuration(args.Window)
		if err != nil {
			return errorToolResult(fmt.Errorf("invalid window %q: %w", args.Window, err))
		}
		cfg.Window = d
	}
	if args.VerticalThreshold > 0 {
		cfg.VerticalPortThreshold = args.VerticalThreshold
	}
	if args.HorizontalThreshold > 0 {
		cfg.HorizontalHostThreshold = args.HorizontalThreshold
	}
	if args.BurstThreshold > 0 {
		cfg.BurstThreshold = args.BurstThreshold
	}
	if args.DistributedSources > 0 {
		cfg.DistributedSourceThreshold = args.DistributedSources
	}
	if args.DistributedPorts > 0 {
		cfg.DistributedPortThreshold = args.DistributedPorts
	}

	var reader io.Reader
	switch {
	case strings.TrimSpace(args.LogPath) != "":
		f, err := os.Open(args.LogPath)
		if err != nil {
			return errorToolResult(fmt.Errorf("open log_path %q: %w", args.LogPath, err))
		}
		defer f.Close()
		reader = f
	case strings.TrimSpace(args.LogContent) != "":
		if len(args.LogContent) > maxInlineLogBytes {
			return errorToolResult(fmt.Errorf("log_content exceeds maximum inline size of %d bytes", maxInlineLogBytes))
		}
		reader = strings.NewReader(args.LogContent)
	default:
		return errorToolResult(errors.New("either log_path or log_content is required"))
	}

	format := strings.TrimSpace(args.LogFormat)
	if format == "" {
		format = "auto"
	}

	det := detector.New(cfg)
	findings, stats, err := det.AnalyzeReader(reader, format)
	if err != nil {
		return errorToolResult(err)
	}

	return jsonToolResult(map[string]any{
		"stats":  stats,
		"report": schema.NewReport(findings, time.Now().UTC()),
	})
}

func decodeArgs(raw json.RawMessage, dst any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	if err := json.Unmarshal(trimmed, dst); err != nil {
		return fmt.Errorf("invalid tool arguments: %w", err)
	}
	return nil
}

func loadPolicyInput(path, inlineYAML string) (*baseline.Policy, error) {
	if strings.TrimSpace(path) != "" {
		return baseline.LoadPolicy(path)
	}
	if strings.TrimSpace(inlineYAML) != "" {
		return baseline.ParsePolicyYAML([]byte(inlineYAML))
	}
	return nil, errors.New("either policy_path or policy_yaml is required")
}

func jsonToolResult(payload any) toolResult {
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return errorToolResult(err)
	}
	return toolResult{
		Content: []textContent{{Type: "text", Text: string(encoded)}},
	}
}

func errorToolResult(err error) toolResult {
	return toolResult{
		Content: []textContent{{Type: "text", Text: err.Error()}},
		IsError: true,
	}
}

func writeJSONLine(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}
