package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/luminariadev/raksa-netguard/internal/baseline"
	"github.com/luminariadev/raksa-netguard/internal/detector"
	"github.com/luminariadev/raksa-netguard/internal/notifier"
	"github.com/luminariadev/raksa-netguard/internal/report"
	"github.com/luminariadev/raksa-netguard/internal/schema"
)

var (
	version   = "0.1.0"
	commit    = "dev"
	buildDate = "unknown"
)

const (
	exitOK        = 0
	exitErr       = 1
	exitThreshold = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printRootUsage(stderr)
		return exitErr
	}

	switch args[0] {
	case "audit":
		return runAudit(args[1:], stdout, stderr)
	case "policy-check":
		return runPolicyCheck(args[1:], stdout, stderr)
	case "analyze":
		return runAnalyze(args[1:], stdout, stderr)
	case "watch":
		return runWatch(args[1:], stdout, stderr)
	case "version", "-v", "--version":
		_, _ = fmt.Fprintf(stdout, "raksa-netguard %s (commit=%s, built=%s)\n", version, commit, buildDate)
		return exitOK
	case "help", "-h", "--help":
		printRootUsage(stdout)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "unknown subcommand %q\n\n", args[0])
		printRootUsage(stderr)
		return exitErr
	}
}

func printRootUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `raksa-netguard - Defensive host open-port auditor and log-based scan detector

Usage:
  raksa-netguard <command> [flags]

Commands:
  audit          Audit local listening sockets against a YAML baseline policy
  policy-check   Validate a YAML baseline policy for permissive or insecure rules
  analyze        Analyze firewall or flow logs for port scans and connection bursts
  watch          Continuously tail a log file and emit alerts or webhook notifications
  version        Print build version metadata
  help           Show this help message

Run "raksa-netguard <command> -h" for command-specific flags.
`)
}

func runAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)

	policyPath := fs.String("policy", "", "Path to YAML baseline policy file (required)")
	outFmt := fs.String("format", "table", "Output format: table, json, sarif")
	failOnRaw := fs.String("fail-on", "", "Exit with code 2 if any finding meets severity (critical, high, medium, low, info)")
	timeout := fs.Duration("timeout", 10*time.Second, "Socket collection timeout")

	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	if strings.TrimSpace(*policyPath) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --policy is required")
		return exitErr
	}

	failOn, err := parseOptionalSeverity(*failOnRaw)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}

	policy, err := baseline.LoadPolicy(*policyPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	listeners, err := baseline.DefaultCollector().Collect(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error collecting local listeners: %v\n", err)
		return exitErr
	}

	now := time.Now().UTC()
	findings := baseline.Audit(listeners, policy, now)
	rep := schema.NewReport(findings, now)

	if err := report.WriteReport(stdout, rep, *outFmt); err != nil {
		_, _ = fmt.Fprintf(stderr, "error writing report: %v\n", err)
		return exitErr
	}
	if rep.HasThresholdBreach(failOn) {
		return exitThreshold
	}
	return exitOK
}

func runPolicyCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("policy-check", flag.ContinueOnError)
	fs.SetOutput(stderr)

	policyPath := fs.String("policy", "", "Path to YAML baseline policy file (required)")
	outFmt := fs.String("format", "table", "Output format: table, json, sarif")
	failOnRaw := fs.String("fail-on", "", "Exit with code 2 if any finding meets severity (critical, high, medium, low, info)")

	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	if strings.TrimSpace(*policyPath) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --policy is required")
		return exitErr
	}

	failOn, err := parseOptionalSeverity(*failOnRaw)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}

	policy, err := baseline.LoadPolicy(*policyPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}

	now := time.Now().UTC()
	findings := baseline.ValidatePolicy(policy, now)
	rep := schema.NewReport(findings, now)

	if err := report.WriteReport(stdout, rep, *outFmt); err != nil {
		_, _ = fmt.Fprintf(stderr, "error writing report: %v\n", err)
		return exitErr
	}
	if rep.HasThresholdBreach(failOn) {
		return exitThreshold
	}
	return exitOK
}

func runAnalyze(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(stderr)

	logPath := fs.String("log", "", "Path to firewall/flow log file, or '-' for stdin (required)")
	logFmt := fs.String("log-format", "auto", "Input log format: auto, ufw, iptables, jsonl")
	outFmt := fs.String("format", "table", "Output format: table, json, sarif")
	failOnRaw := fs.String("fail-on", "", "Exit with code 2 if any finding meets severity (critical, high, medium, low, info)")

	defaults := detector.DefaultConfig()
	window := fs.Duration("window", defaults.Window, "Sliding detection window duration")
	vertThresh := fs.Int("vertical-threshold", defaults.VerticalPortThreshold, "Unique destination ports per target host to trigger NET-101")
	horizThresh := fs.Int("horizontal-threshold", defaults.HorizontalHostThreshold, "Unique destination hosts per port to trigger NET-102")
	burstThresh := fs.Int("burst-threshold", defaults.BurstThreshold, "Connection attempts per source within window to trigger NET-103")
	cooldown := fs.Duration("cooldown", defaults.Cooldown, "Cooldown duration per source and rule")
	ignorePrivate := fs.Bool("ignore-private", defaults.IgnorePrivate, "Ignore RFC1918 private and loopback source IPs")

	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	if strings.TrimSpace(*logPath) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --log is required")
		return exitErr
	}

	failOn, err := parseOptionalSeverity(*failOnRaw)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}

	var reader io.Reader
	if *logPath == "-" {
		reader = os.Stdin
	} else {
		f, openErr := os.Open(*logPath)
		if openErr != nil {
			_, _ = fmt.Fprintf(stderr, "error opening log file: %v\n", openErr)
			return exitErr
		}
		defer f.Close()
		reader = f
	}

	det := detector.New(detector.Config{
		Window:                  *window,
		VerticalPortThreshold:   *vertThresh,
		HorizontalHostThreshold: *horizThresh,
		BurstThreshold:          *burstThresh,
		Cooldown:                *cooldown,
		IgnorePrivate:           *ignorePrivate,
	})

	findings, stats, err := det.AnalyzeReader(reader, *logFmt)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error analyzing logs: %v\n", err)
		return exitErr
	}

	if strings.EqualFold(strings.TrimSpace(*outFmt), "table") || strings.TrimSpace(*outFmt) == "" {
		_, _ = fmt.Fprintf(stderr, "Analyzed %d lines (%d events parsed, %d skipped, %d parse errors)\n",
			stats.LinesRead, stats.EventsParsed, stats.LinesSkipped, stats.ParseErrors)
	}

	rep := schema.NewReport(findings, time.Now().UTC())
	if err := report.WriteReport(stdout, rep, *outFmt); err != nil {
		_, _ = fmt.Fprintf(stderr, "error writing report: %v\n", err)
		return exitErr
	}
	if rep.HasThresholdBreach(failOn) {
		return exitThreshold
	}
	return exitOK
}

func runWatch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(stderr)

	logPath := fs.String("log", "", "Path to firewall/flow log file to tail (required)")
	logFmt := fs.String("log-format", "auto", "Input log format: auto, ufw, iptables, jsonl")
	poll := fs.Duration("poll", 500*time.Millisecond, "Log polling interval")

	defaults := detector.DefaultConfig()
	window := fs.Duration("window", defaults.Window, "Sliding detection window duration")
	vertThresh := fs.Int("vertical-threshold", defaults.VerticalPortThreshold, "Unique destination ports per target host to trigger NET-101")
	horizThresh := fs.Int("horizontal-threshold", defaults.HorizontalHostThreshold, "Unique destination hosts per port to trigger NET-102")
	burstThresh := fs.Int("burst-threshold", defaults.BurstThreshold, "Connection attempts per source within window to trigger NET-103")
	cooldown := fs.Duration("cooldown", defaults.Cooldown, "Cooldown duration per source and rule")
	ignorePrivate := fs.Bool("ignore-private", defaults.IgnorePrivate, "Ignore RFC1918 private and loopback source IPs")

	webhookURL := fs.String("webhook", os.Getenv("RAKSA_WEBHOOK_URL"), "Optional webhook URL for real-time alert delivery (or set RAKSA_WEBHOOK_URL)")
	webhookFmt := fs.String("webhook-format", "generic", "Webhook payload format: generic, slack, discord")
	webhookToken := fs.String("webhook-token", os.Getenv("RAKSA_WEBHOOK_TOKEN"), "Optional bearer token for webhook auth (or set RAKSA_WEBHOOK_TOKEN)")

	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	if strings.TrimSpace(*logPath) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --log is required")
		return exitErr
	}

	var sink *notifier.WebhookSink
	if strings.TrimSpace(*webhookURL) != "" {
		var err error
		sink, err = notifier.NewWebhookSink(notifier.WebhookConfig{
			URL:         *webhookURL,
			Format:      *webhookFmt,
			BearerToken: *webhookToken,
		})
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error configuring webhook: %v\n", err)
			return exitErr
		}
	}

	det := detector.New(detector.Config{
		Window:                  *window,
		VerticalPortThreshold:   *vertThresh,
		HorizontalHostThreshold: *horizThresh,
		BurstThreshold:          *burstThresh,
		Cooldown:                *cooldown,
		IgnorePrivate:           *ignorePrivate,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	_, _ = fmt.Fprintf(stderr, "Watching %s (format=%s, window=%s)... press Ctrl+C to stop.\n", *logPath, *logFmt, window.String())

	err := detector.WatchFile(ctx, *logPath, *logFmt, det, *poll, func(f schema.Finding) {
		raw, marshalErr := json.Marshal(f)
		if marshalErr == nil {
			_, _ = fmt.Fprintln(stdout, string(raw))
		}
		if sink != nil {
			if sendErr := sink.Send(ctx, f); sendErr != nil && ctx.Err() == nil {
				_, _ = fmt.Fprintf(stderr, "webhook delivery error (%s): %v\n", f.RuleID, sendErr)
			}
		}
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "watch error: %v\n", err)
		return exitErr
	}
	return exitOK
}

func parseOptionalSeverity(raw string) (schema.Severity, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	return schema.ParseSeverity(raw)
}
