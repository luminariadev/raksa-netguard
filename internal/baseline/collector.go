package baseline

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// Listener describes a locally bound listening socket observed on the host.
type Listener struct {
	Protocol    string
	BindAddr    string
	Port        int
	PID         string
	ProcessName string
	State       string
}

// Collector gathers active local listening sockets for the host OS.
type Collector interface {
	Collect(ctx context.Context) ([]Listener, error)
}

// DefaultCollector returns the local socket collector for the current operating system.
func DefaultCollector() Collector {
	return osCollector{}
}

type osCollector struct{}

func (osCollector) Collect(ctx context.Context) ([]Listener, error) {
	switch runtime.GOOS {
	case "linux":
		return collectLinuxProcNet()
	case "windows":
		return collectWindowsNetstat(ctx)
	default:
		return nil, fmt.Errorf("unsupported host OS %q for automatic socket collection", runtime.GOOS)
	}
}

func collectLinuxProcNet() ([]Listener, error) {
	sources := []struct {
		path  string
		proto string
	}{
		{path: "/proc/net/tcp", proto: "tcp"},
		{path: "/proc/net/tcp6", proto: "tcp"},
		{path: "/proc/net/udp", proto: "udp"},
		{path: "/proc/net/udp6", proto: "udp"},
	}

	var all []Listener
	var firstErr error
	parsedAny := false

	for _, src := range sources {
		f, err := os.Open(src.path)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		parsedAny = true
		list, parseErr := ParseProcNet(f, src.proto)
		_ = f.Close()
		if parseErr != nil {
			return nil, fmt.Errorf("parse %s: %w", src.path, parseErr)
		}
		all = append(all, list...)
	}

	if !parsedAny && firstErr != nil {
		return nil, fmt.Errorf("read /proc/net tables: %w", firstErr)
	}
	return sortAndDeduplicateListeners(all), nil
}

func collectWindowsNetstat(ctx context.Context) ([]Listener, error) {
	cmd := exec.CommandContext(ctx, "netstat", "-ano")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("run netstat -ano: %w", err)
	}
	return ParseNetstatOutput(bytes.NewReader(out))
}

// ParseProcNet parses Linux /proc/net/{tcp,tcp6,udp,udp6} socket tables.
// In Linux procfs on little-endian architectures, each 32-bit hex word of the
// IPv4/IPv6 address is stored in host byte order, while ports are big-endian.
func ParseProcNet(r io.Reader, proto string) ([]Listener, error) {
	normProto, err := normalizeProtocol(proto)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(r)
	var listeners []Listener
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "sl ") || strings.HasPrefix(line, "sl\t") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		localField := fields[1]
		remoteField := fields[2]
		stateHex := strings.ToUpper(fields[3])

		if normProto == "tcp" && stateHex != "0A" {
			continue
		}
		if normProto == "udp" && stateHex != "07" && stateHex != "0A" {
			continue
		}
		// Unconnected bound UDP sockets keep an all-zero remote port.
		if normProto == "udp" && !strings.HasSuffix(remoteField, ":0000") {
			continue
		}

		ipStr, port, err := parseProcAddrPort(localField)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}

		stateLabel := "LISTENING"
		if normProto == "udp" {
			stateLabel = "BOUND"
		}

		listeners = append(listeners, Listener{
			Protocol: normProto,
			BindAddr: ipStr,
			Port:     port,
			State:    stateLabel,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sortAndDeduplicateListeners(listeners), nil
}

func parseProcAddrPort(token string) (string, int, error) {
	idx := strings.LastIndex(token, ":")
	if idx <= 0 || idx >= len(token)-1 {
		return "", 0, fmt.Errorf("malformed address:port %q", token)
	}

	hexIP := token[:idx]
	hexPort := token[idx+1:]

	portVal, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid hex port %q: %w", hexPort, err)
	}

	raw, err := hex.DecodeString(hexIP)
	if err != nil {
		return "", 0, fmt.Errorf("invalid hex IP %q: %w", hexIP, err)
	}

	switch len(raw) {
	case 4:
		ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
		return ip.String(), int(portVal), nil
	case 16:
		ipBytes := make([]byte, 16)
		for word := 0; word < 4; word++ {
			off := word * 4
			ipBytes[off] = raw[off+3]
			ipBytes[off+1] = raw[off+2]
			ipBytes[off+2] = raw[off+1]
			ipBytes[off+3] = raw[off]
		}
		ip := net.IP(ipBytes)
		return ip.String(), int(portVal), nil
	default:
		return "", 0, fmt.Errorf("unexpected hex IP byte length %d", len(raw))
	}
}

// ParseNetstatOutput parses Windows `netstat -ano` output into local listeners.
func ParseNetstatOutput(r io.Reader) ([]Listener, error) {
	scanner := bufio.NewScanner(r)
	var listeners []Listener

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}

		var state, pid string
		if proto == "tcp" {
			if len(fields) < 5 {
				continue
			}
			state = strings.ToUpper(fields[3])
			if state != "LISTENING" {
				continue
			}
			pid = fields[4]
		} else {
			// Windows netstat omits the State column for UDP sockets.
			state = "BOUND"
			pid = fields[3]
		}

		host, portStr, err := net.SplitHostPort(fields[1])
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			continue
		}

		listeners = append(listeners, Listener{
			Protocol: proto,
			BindAddr: normalizeBindAddr(host),
			Port:     port,
			PID:      pid,
			State:    state,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sortAndDeduplicateListeners(listeners), nil
}

func sortAndDeduplicateListeners(in []Listener) []Listener {
	type dedupeKey struct {
		proto string
		addr  string
		port  int
		pid   string
	}
	seen := make(map[dedupeKey]struct{}, len(in))
	out := make([]Listener, 0, len(in))

	for _, l := range in {
		k := dedupeKey{
			proto: l.Protocol,
			addr:  l.BindAddr,
			port:  l.Port,
			pid:   l.PID,
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, l)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].BindAddr != out[j].BindAddr {
			return out[i].BindAddr < out[j].BindAddr
		}
		return out[i].PID < out[j].PID
	})

	return out
}
