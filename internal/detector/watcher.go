package detector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/luminariadev/raksa-netguard/internal/schema"
)

// WatchFile continuously tails a firewall or flow log file, handling log rotation
// and truncation while forwarding newly detected findings to onFinding.
func WatchFile(ctx context.Context, path string, format string, det *Detector, pollInterval time.Duration, onFinding func(schema.Finding)) error {
	if det == nil {
		return errors.New("detector must not be nil")
	}
	normFmt := strings.ToLower(strings.TrimSpace(format))
	if normFmt == "" {
		normFmt = "auto"
	}
	if !IsSupportedLogFormat(normFmt) {
		return fmt.Errorf("unsupported log format %q: expected auto, ufw, iptables, nftables, windows-fw, or jsonl", format)
	}
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}

	var offset int64
	var pending []byte
	var lastInfo os.FileInfo

	readAvailable := func() error {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				// Log file might be momentarily absent during logrotate.
				offset = 0
				pending = nil
				lastInfo = nil
				return nil
			}
			return fmt.Errorf("stat watched log %q: %w", path, err)
		}

		// Reset offset if the log file was truncated or replaced by log rotation.
		if (lastInfo != nil && !os.SameFile(lastInfo, info)) || info.Size() < offset {
			offset = 0
			pending = nil
		}
		lastInfo = info
		if info.Size() == offset {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open watched log %q: %w", path, err)
		}
		defer f.Close()

		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return fmt.Errorf("seek watched log %q: %w", path, err)
		}

		chunk, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("read watched log %q: %w", path, err)
		}
		offset += int64(len(chunk))

		data := append(pending, chunk...)
		for {
			idx := bytes.IndexByte(data, '\n')
			if idx < 0 {
				break
			}
			line := string(bytes.TrimRight(data[:idx], "\r"))
			data = data[idx+1:]

			ev, parsed, parseErr := ParseLine(line, normFmt)
			if parseErr != nil || !parsed {
				continue
			}
			for _, finding := range det.Ingest(ev) {
				if onFinding != nil {
					onFinding(finding)
				}
			}
		}
		pending = append(pending[:0], data...)
		return nil
	}

	if err := readAvailable(); err != nil {
		return err
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := readAvailable(); err != nil {
				return err
			}
		}
	}
}
