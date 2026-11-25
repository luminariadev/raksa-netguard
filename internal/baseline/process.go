package baseline

import (
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcessMeta holds a resolved process identifier and executable/command name.
type ProcessMeta struct {
	PID  string
	Name string
}

// EnrichLinuxProcesses best-effort resolves PID and process name for Linux socket
// listeners by scanning /proc/<pid>/fd socket symlinks and /proc/<pid>/comm.
func EnrichLinuxProcesses(procRoot string, listeners []Listener) {
	if len(listeners) == 0 {
		return
	}

	needed := make(map[string]struct{})
	for _, l := range listeners {
		if l.Inode != "" && l.Inode != "0" {
			needed[l.Inode] = struct{}{}
		}
	}
	if len(needed) == 0 {
		return
	}

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return
	}

	byInode := make(map[string]ProcessMeta, len(needed))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		fdDir := filepath.Join(procRoot, pid, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			// Unprivileged users cannot read fd directories for processes owned by other UIDs.
			continue
		}

		var procName string
		nameLoaded := false
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := parseSocketInodeLink(target)
			if !ok {
				continue
			}
			if _, wanted := needed[inode]; !wanted {
				continue
			}

			if !nameLoaded {
				procName = readProcComm(filepath.Join(procRoot, pid, "comm"))
				nameLoaded = true
			}
			byInode[inode] = ProcessMeta{
				PID:  pid,
				Name: procName,
			}
		}

		if len(byInode) == len(needed) {
			break
		}
	}

	applyProcessByInode(listeners, byInode)
}

func readProcComm(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func parseSocketInodeLink(target string) (string, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return "", false
	}
	inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	if inode == "" || inode == "0" {
		return "", false
	}
	return inode, true
}

func applyProcessByInode(listeners []Listener, byInode map[string]ProcessMeta) {
	for i := range listeners {
		if listeners[i].Inode == "" {
			continue
		}
		if meta, ok := byInode[listeners[i].Inode]; ok {
			if listeners[i].PID == "" && meta.PID != "" {
				listeners[i].PID = meta.PID
			}
			if listeners[i].ProcessName == "" && meta.Name != "" {
				listeners[i].ProcessName = meta.Name
			}
		}
	}
}

func enrichWindowsProcesses(ctx context.Context, listeners []Listener) {
	if len(listeners) == 0 {
		return
	}
	cmd := exec.CommandContext(ctx, "tasklist", "/FO", "CSV", "/NH")
	out, err := cmd.Output()
	if err != nil {
		return
	}
	byPID := ParseTasklistCSV(bytes.NewReader(out))
	applyProcessByPID(listeners, byPID)
}

// ParseTasklistCSV parses `tasklist /FO CSV /NH` output into a PID -> ImageName map.
func ParseTasklistCSV(r io.Reader) map[string]string {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1

	result := make(map[string]string)
	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(rec) < 2 {
			continue
		}
		name := strings.TrimSpace(rec[0])
		pid := strings.TrimSpace(rec[1])
		if name == "" || pid == "" {
			continue
		}
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		result[pid] = name
	}
	return result
}

func applyProcessByPID(listeners []Listener, byPID map[string]string) {
	for i := range listeners {
		if listeners[i].PID == "" || listeners[i].ProcessName != "" {
			continue
		}
		if name, ok := byPID[listeners[i].PID]; ok {
			listeners[i].ProcessName = name
		}
	}
}
