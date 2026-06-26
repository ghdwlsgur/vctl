// Package hoststatus collects lightweight host runtime status from /proc and
// syscalls. It is intentionally observation-only: it never touches inventory.
package hoststatus

import (
	"bufio"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// Collect gathers the current host runtime status for the given inventory
// hostname and agent version.
func Collect(hostname, agentVersion string) store.ServerStatus {
	return store.ServerStatus{
		Hostname:        hostname,
		AgentVersion:    agentVersion,
		OS:              runtime.GOOS,
		Kernel:          kernelVersion(),
		UptimeSeconds:   uptimeSeconds(),
		Load1:           load1(),
		MemoryUsedPct:   memoryUsedPct(),
		DiskRootUsedPct: diskUsedPct("/"),
	}
}

func kernelVersion() string {
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

func uptimeSeconds() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	return parseUptimeSeconds(string(b))
}

// parseFirstFloat parses the first whitespace-separated field as a float.
func parseFirstFloat(s string) (float64, bool) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0, false
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

func parseUptimeSeconds(s string) int64 {
	f, ok := parseFirstFloat(s)
	if !ok {
		return 0
	}
	return int64(f)
}

func load1() *float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	return parseLoad1(string(b))
}

func parseLoad1(s string) *float64 {
	f, ok := parseFirstFloat(s)
	if !ok {
		return nil
	}
	return &f
}

func memoryUsedPct() *float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseMemUsedPct(f)
}

func parseMemUsedPct(r io.Reader) *float64 {
	var total, available float64
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(fields[1], 64)
		switch fields[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			available = v
		}
	}
	if sc.Err() != nil {
		return nil
	}
	if total <= 0 || available < 0 {
		return nil
	}
	used := (total - available) / total * 100
	return &used
}

func diskUsedPct(path string) *float64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil || st.Blocks == 0 {
		return nil
	}
	used := float64(st.Blocks-st.Bavail) / float64(st.Blocks) * 100
	return &used
}
