// Package hoststatus collects lightweight host runtime status from /proc and
// syscalls. It is intentionally observation-only: it never touches inventory.
package hoststatus

import (
	"bufio"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

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
		ObservedIPs:     localIPv4s(),
	}
}

// localIPv4s returns the host's non-loopback, non-link-local IPv4 addresses
// across all interfaces, so a multi-homed host (extra NICs, floating VIPs) is
// reachable via `vctl ssh --server <ip>` on any of them.
func localIPv4s() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var ips []string
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		v4 := ip.To4()
		if v4 == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		ips = append(ips, v4.String())
	}
	return ips
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
