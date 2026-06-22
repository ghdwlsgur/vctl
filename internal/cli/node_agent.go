package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func nodeAgentCmd() *cobra.Command {
	var (
		hostname string
		interval time.Duration
		once     bool
	)
	cmd := &cobra.Command{
		Use:   "node-agent",
		Short: "Report lightweight host runtime status",
		Long: `node-agent reports observed host state to server_status.

It never creates inventory. The host must already exist in the servers table;
otherwise the heartbeat is ignored. Use AppRole credentials and a narrow
database role for low-risk, low-resource status reporting.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			st, err := a.OpenStatusStore(ctx)
			if err != nil {
				return err
			}
			defer st.Close()

			if hostname == "" {
				hostname, _ = os.Hostname()
			}
			if hostname == "" {
				return fmt.Errorf("hostname is required")
			}

			report := func() error {
				status := collectNodeStatus(ctx, hostname)
				ok, err := st.UpsertServerStatus(ctx, status)
				if err != nil {
					return err
				}
				if !ok {
					ui.Warnf(os.Stderr, "status ignored: %s is not registered in inventory", hostname)
					return nil
				}
				ui.Infof(os.Stderr, "reported status for %s", hostname)
				return nil
			}

			if once {
				return report()
			}
			if interval <= 0 {
				interval = 5 * time.Minute
			}
			if err := report(); err != nil {
				ui.Warnf(os.Stderr, "status report failed: %v", err)
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-ticker.C:
					if err := report(); err != nil {
						ui.Warnf(os.Stderr, "status report failed: %v", err)
					}
				}
			}
		},
	}
	cmd.Flags().StringVar(&hostname, "hostname", "", "inventory hostname to report; defaults to os hostname")
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Minute, "heartbeat interval")
	cmd.Flags().BoolVar(&once, "once", false, "report once and exit")
	return cmd
}

func collectNodeStatus(ctx context.Context, hostname string) store.ServerStatus {
	return store.ServerStatus{
		Hostname:         hostname,
		AgentVersion:     Version,
		OS:               runtime.GOOS,
		Kernel:           kernelVersion(),
		UptimeSeconds:    uptimeSeconds(),
		Load1:            load1(),
		MemoryUsedPct:    memoryUsedPct(),
		DiskRootUsedPct:  diskUsedPct("/"),
		SSHDOK:           serviceOK(ctx, "sshd", "ssh"),
		KubeletOK:        serviceOK(ctx, "kubelet"),
		CRIOOK:           serviceOK(ctx, "crio", "cri-o"),
		DockerOK:         serviceOK(ctx, "docker"),
		AuditCollectorOK: serviceOK(ctx, "vctl-collect"),
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
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int64(f)
}

func load1() *float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return nil
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
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
	var total, available float64
	sc := bufio.NewScanner(f)
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

func serviceOK(ctx context.Context, names ...string) *bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	for _, name := range names {
		cctx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
		err := exec.CommandContext(cctx, "systemctl", "is-active", "--quiet", name).Run()
		cancel()
		if err == nil {
			v := true
			return &v
		}
	}
	v := false
	return &v
}
