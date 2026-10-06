package nodeaccess

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	maxResultBytes = 256 << 10
	commandTimeout = 30 * time.Second
)

// Execute runs one validated, read-only operation on the local host. It never
// invokes a shell and never accepts executable paths or arbitrary arguments
// from the request. Installations should grant the separate session-agent only
// the OS permissions these fixed operations need.
func Execute(ctx context.Context, request Request) (Result, error) {
	result := Result{Version: ProtocolVersion, ID: request.ID}
	if err := request.Validate(time.Now()); err != nil {
		return result, err
	}
	deadline := request.Deadline
	if max := time.Now().Add(commandTimeout); deadline.After(max) {
		deadline = max
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	switch request.Operation {
	case OperationHostStatus:
		hostname, err := os.Hostname()
		if err != nil {
			return result, fmt.Errorf("read hostname: %w", err)
		}
		load, err := os.ReadFile("/proc/loadavg")
		if err != nil {
			return result, fmt.Errorf("read load average: %w", err)
		}
		result.Output = fmt.Sprintf("hostname: %s\nloadavg: %s", hostname, strings.TrimSpace(string(load)))
	case OperationContainerList:
		runtime := "/usr/bin/podman"
		args := []string{"ps", "--format", "json"}
		if _, err := os.Stat(runtime); err != nil {
			runtime = "/usr/bin/docker"
			args = []string{"ps", "--format", "{{json .}}"}
		}
		output, err := runBounded(ctx, runtime, args...)
		if err != nil {
			return result, fmt.Errorf("list containers: %w", err)
		}
		result.Output = output
	case OperationServiceStatus:
		output, err := runBounded(ctx, "/usr/bin/systemctl", "show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState,UnitFileState", request.Params["service"])
		if err != nil {
			return result, fmt.Errorf("read service status: %w", err)
		}
		result.Output = output
	case OperationServiceJournal:
		output, err := runBounded(ctx, "/usr/bin/journalctl", "--no-pager", "--output=short-iso", "--unit", request.Params["service"], "--lines", request.Params["lines"])
		if err != nil {
			return result, fmt.Errorf("read service journal: %w", err)
		}
		result.Output = output
	default:
		return result, fmt.Errorf("unsupported operation %q", request.Operation)
	}
	return result, nil
}

func runBounded(ctx context.Context, executable string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	var stdout, stderr cappedBuffer
	stdout.limit = maxResultBytes
	stderr.limit = 8 << 10
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("command timed out or was cancelled: %w", ctx.Err())
		}
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return "", fmt.Errorf("%w: %s", err, message)
		}
		return "", err
	}
	if stdout.overflow {
		return "", fmt.Errorf("command output exceeded %d bytes", maxResultBytes)
	}
	return stdout.String(), nil
}

type cappedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.overflow = true
		return original, nil
	}
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	_, _ = b.Buffer.Write(p)
	return original, nil
}
