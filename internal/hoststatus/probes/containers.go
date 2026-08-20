package probes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Container engines are asked over their unix socket rather than by running
// their CLI.
//
// The CLI was tried first and cannot work here. The node agent's unit is sized
// for a heartbeat — MemoryMax=48M, TasksMax=24, CPUQuota=2% — and a container
// engine is a large Go program that inherits all of it. On a real controller
// both engines died the same way:
//
//	could not list containers (podman: signal: aborted (core dumped);
//	docker: signal: aborted (core dumped))
//
// The alternative was to widen the unit's limits on every OpenStack host so a
// subprocess would fit. Speaking the socket costs no subprocess at all: no
// memory beyond this process, no task against the cgroup's pid limit, and none
// of the ~0.4s a fork costs at 2% CPU. The narrow unit stays narrow.
//
// Both engines serve the Docker-compatible endpoint, so one request shape works
// for both.
var containerSockets = []struct {
	engine string
	path   string
}{
	{"podman", "/run/podman/podman.sock"},
	{"docker", "/var/run/docker.sock"},
}

// containersEndpoint is the Docker-compatible listing. Podman serves it too,
// which is why there is one code path rather than one per engine.
const containersEndpoint = "http://localhost/containers/json?all=1"

// socketTimeout bounds one request. The socket is local, so this is about a
// wedged daemon rather than a slow network.
const socketTimeout = 15 * time.Second

// apiContainer is the part of the listing this probe reads.
type apiContainer struct {
	Names []string `json:"Names"`
	State string   `json:"State"`
	Image string   `json:"Image"`
}

// containerInfo is what one container tells us about the service it runs.
type containerInfo struct {
	State string
	Image string
}

// listViaSocket asks one engine's socket for its containers.
func listViaSocket(ctx context.Context, socket string) (map[string]containerInfo, error) {
	client := &http.Client{
		Timeout: socketTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, containersEndpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Bounded read: an error body from a misbehaving daemon should not be
		// pulled into memory in a process capped at 48M.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var list []apiContainer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&list); err != nil {
		return nil, err
	}
	out := make(map[string]containerInfo, len(list))
	for _, c := range list {
		for _, n := range c.Names {
			// The compat API returns names with a leading slash.
			out[strings.TrimPrefix(n, "/")] = containerInfo{
				State: strings.ToLower(c.State),
				Image: c.Image,
			}
		}
	}
	return out, nil
}

// imageTag is the tag part of an image reference, or empty when there is none.
//
// The last colon is only a tag separator if nothing after it looks like a path.
// The registry in this fleet carries a port — 172.16.0.11:7777/kolla/x:2025.1 —
// so a naive "after the last colon" would read the port as the tag of an
// untagged image.
func imageTag(ref string) string {
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return ""
	}
	if tag := ref[i+1:]; !strings.Contains(tag, "/") {
		return tag
	}
	return ""
}

// versionEndpoint is the Docker-compatible version report. Podman serves it too,
// and its Components carry the OCI runtime — which is the field worth having.
const versionEndpoint = "http://localhost/version"

// apiVersion is the part of the response worth reading.
type apiVersion struct {
	Version    string `json:"Version"`
	Components []struct {
		Name    string `json:"Name"`
		Version string `json:"Version"`
	} `json:"Components"`
}

// engineVersions asks one engine's socket what it and its OCI runtime are.
//
// This exists because a runtime version was the whole cause of a real incident
// and nothing in the fleet recorded it. One host ran crun 1.23.1 while the rest
// ran 1.27; the old one leaked 16,383 mount entries into the host's mount table
// and the agent on it burned a core reading /proc/self/mountinfo for 57 days.
// The two hosts were otherwise identical — same distro family, same Kolla
// containers, same shared-propagation bind mounts. Finding it meant logging into
// both and running rpm -q by hand.
//
// Recorded as capability components, beside nova-compute and libvirt, because it
// is the same kind of fact: a version this deployment is running that somebody
// will eventually need to compare across hosts.
//
// Best effort. A socket that answers the container listing but not this is a
// version we do not learn, not a probe that failed — the listing is what the
// capability is actually built from.
func engineVersions(ctx context.Context, socket string) map[string]string {
	client := &http.Client{
		Timeout: socketTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionEndpoint, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var v apiVersion
	// 256KB: this response is a few hundred bytes and the process is capped at 48M.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&v); err != nil {
		return nil
	}
	out := map[string]string{}
	if v.Version != "" {
		out["engine"] = v.Version
	}
	for _, c := range v.Components {
		// Podman spells it "OCI Runtime (crun)"; Docker reports "runc" as its
		// own component. Key on the role rather than the implementation so the
		// two are comparable across a mixed fleet.
		n := strings.ToLower(c.Name)
		switch {
		case strings.Contains(n, "oci runtime"), n == "runc", n == "crun":
			if c.Version != "" {
				out["oci-runtime"] = c.Version
				// The implementation is worth keeping too: crun and runc are
				// not interchangeable and their version numbers are unrelated.
				out["oci-runtime-name"] = strings.TrimSpace(c.Name)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
