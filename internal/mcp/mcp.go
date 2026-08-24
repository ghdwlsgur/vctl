// Package mcp exposes the read-only inventory over the Model Context Protocol
// (stdio) so an AI agent like Claude Code can query the fleet. It speaks
// JSON-RPC 2.0 over newline-delimited stdin/stdout (the MCP stdio transport)
// with no extra dependency. Tools run as the current vctl identity, so Vault
// policies and app-layer RBAC still apply.
//
// This lived in internal/cli, where 17 of its 450 lines were cobra wiring and
// the rest were a protocol server — and being there let it grow private
// wiring: it took the CLI's dependency seam as a parameter and then built its
// app around it, so the fake app every other command honours never reached
// these tools. The seams it actually needs are now stated in Deps, supplied
// by the one cobra command left behind.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/authz"
	"github.com/ghdwlsgur/vctl/internal/store"
)

const protocolVersion = "2024-11-05"

// Deps is what the server borrows from the CLI: seams that already exist
// there, passed rather than imported so the two surfaces cannot cycle and the
// tools keep matching their command-line counterparts.
type Deps struct {
	// Version is what serverInfo reports.
	Version string

	// NewApp builds the app a tool call runs as. The CLI pins its auth
	// non-interactive: a login prompt would corrupt the stdio channel.
	NewApp func() (*app.App, error)

	// Connector executes over SSH with the same wiring `vctl ssh` uses —
	// Vault-signed certificate, audit recording, the works.
	Connector func(*app.App) *access.Connector

	// HostStatus renders a host's liveness the way `vctl list` does, color
	// already stripped: MCP output is JSON, not a terminal.
	HostStatus func(store.ServerWithStatus) string
}

// Serve runs the MCP server over in/out until EOF.
func Serve(ctx context.Context, in io.Reader, out io.Writer, deps Deps) error {
	s := &server{deps: deps}
	// A streaming decoder reads one JSON value per call regardless of size, so a
	// large frame can't trip a line-length cap (a bufio.Scanner would terminate
	// the session on a token over its max). Whitespace/newlines between frames
	// are skipped by the decoder.
	dec := json.NewDecoder(in)
	enc := json.NewEncoder(out)
	for {
		var req request
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		resp, respond := s.dispatch(ctx, &req)
		if !respond {
			continue // notification: no reply
		}
		if err := enc.Encode(resp); err != nil { // Encode appends '\n'
			return err
		}
	}
}

type server struct {
	deps Deps
}

// ---- JSON-RPC 2.0 plumbing (MCP stdio transport: one JSON object per line) ----

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *server) dispatch(ctx context.Context, req *request) (response, bool) {
	notification := len(req.ID) == 0
	resp := response{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "vctl", "version": s.deps.Version},
		}
	case "tools/list":
		resp.Result = map[string]any{"tools": tools()}
	case "tools/call":
		if notification {
			return resp, false // a request, not a notification — don't run a side-effecting tool whose result would be discarded
		}
		resp.Result = s.callTool(ctx, req.Params)
	case "ping":
		resp.Result = map[string]any{}
	default:
		if notification {
			return resp, false
		}
		resp.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
	return resp, !notification
}

// ---- tool catalog ----

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func tools() []tool {
	return []tool{
		{
			Name:        "vctl_list",
			Description: "List the central server inventory: hostname, primary IP and extra IPs, datacenter, ssh user, jump host, and liveness/agent status. Optionally filter by datacenter.",
			InputSchema: obj(map[string]any{
				"dc": map[string]any{"type": "string", "description": "exact datacenter label to filter by (e.g. seoul-onprem, incheon-vm, openstack.native-ai.local)"},
			}),
		},
		{
			Name:        "vctl_resolve",
			Description: "Resolve a server by hostname (fuzzy substring) or by IP address (primary, operator-set extra IP, or agent-observed IP) to its inventory record. Returns a single match or candidate list.",
			InputSchema: obj(map[string]any{
				"query": map[string]any{"type": "string", "description": "hostname substring or an IP address"},
			}, "query"),
		},
		{
			Name:        "vctl_whoami",
			Description: "Show the current vctl/Vault identity, token policies, whether it is an admin, and the app-RBAC commands it is allowed to run.",
			InputSchema: obj(map[string]any{}),
		},
		{
			Name:        "vctl_access_log",
			Description: "Recent SSH access records (who connected to which host, when, success/failure). Requires audit-read access (vctl-auditors or admin); otherwise returns a permission error.",
			InputSchema: obj(map[string]any{
				"limit": map[string]any{"type": "integer", "description": "max records (default 20)"},
				"host":  map[string]any{"type": "string", "description": "filter by hostname"},
				"user":  map[string]any{"type": "string", "description": "filter by Vault user"},
			}),
		},
		{
			Name:        "vctl_ssh_exec",
			Description: "Run a shell command on an inventory host over SSH (non-interactive) and return stdout, stderr, and exit code. Resolves the host like vctl ssh (fuzzy hostname or IP, plus jump chain) and authenticates with a Vault-signed certificate. Requires an ssh-capable identity (vctl-ssh-users or admin) AND app-RBAC 'ssh'; the shared read-only AppRole cannot ssh, and an expired session errors instead of prompting.",
			InputSchema: obj(map[string]any{
				"host":            map[string]any{"type": "string", "description": "hostname (fuzzy/exact) or IP of the target"},
				"command":         map[string]any{"type": "string", "description": "shell command to run on the host"},
				"timeout_seconds": map[string]any{"type": "integer", "description": "max seconds for the command (default 60, max 600)"},
			}, "host", "command"),
		},
	}
}

func (s *server) callTool(ctx context.Context, params json.RawMessage) map[string]any {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	_ = json.Unmarshal(params, &p)
	text, err := s.runTool(ctx, p.Name, p.Arguments)
	if err != nil {
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": "error: " + err.Error()}},
			"isError": true,
		}
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}

func (s *server) runTool(ctx context.Context, name string, args map[string]any) (string, error) {
	switch name {
	case "vctl_list":
		return s.toolList(ctx, argString(args, "dc"))
	case "vctl_resolve":
		return s.toolResolve(ctx, argString(args, "query"))
	case "vctl_whoami":
		return s.toolWhoami(ctx)
	case "vctl_access_log":
		return s.toolAccessLog(ctx, argInt(args, "limit", 20), argString(args, "host"), argString(args, "user"))
	case "vctl_ssh_exec":
		return s.toolSSHExec(ctx, argString(args, "host"), argString(args, "command"), argInt(args, "timeout_seconds", 60))
	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
}

// toolSSHExec runs a command on a host over SSH, enforcing the same two-layer
// gate as `vctl ssh`: the Vault SSH policy (cert signing) plus app-layer RBAC.
// It runs as the current identity — the read-only AppRole cannot sign certs, so
// an ssh-capable OIDC session (vctl-ssh-users / admin) must be active.
func (s *server) toolSSHExec(ctx context.Context, host, command string, timeout int) (string, error) {
	if strings.TrimSpace(host) == "" || strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("host and command are required")
	}
	if timeout <= 0 {
		timeout = 60
	}
	if timeout > 600 {
		timeout = 600 // clamp to the documented max rather than resetting to default
	}
	var out map[string]any
	err := s.withStore(ctx, app.PurposeInventoryRead, func(a *app.App, st *store.Store) error {
		// app-RBAC ssh gate (Layer 2) — the same Check the CLI gate runs, with
		// the class read from the catalog, so the two cannot drift; Vault cert
		// signing is the Layer-1 gate enforced when the connector signs below.
		// Check fails closed on a Vault policy-lookup error and reports an
		// unmigrated RBAC schema as such, where a hand-rolled mirror of this
		// decision used to misreport it as a missing grant.
		sshClass, _ := authz.ClassOf("ssh")
		if err := authorizer(a, st).Check(ctx, authz.Command{Name: "ssh", Class: sshClass}); err != nil {
			return err
		}

		target, err := access.ResolveServer(ctx, st, host)
		if err != nil {
			return err
		}
		tgt, err := access.BuildTarget(ctx, st, target, a.Cfg.SSHDirectFirst)
		if err != nil {
			return err
		}

		// HostKeyAcceptNew: a non-interactive agent can't confirm a host key, so
		// record an unknown one on first use. Execute bounds signing+dial+run by
		// the per-command timeout and always records the attempt to the audit log.
		res, runErr := s.deps.Connector(a).Execute(ctx,
			access.Request{Target: tgt, HostKey: access.HostKeyAcceptNew},
			command, time.Duration(timeout)*time.Second)

		// Return structured output in-band, including partial stdout/stderr on a
		// timeout and the error itself, so the agent can diagnose rather than lose it.
		out = map[string]any{"host": res.Host, "addr": res.Addr, "stdout": res.Stdout, "stderr": res.Stderr}
		if runErr != nil {
			out["error"] = runErr.Error()
		} else {
			out["exit_code"] = res.ExitCode
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return toJSON(out)
}

// ---- tool handlers ----

type serverRow struct {
	Hostname string   `json:"hostname"`
	IP       string   `json:"ip"`
	ExtraIPs []string `json:"extra_ips,omitempty"`
	DC       string   `json:"dc"`
	User     string   `json:"user"`
	Jump     string   `json:"jump,omitempty"`
	Status   string   `json:"status"`
	Agent    string   `json:"agent_version,omitempty"`
}

func (s *server) toRow(w store.ServerWithStatus) serverRow {
	m := serverRow{
		Hostname: w.Hostname, IP: w.IP, ExtraIPs: w.ExtraIPs,
		DC: w.DC, User: w.User, Jump: w.JumpVia,
		Status: s.deps.HostStatus(w),
	}
	if w.Status != nil {
		m.Agent = w.Status.AgentVersion
	}
	return m
}

func (s *server) toolList(ctx context.Context, dc string) (string, error) {
	var items []serverRow
	err := s.withStore(ctx, app.PurposeInventoryRead, func(_ *app.App, st *store.Store) error {
		rows, err := st.ListWithStatus(ctx, dc)
		if err != nil {
			return err
		}
		items = make([]serverRow, len(rows))
		for i, w := range rows {
			items[i] = s.toRow(w)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return toJSON(map[string]any{"count": len(items), "servers": items})
}

func (s *server) toolResolve(ctx context.Context, query string) (string, error) {
	if strings.TrimSpace(query) == "" {
		return "", fmt.Errorf("query is required")
	}
	var out any
	err := s.withStore(ctx, app.PurposeInventoryRead, func(_ *app.App, st *store.Store) error {
		sv, cands, err := st.Resolve(ctx, query)
		if err != nil {
			return err
		}
		switch {
		case sv != nil:
			out = map[string]any{"match": s.toRow(store.ServerWithStatus{Server: *sv})}
		case len(cands) == 0:
			out = map[string]any{"match": nil, "candidates": []any{}}
		default:
			cs := make([]serverRow, len(cands))
			for i, c := range cands {
				cs[i] = s.toRow(store.ServerWithStatus{Server: c})
			}
			out = map[string]any{"match": nil, "candidates": cs}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return toJSON(out)
}

func (s *server) toolWhoami(ctx context.Context) (string, error) {
	var out map[string]any
	err := s.withStore(ctx, app.PurposeInventoryRead, func(a *app.App, st *store.Store) error {
		az, err := authorizer(a, st).Snapshot(ctx)
		if err != nil {
			return err
		}
		out = map[string]any{"identity": az.Identity, "policies": az.Policies, "admin": az.Admin}
		if az.Admin {
			out["rbac_commands"] = []string{"*"}
		} else {
			out["rbac_commands"] = slices.Sorted(maps.Keys(az.Commands))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return toJSON(out)
}

type accessRow struct {
	User       string `json:"user"`
	Host       string `json:"host"`
	OK         bool   `json:"ok"`
	SignedAt   string `json:"signed_at"`
	SourceIP   string `json:"source_ip,omitempty"`
	ClientUser string `json:"client_user,omitempty"`
	Error      string `json:"error,omitempty"`
}

func (s *server) toolAccessLog(ctx context.Context, limit int, host, user string) (string, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	var items []accessRow
	err := s.withStore(ctx, app.PurposeAuditRead, func(_ *app.App, st *store.Store) error {
		entries, err := st.AccessLog(ctx, limit, host, user, "")
		if err != nil {
			return err
		}
		items = make([]accessRow, len(entries))
		for i, e := range entries {
			items[i] = accessRow{
				User: e.VaultUser, Host: e.Hostname, OK: e.OK,
				SignedAt: e.SignedAt.Format(time.RFC3339), SourceIP: e.SourceIP,
				ClientUser: e.ClientUser, Error: e.Error,
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return toJSON(map[string]any{"count": len(items), "access_log": items})
}

// ---- helpers ----

// withStore opens the store for one tool call under the named purpose and
// closes it on every path. The purpose is stated at the call site rather than
// through an rw flag that every caller set to false — a knob that reads as a
// write path this read-only server does not have.
func (s *server) withStore(ctx context.Context, p app.Purpose, fn func(*app.App, *store.Store) error) error {
	a, err := s.deps.NewApp()
	if err != nil {
		return err
	}
	st, err := a.OpenStore(ctx, p)
	if err != nil {
		return err
	}
	defer st.Close()
	return fn(a, st)
}

// authorizer wires an authz.Authorizer over the store a tool call already
// holds, so a check reuses its open connection instead of opening another.
func authorizer(a *app.App, st *store.Store) *authz.Authorizer {
	return authz.NewWithGrants(a.Vault, st)
}

func toJSON(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func argString(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func argInt(m map[string]any, k string, def int) int {
	if v, ok := m[k].(float64); ok {
		return int(v)
	}
	return def
}
