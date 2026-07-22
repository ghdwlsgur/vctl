package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// mcp exposes the read-only inventory over the Model Context Protocol (stdio)
// so an AI agent like Claude Code can query the fleet. It speaks JSON-RPC 2.0
// over newline-delimited stdin/stdout (the MCP stdio transport) with no extra
// dependency. Tools run as the current vctl identity, so Vault policies and
// app-layer RBAC still apply. Auth is forced non-interactive (cached token or
// AppRole): a lapsed, AppRole-less session makes a tool error rather than emit
// a login prompt that would corrupt the JSON-RPC channel.
const mcpProtocolVersion = "2024-11-05"

func mcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run a read-only MCP server (stdio) exposing the inventory to AI agents",
		Long: `mcp runs a Model Context Protocol server over stdio so an AI agent
(e.g. Claude Code) can query the vctl inventory.

Read-only tools: vctl_list, vctl_resolve, vctl_whoami, vctl_access_log. Tools
run as your current vctl identity — Vault policies and app RBAC still apply.
Auth is non-interactive (cached token / AppRole); it never prompts.

Wire it into Claude Code:
  claude mcp add vctl -- vctl mcp`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return serveMCP(cmd.Context(), os.Stdin, os.Stdout)
		},
	}
}

// ---- JSON-RPC 2.0 plumbing (MCP stdio transport: one JSON object per line) ----

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func serveMCP(ctx context.Context, in io.Reader, out io.Writer) error {
	// A streaming decoder reads one JSON value per call regardless of size, so a
	// large frame can't trip a line-length cap (a bufio.Scanner would terminate
	// the session on a token over its max). Whitespace/newlines between frames
	// are skipped by the decoder.
	dec := json.NewDecoder(in)
	enc := json.NewEncoder(out)
	for {
		var req mcpRequest
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		resp, respond := dispatchMCP(ctx, &req)
		if !respond {
			continue // notification: no reply
		}
		if err := enc.Encode(resp); err != nil { // Encode appends '\n'
			return err
		}
	}
}

func dispatchMCP(ctx context.Context, req *mcpRequest) (mcpResponse, bool) {
	notification := len(req.ID) == 0
	resp := mcpResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "vctl", "version": Version},
		}
	case "tools/list":
		resp.Result = map[string]any{"tools": mcpTools()}
	case "tools/call":
		if notification {
			return resp, false // a request, not a notification — don't run a side-effecting tool whose result would be discarded
		}
		resp.Result = mcpCallTool(ctx, req.Params)
	case "ping":
		resp.Result = map[string]any{}
	default:
		if notification {
			return resp, false
		}
		resp.Error = &mcpError{Code: -32601, Message: "method not found: " + req.Method}
	}
	return resp, !notification
}

// ---- tool catalog ----

type mcpTool struct {
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

func mcpTools() []mcpTool {
	return []mcpTool{
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

func mcpCallTool(ctx context.Context, params json.RawMessage) map[string]any {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	_ = json.Unmarshal(params, &p)
	text, err := runMCPTool(ctx, p.Name, p.Arguments)
	if err != nil {
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": "error: " + err.Error()}},
			"isError": true,
		}
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}

func runMCPTool(ctx context.Context, name string, args map[string]any) (string, error) {
	switch name {
	case "vctl_list":
		return mcpToolList(ctx, argString(args, "dc"))
	case "vctl_resolve":
		return mcpToolResolve(ctx, argString(args, "query"))
	case "vctl_whoami":
		return mcpToolWhoami(ctx)
	case "vctl_access_log":
		return mcpToolAccessLog(ctx, argInt(args, "limit", 20), argString(args, "host"), argString(args, "user"))
	case "vctl_ssh_exec":
		return mcpToolSSHExec(ctx, argString(args, "host"), argString(args, "command"), argInt(args, "timeout_seconds", 60))
	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
}

// mcpToolSSHExec runs a command on a host over SSH, enforcing the same two-layer
// gate as `vctl ssh`: the Vault SSH policy (cert signing) plus app-layer RBAC.
// It runs as the current identity — the read-only AppRole cannot sign certs, so
// an ssh-capable OIDC session (vctl-ssh-users / admin) must be active.
func mcpToolSSHExec(ctx context.Context, host, command string, timeout int) (string, error) {
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
	err := withMCPStore(ctx, false, func(a *app.App, st *store.Store) error {
		// app-RBAC ssh gate (Layer 2), mirroring enforceRBAC; Vault cert signing
		// is the Layer-1 gate enforced when the connector signs below. Snapshot
		// fails closed on a Vault policy-lookup error (no silent admin-misclassification).
		az, err := mcpAuthorizer(a, st).Snapshot(ctx)
		if err != nil {
			return err
		}
		if !az.Allows("ssh") {
			return fmt.Errorf("rbac: 'ssh' not permitted for %q (needs vctl-ssh-users/admin + an rbac grant; the read-only AppRole cannot ssh)", az.Identity)
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
		res, runErr := newConnector(a).Execute(ctx,
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

type mcpServer struct {
	Hostname string   `json:"hostname"`
	IP       string   `json:"ip"`
	ExtraIPs []string `json:"extra_ips,omitempty"`
	DC       string   `json:"dc"`
	User     string   `json:"user"`
	Jump     string   `json:"jump,omitempty"`
	Status   string   `json:"status"`
	Agent    string   `json:"agent_version,omitempty"`
}

func toMCPServer(w store.ServerWithStatus) mcpServer {
	m := mcpServer{
		Hostname: w.Hostname, IP: w.IP, ExtraIPs: w.ExtraIPs,
		DC: w.DC, User: w.User, Jump: w.JumpVia,
		Status: stripANSI(liveStatus(w)),
	}
	if w.Status != nil {
		m.Agent = w.Status.AgentVersion
	}
	return m
}

func mcpToolList(ctx context.Context, dc string) (string, error) {
	var items []mcpServer
	err := withMCPStore(ctx, false, func(_ *app.App, st *store.Store) error {
		rows, err := st.ListWithStatus(ctx, dc)
		if err != nil {
			return err
		}
		items = make([]mcpServer, len(rows))
		for i, w := range rows {
			items[i] = toMCPServer(w)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return toJSON(map[string]any{"count": len(items), "servers": items})
}

func mcpToolResolve(ctx context.Context, query string) (string, error) {
	if strings.TrimSpace(query) == "" {
		return "", fmt.Errorf("query is required")
	}
	var out any
	err := withMCPStore(ctx, false, func(_ *app.App, st *store.Store) error {
		sv, cands, err := st.Resolve(ctx, query)
		if err != nil {
			return err
		}
		switch {
		case sv != nil:
			out = map[string]any{"match": toMCPServer(store.ServerWithStatus{Server: *sv})}
		case len(cands) == 0:
			out = map[string]any{"match": nil, "candidates": []any{}}
		default:
			cs := make([]mcpServer, len(cands))
			for i, c := range cands {
				cs[i] = toMCPServer(store.ServerWithStatus{Server: c})
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

func mcpToolWhoami(ctx context.Context) (string, error) {
	var out map[string]any
	err := withMCPStore(ctx, false, func(a *app.App, st *store.Store) error {
		az, err := mcpAuthorizer(a, st).Snapshot(ctx)
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

type mcpAccess struct {
	User       string `json:"user"`
	Host       string `json:"host"`
	OK         bool   `json:"ok"`
	SignedAt   string `json:"signed_at"`
	SourceIP   string `json:"source_ip,omitempty"`
	ClientUser string `json:"client_user,omitempty"`
	Error      string `json:"error,omitempty"`
}

func mcpToolAccessLog(ctx context.Context, limit int, host, user string) (string, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	var items []mcpAccess
	err := withMCPAuditStore(ctx, func(_ *app.App, st *store.Store) error {
		entries, err := st.AccessLog(ctx, limit, host, user, "")
		if err != nil {
			return err
		}
		items = make([]mcpAccess, len(entries))
		for i, e := range entries {
			items[i] = mcpAccess{
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

// mcpApp builds the app with auth pinned to AppRole so a lapsed session re-auths
// non-interactively (or errors) and never emits a login prompt that would
// corrupt the stdio JSON-RPC channel.
func mcpApp() (*app.App, error) {
	a, err := app.New()
	if err != nil {
		return nil, err
	}
	a.Cfg.AuthMethod = "approle"
	return a, nil
}

func withMCPStore(ctx context.Context, rw bool, fn func(*app.App, *store.Store) error) error {
	a, err := mcpApp()
	if err != nil {
		return err
	}
	p := app.PurposeInventoryRead
	if rw {
		p = app.PurposeInventoryWrite
	}
	st, err := a.OpenStore(ctx, p)
	if err != nil {
		return err
	}
	defer st.Close()
	return fn(a, st)
}

func withMCPAuditStore(ctx context.Context, fn func(*app.App, *store.Store) error) error {
	a, err := mcpApp()
	if err != nil {
		return err
	}
	st, err := a.OpenStore(ctx, app.PurposeAuditRead)
	if err != nil {
		return err
	}
	defer st.Close()
	return fn(a, st)
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

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
