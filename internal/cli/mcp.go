package cli

import (
	"bufio"
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
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		if len(strings.TrimSpace(sc.Text())) == 0 {
			continue
		}
		var req mcpRequest
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			continue // ignore unparseable frames
		}
		resp, respond := dispatchMCP(ctx, &req)
		if !respond {
			continue // notification: no reply
		}
		if err := enc.Encode(resp); err != nil { // Encode appends '\n'
			return err
		}
	}
	return sc.Err()
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
	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
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
		id := a.Vault.Identity(ctx)
		pols, _ := a.Vault.TokenPolicies(ctx)
		admin := hasAdminPolicy(pols)
		out = map[string]any{"identity": id, "policies": pols, "admin": admin}
		if admin {
			out["rbac_commands"] = []string{"*"}
			return nil
		}
		cmds, err := st.RBACCommandsForUser(ctx, id)
		if err != nil {
			if isUninitializedRBAC(err) {
				out["rbac_commands"] = []string{}
				return nil
			}
			return err
		}
		out["rbac_commands"] = slices.Sorted(maps.Keys(cmds))
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

// withMCPStore opens the read store with auth pinned to AppRole so a lapsed
// session re-auths non-interactively (or errors) and never prompts on stdio.
func withMCPStore(ctx context.Context, rw bool, fn func(*app.App, *store.Store) error) error {
	a, err := app.New()
	if err != nil {
		return err
	}
	a.Cfg.AuthMethod = "approle"
	st, err := a.OpenStore(ctx, rw)
	if err != nil {
		return err
	}
	defer st.Close()
	return fn(a, st)
}

func withMCPAuditStore(ctx context.Context, fn func(*app.App, *store.Store) error) error {
	a, err := app.New()
	if err != nil {
		return err
	}
	a.Cfg.AuthMethod = "approle"
	st, err := a.OpenStoreRole(ctx, a.Cfg.DBRoleAuditRO)
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
