// Package access owns the SSH connection pipeline shared by `vctl ssh` and the
// MCP vctl_ssh_exec tool: resolve an inventory host, build its jump chain, apply
// a host-key policy, sign a short-lived certificate via Vault, dial (interactive
// shell or one-shot command), and record the attempt to the central access log.
//
// Before this package each caller reassembled those steps inline, so a host-key
// policy tweak or a missing audit write had to be fixed in two places. Here the
// order is fixed once — most importantly, every Connect/Execute records an audit
// entry through the same path, so an SSH can never run without a trace. Callers
// keep only input (which host, interactive or not) and output (rendering the
// result). The package depends on narrow ports, never on internal/app, so it
// stays testable and free of an import cycle.
package access

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/ghdwlsgur/vctl/internal/sshc"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
)

// CertSigner signs an SSH public key via the Vault SSH CA. Satisfied by
// *vaultc.Client.
type CertSigner interface {
	SignSSH(ctx context.Context, role, publicKey string, principals []string, ttl string, extensions []string) (string, error)
}

// Identifier returns the current Vault identity, used to attribute audit rows.
// Satisfied by *vaultc.Client.
//
// The error matters here: a failed lookup used to collapse into "", and the
// audit row it fed was indistinguishable from one made by a legitimately
// nameless token. The connection still proceeds — Vault just signed its
// certificate, so the failure is a blip, not an authorization problem — but
// the caller is told the attribution is missing instead of it going quietly.
type Identifier interface {
	Identity(ctx context.Context) (string, error)
}

// AuditLogger records one access attempt. Satisfied by *app.App.
type AuditLogger interface {
	LogAccess(ctx context.Context, entry store.AccessEntry) error
}

// Inventory resolves inventory hosts. Satisfied by *store.Store.
type Inventory interface {
	Resolve(ctx context.Context, query string) (*store.Server, []store.Server, error)
	Get(ctx context.Context, hostname string) (*store.Server, error)
}

// HostKeyPolicy decides how an unknown host key is handled along the whole jump
// chain — the single knob that used to be two scattered setHostKey* helpers.
type HostKeyPolicy int

const (
	// HostKeyPrompt allows an interactive prompt to confirm an unknown key
	// (`vctl ssh <host>` at a terminal).
	HostKeyPrompt HostKeyPolicy = iota
	// HostKeyStrict rejects an unknown key with no prompt and no auto-add
	// (`vctl ssh --server`: exact, non-interactive, but not an agent).
	HostKeyStrict
	// HostKeyAcceptNew records an unknown key on first use (accept-new) for
	// non-interactive agents that cannot prompt (`vctl mcp`).
	HostKeyAcceptNew
)

// apply writes the policy onto every hop of the jump chain.
func (p HostKeyPolicy) apply(t *sshc.Target) {
	for ; t != nil; t = t.Jump {
		t.ConfirmHostKey = p == HostKeyPrompt
		t.AutoAddHostKey = p == HostKeyAcceptNew
	}
}

// Request is one connection or execution against an already-resolved target.
type Request struct {
	Target  *sshc.Target
	HostKey HostKeyPolicy
}

// Result is the outcome of Execute: the target it ran against plus the captured
// output. Stdout/Stderr may hold partial output even when Execute returns an
// error (e.g. a timeout), so a caller can surface it.
type Result struct {
	Host     string
	Addr     string
	Stdout   string
	Stderr   string
	ExitCode int
}

// Connector runs the SSH pipeline for a single identity. Build one per app via
// the caller's wiring; it holds no per-connection state.
type Connector struct {
	Signer   CertSigner
	Identity Identifier
	Audit    AuditLogger
	SignTTL  string // issued certificate TTL (config SSHSign)

	// OnAuditError is invoked when the best-effort audit write fails, so the
	// caller can warn without the pipeline failing the connection. May be nil.
	OnAuditError func(error)

	// Now is the clock used to stamp an audit row with the certificate's signing
	// time. Nil means time.Now; tests set it to assert the stamp.
	Now func() time.Time
}

// Connect opens an interactive PTY shell to the target and blocks until it
// exits. The attempt is always audited, success or failure.
//
// The audit row is written the moment the PTY opens — before the shell blocks,
// not after it returns. An interactive session can last hours, and the process
// can die inside it (a closed terminal is a SIGHUP, a crashed laptop is nothing
// at all); recording only after sshc.Connect returned meant those sessions left
// no trace in Postgres or the spool, and even a clean exit stamped the row with
// the logout time instead of when access was granted. The access has happened
// once the certificate is signed and the PTY is up, so that is when it is
// logged, with the certificate's own signing time.
func (c *Connector) Connect(ctx context.Context, req Request) error {
	req.HostKey.apply(req.Target)
	sign, serial, signedAt := c.signFunc(ctx)
	vaultUser := c.attributedIdentity(ctx)

	recorded := false
	info, err := sshc.Connect(ctx, req.Target, sign, func(dialed sshc.ConnectionInfo) {
		// The PTY is open: the access is real and must survive whatever the
		// session does next, including the process not returning from it.
		c.record(ctx, accessEntry(vaultUser, req.Target, dialed, serial(), signedAt(), nil))
		recorded = true
	})
	if !recorded {
		// Dial or handshake failed before the shell — the attempt is still audited.
		c.record(ctx, accessEntry(vaultUser, req.Target, info, serial(), signedAt(), err))
	}
	return err
}

// attributedIdentity is who the audit row will name. A lookup failure is
// surfaced through OnAuditError — the same channel a failed audit write uses,
// because both mean the same thing: the trail for this connection is
// incomplete and somebody should know now, not during an investigation.
func (c *Connector) attributedIdentity(ctx context.Context) string {
	id, err := c.Identity.Identity(ctx)
	if err != nil && c.OnAuditError != nil {
		c.OnAuditError(fmt.Errorf("identity lookup failed; the audit row will carry no user: %w", err))
	}
	return id
}

// Execute runs a single command on the target non-interactively and returns its
// output. A non-zero remote exit is reported in Result.ExitCode with a nil
// error; only a transport/connection failure returns a non-nil error.
//
// When timeout > 0 the sign+dial+run are bounded by it; the audit write is not,
// so a timed-out command is still recorded. The attempt is always audited.
func (c *Connector) Execute(ctx context.Context, req Request, command string, timeout time.Duration) (Result, error) {
	res, entry, err := c.run(ctx, req, command, timeout)
	c.record(ctx, entry)
	return res, err
}

// run performs the sign + dial + command without recording anything, returning
// the audit entry the attempt produced so the caller decides what to do with it.
//
// Split out for Monitor, which polls on a timer and must not write a row per
// poll. Execute is still the only way to run a one-off command, and it always
// records — the split moves the decision, it does not remove it.
func (c *Connector) run(ctx context.Context, req Request, command string, timeout time.Duration) (Result, store.AccessEntry, error) {
	runCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	req.HostKey.apply(req.Target)
	sign, serial, signedAt := c.signFunc(runCtx)
	vaultUser := c.attributedIdentity(ctx)
	res, info, err := sshc.Run(runCtx, req.Target, sign, command)
	return Result{
			Host: req.Target.Name, Addr: req.Target.Addr,
			Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode,
		},
		accessEntry(vaultUser, req.Target, info, serial(), signedAt(), err),
		err
}

// record writes one prepared audit entry, best-effort.
func (c *Connector) record(ctx context.Context, entry store.AccessEntry) {
	if err := c.Audit.LogAccess(ctx, entry); err != nil && c.OnAuditError != nil {
		c.OnAuditError(err)
	}
}

// signFunc returns a sshc.SignFunc that signs through the CA at the configured
// TTL, a getter for the most recent issued cert serial, and a getter for when it
// was signed. On a jump chain the target is signed last, so both getters end up
// holding the target's values — used to map the access-audit row to a specific
// certificate and to stamp it with the time access was actually granted rather
// than whenever the row happens to be written.
func (c *Connector) signFunc(ctx context.Context) (sshc.SignFunc, func() string, func() time.Time) {
	var (
		serial   string
		signedAt time.Time
	)
	fn := func(role, pub string, principals, extensions []string) (string, error) {
		cert, err := c.Signer.SignSSH(ctx, role, pub, principals, c.SignTTL, extensions)
		if err == nil {
			if s := sshc.CertSerial(cert); s != "" {
				serial = s
				signedAt = c.now()
			}
		}
		return cert, err
	}
	return fn, func() string { return serial }, func() time.Time { return signedAt }
}

// now is the clock, injectable so tests can assert the stamped time.
func (c *Connector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// ResolveServer resolves a host non-interactively (for --server and MCP): exact
// or unique match only, never a picker. Ambiguous or missing hosts error out
// with the candidate list so the caller can pick an exact name.
func ResolveServer(ctx context.Context, inv Inventory, query string) (*store.Server, error) {
	sv, cands, err := inv.Resolve(ctx, query)
	if err != nil {
		return nil, err
	}
	if sv != nil {
		return sv, nil
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("no server matches %q", query)
	}
	names := make([]string, 0, len(cands))
	for _, c := range cands {
		names = append(names, c.Hostname)
	}
	return nil, fmt.Errorf("%q is ambiguous (%d matches: %s) — pass an exact hostname", query, len(cands), strings.Join(names, ", "))
}

// BuildTarget converts a server and its jump chain into sshc.Target values,
// detecting cycles along the way.
func BuildTarget(ctx context.Context, inv Inventory, sv *store.Server, directFirst bool) (*sshc.Target, error) {
	return buildTargetSeen(ctx, inv, sv, directFirst, map[string]bool{})
}

func buildTargetSeen(ctx context.Context, inv Inventory, sv *store.Server, directFirst bool, seen map[string]bool) (*sshc.Target, error) {
	if seen[sv.Hostname] {
		return nil, fmt.Errorf("jump host cycle detected: %s", sv.Hostname)
	}
	seen[sv.Hostname] = true

	t := &sshc.Target{
		Name:       sv.Hostname,
		Addr:       net.JoinHostPort(sv.IP, strconv.Itoa(sv.Port)),
		User:       sv.User,
		Role:       sv.CARole,
		SkipDirect: !directFirst,
	}
	if sv.JumpVia != "" {
		jsv, err := inv.Get(ctx, sv.JumpVia)
		if err != nil {
			return nil, fmt.Errorf("lookup jump host %q: %w", sv.JumpVia, err)
		}
		jt, err := buildTargetSeen(ctx, inv, jsv, directFirst, seen)
		if err != nil {
			return nil, err
		}
		t.Jump = jt
	}
	return t, nil
}

// accessEntry assembles the central access-log row from the connection result
// and the local client context. signedAt is when the certificate for this access
// was issued; a zero value lets the store fall back to its own clock, but the
// callers pass the real signing time so the row reflects when access was granted
// rather than when the row was written (which, for an interactive session, is
// when it ended).
func accessEntry(vaultUser string, tgt *sshc.Target, connInfo sshc.ConnectionInfo, certSerial string, signedAt time.Time, connErr error) store.AccessEntry {
	clientUser := ""
	if u, err := user.Current(); err == nil && u != nil {
		clientUser = u.Username
	}
	if clientUser == "" {
		clientUser = os.Getenv("USER")
	}
	clientHost, _ := os.Hostname()
	entry := store.AccessEntry{
		VaultUser:  vaultUser,
		Hostname:   tgt.Name,
		CertSerial: certSerial,
		SignedAt:   signedAt,
		OK:         connErr == nil,
		SourceIP:   connInfo.SourceIP,
		SourceAddr: connInfo.SourceAddr,
		ClientHost: clientHost,
		ClientUser: clientUser,
		TargetAddr: strutil.FirstNonEmpty(connInfo.TargetAddr, tgt.Addr),
		JumpVia:    connInfo.JumpHost,
	}
	if connErr != nil {
		entry.Error = truncateAuditError(connErr.Error())
	}
	return entry
}

func truncateAuditError(s string) string {
	const max = 500
	if len(s) <= max {
		return s
	}
	return s[:max]
}
