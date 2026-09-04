// Package cmdkit is the machinery a vctl command is built from: the dependency
// seam every constructor takes (Env), the store/inventory open-run-close
// helpers, structured output, shell completion plumbing, the RBAC gate, the
// list picker and the host resolver.
//
// It exists so a command subtree can live in its own package. The first one to
// leave internal/cli (internal/mcp) took its four seams as an explicit Deps
// struct; the openstack tree needs a couple of dozen, which is not a Deps
// struct any more — it is the command framework itself, and this package is
// that framework with a name. What stays behind in internal/cli is what makes
// vctl vctl: the commands, and the root that decides where an operator finds
// them.
//
// The nested internal/ is deliberate. Only the cli tree can import this
// package, so a protocol server or an agent daemon cannot quietly grow a
// dependency on the CLI's wiring the way the MCP server once did on the CLI's
// app seam (see internal/mcp's package doc for that history).
package cmdkit

import (
	"context"
	"os"
	"time"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/audit"
	"github.com/ghdwlsgur/vctl/internal/auditspool"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func withAppFrom(newApp func() (*app.App, error), fn func(*app.App) error) error {
	a, err := newApp()
	if err != nil {
		return err
	}
	return fn(a)
}

// withInventory is withStore's read-only sibling for the two commands that have
// to keep working during a database outage: it opens the inventory through the
// local snapshot fallback instead of requiring Postgres.
//
// Commands that write, or that read data with no offline meaning (audit history,
// RBAC administration), keep using withStore and keep failing loudly when the
// database is gone — which is the correct outcome for them.
func withInventoryFrom(ctx context.Context, newApp func() (*app.App, error), fn func(*app.App, *app.Inventory) error) error {
	a, err := newApp()
	if err != nil {
		return err
	}
	a.OnSpoolFlush = reportSpoolFlush
	inv, err := a.OpenInventory(ctx)
	if err != nil {
		return err
	}
	defer inv.Close()
	warnIfCached(inv)
	return fn(a, inv)
}

// warnIfCached tells the operator, once per command, that what follows is a
// snapshot rather than the current inventory. Silence here would be the
// dangerous option: a decommissioned host still present in an hours-old snapshot
// looks exactly like a live one.
func warnIfCached(inv *app.Inventory) {
	if !inv.Cached() {
		return
	}
	ui.Warnf(os.Stderr, "inventory database unreachable — using the local snapshot from %s ago (run 'vctl cache status' for detail)",
		strutil.CompactDuration(inv.Age(time.Now())))
}

// reportSpoolFlush surfaces the replay of access records that were queued while
// Postgres was unreachable. Dropped records are warned about first and always:
// they are the part of the trail that is gone, and a success line alone would
// read as a complete recovery.
func reportSpoolFlush(res auditspool.Result, err error) {
	if res.Skipped > 0 {
		ui.Warnf(os.Stderr, "dropped %d unreadable queued access record(s) — the audit trail is missing them", res.Skipped)
	}
	if err != nil {
		ui.Warnf(os.Stderr, "queued access records: %v", err)
		return
	}
	if res.Sent > 0 {
		ui.Infof(os.Stderr, "flushed %d queued access record(s) to the audit log", res.Sent)
	}
}

// withStore builds the app, opens the inventory store (rw=true for write roles),
// and runs fn with both — closing the store afterward. It collapses the
// new-app + open-store + defer-close preamble repeated by every store-backed
// command into one call.
// WithStorePort opens the store the way withStore does and hands fn only the
// port the command declared — its three-to-five methods, not the store's
// eighty-seven. The compiler then owns the rule that `vctl add` cannot delete
// a host: reaching for a method outside the port is a build error, where
// before it was a diff nobody was asked about. Vault's per-purpose DB roles
// still bound what the credential can do; this bounds what the code can ask.
//
// The assertion cannot fire: every port carries a
// `var _ port = (*store.Store)(nil)` proof next to its declaration.
func WithStorePort[S any](env Env, ctx context.Context, rw bool, fn func(*app.App, S) error) error {
	return env.WithStore(ctx, rw, func(a *app.App, st *store.Store) error {
		return fn(a, any(st).(S))
	})
}

// withStoreFrom is withPurposeStore with the app constructor left open.
//
// The MCP server needs the same open/run/close discipline but a different app:
// it must authenticate non-interactively, because a login prompt would write to
// the stdio channel that carries JSON-RPC and corrupt the protocol. That is one
// line of difference, and duplicating the preamble to express it meant the
// close-on-every-path guarantee lived in two places — the kind of thing that
// stays correct until someone fixes a leak in one copy.
func withStoreFrom(ctx context.Context, newApp func() (*app.App, error), p app.Purpose, fn func(*app.App, *store.Store) error) error {
	a, err := newApp()
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

// audit is the audit database, scoped to what a caller may do with it.
//
// The commands that touch audit data used to receive the whole store and pick
// their own methods out of it, which said nothing about the three separate
// credentials behind them — see internal/audit.
func (e Env) Audit() (*app.App, *audit.Store, error) {
	a, err := e.App()
	if err != nil {
		return nil, nil, err
	}
	return a, audit.New(func(ctx context.Context, p audit.Purpose) (audit.Conn, error) {
		purpose := app.PurposeAuditRead
		switch p {
		case audit.Ingest:
			purpose = app.PurposeAuditIngest
		case audit.Prune:
			purpose = app.PurposeAuditPrune
		}
		return a.OpenStore(ctx, purpose)
	}), nil
}

// Env is what a command needs from the place it was built.
//
// It replaced a package variable that NewRoot pointed at the resolved
// Dependencies. That worked because callers build one tree at a time, which was
// true and was a convention rather than a guarantee: a second NewRoot
// overwrote the first tree's factory, and from then on whichever tree ran used
// the other's app. Nothing failed — the wrong dependency simply answered — and
// with no parallel tests in the package there was nothing to notice it.
//
// The zero value builds a real app, which is what a test constructing a tree
// only to read its shape gets. Anything that runs a command supplies one.
type Env struct {
	// NewApp builds the App this tree's commands use.
	NewApp func() (*app.App, error)
}

func (e Env) App() (*app.App, error) {
	if e.NewApp != nil {
		return e.NewApp()
	}
	// The zero value is what tests build a command tree with when they only
	// want its shape. Production always comes through NewRoot.
	return app.New()
}

// withApp is Env's version of the package function, for commands that
// need the app but not the store.
func (e Env) WithApp(fn func(*app.App) error) error {
	return withAppFrom(e.App, fn)
}

// withInventory is Env's version of the package function: the store when
// it answers, the local snapshot when it does not.
func (e Env) WithInventory(ctx context.Context, fn func(*app.App, *app.Inventory) error) error {
	return withInventoryFrom(ctx, e.App, fn)
}

// withPurposeStore opens the store for one purpose.
func (e Env) WithPurposeStore(ctx context.Context, p app.Purpose, fn func(*app.App, *store.Store) error) error {
	return withStoreFrom(ctx, e.App, p, fn)
}

// withStore opens the inventory store for this subtree's app (rw=true for write
// roles), runs fn, and closes it.
func (e Env) WithStore(ctx context.Context, rw bool, fn func(*app.App, *store.Store) error) error {
	p := app.PurposeInventoryRead
	if rw {
		p = app.PurposeInventoryWrite
	}
	return withStoreFrom(ctx, e.App, p, fn)
}
