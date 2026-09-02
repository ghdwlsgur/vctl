package cmdkit

// Shell completion for the values that are typed most and remembered least: a
// deployment's Keystone endpoint, a Nova uuid, the project a VM belongs to.
//
// Three rules hold for everything here and for every completion built on it,
// and they come from where a completion runs: a hidden process spawned by a
// keystroke, in the middle of a line somebody is still typing.
//
//   - It never asks anything. Authenticating here would put a password prompt,
//     or a browser, behind a Tab — so a completion that would need one produces
//     nothing instead.
//   - It never waits. CompletionBudget is the whole cost of a keypress, and
//     an unreachable database has to cost that and no more.
//   - It never speaks. Anything written to stderr lands in the middle of the
//     command being typed, so stderr is closed for the duration.
//
// Every failure means the same thing: no candidates. A shell that gets nothing
// falls back to the user typing the value, which is where they were anyway.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// CompletionBudget is what one Tab may cost.
//
// Short on purpose, and short enough to lose some answers. Measured on this
// fleet: a warm process answers in 0.14s, while the first contact with Vault
// and Postgres after an idle period takes about ten seconds — the same ten
// seconds any other vctl command pays there. No budget that belongs on a
// keystroke covers that, so the first Tab of a session can come back empty and
// the next one, after any real command has opened the path, is instant.
//
// That is the trade taken deliberately. A Tab that offers nothing costs the
// user the typing they were already doing; a Tab that freezes the terminal for
// ten seconds looks like a hung shell.
const CompletionBudget = 2 * time.Second

// Completer is cobra's signature for both flag values and positional arguments.
type Completer func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)

// CompleteFromStore answers a completion out of the inventory database.
//
// fn returns the candidates and nothing else: no error path, because there is
// nowhere to report one. Everything that can fail — building the app,
// authenticating, connecting, querying — collapses to an empty list here.
func (e Env) CompleteFromStore(fn func(context.Context, *store.Store, string) []string) Completer {
	return func(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		defer SilenceStderr()()

		a, err := e.App()
		if err != nil {
			return NoCompletions()
		}
		// The one check that has to happen before anything opens: with no token
		// and no AppRole credentials, opening the store is what triggers the
		// login, and a login triggered from here is a prompt nobody asked for
		// attached to a keystroke.
		if a.WouldPromptForLogin() {
			return NoCompletions()
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), CompletionBudget)
		defer cancel()
		st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
		if err != nil {
			return NoCompletions()
		}
		defer st.Close()
		return fn(ctx, st, toComplete), cobra.ShellCompDirectiveNoFileComp
	}
}

// NoCompletions is the answer to everything that went wrong.
//
// NoFileComp rather than ShellCompDirectiveError: on an error most shells fall
// back to completing filenames, and offering the contents of the current
// directory as candidates for --farm is worse than offering nothing.
func NoCompletions() ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveNoFileComp
}

// SilenceStderr redirects stderr for the duration of a completion and returns
// the undo.
//
// Not tidiness. The store path warns about a local DSN, the audit spool reports
// what it flushed — both correct in a command, both written straight into the
// half-typed line here, where the shell has already drawn the prompt and has no
// idea something else printed.
func SilenceStderr() func() {
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return func() {}
	}
	prev := os.Stderr
	os.Stderr = devnull
	return func() {
		os.Stderr = prev
		_ = devnull.Close()
	}
}

// candidate formats one completion the way cobra reads it: the value, a tab,
// and what to say about it.
//
// The description is what makes a uuid choosable. Tabs and newlines inside it
// would end the value or the line, so they are flattened rather than trusted —
// a VM name comes from nova and nothing here controls what is in it.
func Candidate(value, desc string) string {
	desc = strings.Join(strings.Fields(desc), " ")
	if desc == "" {
		return value
	}
	return value + "\t" + desc
}

func HasPrefixFold(s, prefix string) bool {
	return strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix))
}

// StoredThenStore is the sequence every fleet completion runs: the stored
// reading answers when it can — a Tab has a two-second budget and the first
// contact with Vault and Postgres after an idle period takes about ten — and
// the database answers when it cannot. Five completions carried this wrapper
// verbatim, and a sixth had inlined it one branch differently.
func StoredThenStore(env Env, stored func(string) ([]string, bool), db func(context.Context, *store.Store, string) []string) Completer {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		restore := SilenceStderr()
		if out, ok := stored(toComplete); ok {
			restore()
			return out, cobra.ShellCompDirectiveNoFileComp
		}
		restore()
		return env.CompleteFromStore(db)(cmd, args, toComplete)
	}
}

// CompleteInventoryHost offers the hosts vctl can connect to.
//
// The inventory rather than the OpenStack view: this is what `vctl ssh` and
// --server resolve against, and most of the fleet is not an OpenStack machine.
// Retired hosts are left out — the row is kept as a record and connecting to
// one is not what anybody is completing towards.
//
// The local snapshot answers first, which is the opposite of every other path
// here. Two reasons, and neither applies to farms or VMs. It is the completion
// somebody presses constantly, and the snapshot has exactly what it needs — so
// paying the database for it is paying for something already on disk. And the
// snapshot is what `vctl ssh` itself falls back to when Postgres is gone, so
// completing from it during an outage offers the same hosts the command will
// still resolve.
func CompleteInventoryHost(env Env) Completer {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		restore := SilenceStderr()
		if a, err := env.App(); err == nil && !a.Cfg.CacheDisabled {
			snap, err := a.CacheFile().Load()
			if err == nil && snap.HasInventory() && !snap.Expired(time.Now(), a.Cfg.CacheStaleLimit()) {
				servers := make([]store.Server, 0, len(snap.Servers))
				for _, s := range snap.Servers {
					servers = append(servers, s.Server)
				}
				restore()
				return inventoryHostCompletions(servers, toComplete), cobra.ShellCompDirectiveNoFileComp
			}
		}
		restore()
		return env.CompleteFromStore(func(ctx context.Context, st *store.Store, toComplete string) []string {
			servers, err := st.List(ctx, "")
			if err != nil {
				return nil
			}
			return inventoryHostCompletions(servers, toComplete)
		})(cmd, args, toComplete)
	}
}

func inventoryHostCompletions(servers []store.Server, toComplete string) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		if s.State == store.StateRetired || !HasPrefixFold(s.Hostname, toComplete) {
			continue
		}
		desc := s.DC
		if s.State != "" && s.State != store.StateActive {
			desc = strings.TrimPrefix(desc+" · "+s.State, " · ")
		}
		out = append(out, Candidate(s.Hostname, desc))
	}
	return out
}

// StaticCompletions offers a fixed set — a flag whose values are a contract
// rather than data. It touches nothing, so it answers during an outage too.
//
// The value may carry its own description after a tab, the same as any other
// candidate.
func StaticCompletions(values ...string) Completer {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		out := make([]string, 0, len(values))
		for _, v := range values {
			if HasPrefixFold(v, toComplete) {
				out = append(out, v)
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

// ByPosition dispatches on which argument is being typed: the first Completer
// answers the first argument, the second the second, and anything past the end
// gets nothing.
//
// `farm state <deployment> <state>` is two different questions in one line, and
// offering the deployments again in the second position would suggest a farm
// where only four words are legal.
func ByPosition(fns ...Completer) Completer {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) >= len(fns) {
			return NoCompletions()
		}
		return fns[len(args)](cmd, args, toComplete)
	}
}

// RegisterCompletion attaches a Completer to a flag. cobra reports the flag not
// existing, which is a wiring mistake rather than a runtime condition, so it
// panics here rather than leaving a flag silently uncompleted.
func RegisterCompletion(cmd *cobra.Command, flag string, fn Completer) {
	if err := cmd.RegisterFlagCompletionFunc(flag, fn); err != nil {
		panic(fmt.Sprintf("completion for --%s on %q: %v", flag, cmd.Name(), err))
	}
}
