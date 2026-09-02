package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// The kv commands, one file per concern:
//
//	kv.go          the command tree, the Vault port, and what every verb shares
//	kv_list.go     one level of the tree
//	kv_get.go      one secret, masked unless asked
//	kv_search.go   the walk over the tree, and the search built on it
//	kv_resolve.go  a word into a path — the exact-name rule, the picker, completion
//	kv_exec.go     a command run with fields filled in
//	kv_redact.go   the output filter that keeps those fields off the screen

// kvReader is what `vctl kv` may ask Vault: list one level, read one secret.
//
// Nothing here writes. A secret's copy in Vault belongs to the IaC that manages
// the path, and a CLI that could edit it in place is how the two stop agreeing.
type kvReader interface {
	ListKV(ctx context.Context, path string) ([]string, error)
	ReadKVSecret(ctx context.Context, path string, version int) (vaultc.KVSecret, error)
}

var _ kvReader = (*vaultc.Client)(nil)

func kvCmd(env cmdkit.Env) *cobra.Command {
	var opts kvGetOpts
	cmd := &cobra.Command{
		Use:   "kv [word|path]",
		Short: "Read and search Vault KV secrets",
		Long: `kv reads and searches the KV secrets your Vault token is allowed to see.

  vctl kv                          pick a secret from everything you can list
  vctl kv gitlab                   a word: the one secret it matches, or a picker
  vctl kv kv/teams/sre/x           a path: that secret, exactly
  vctl kv list kv/teams/sre        one level of the tree
  vctl kv search gitlab token      every path containing both words
  vctl kv exec vctl-postgres PGPASSWORD={password} psql -U {username} vctl
                                   run a command with the values filled in, never shown

The bare command takes a secret the way 'vctl ssh' takes a host. A word is
matched against the whole path, case-insensitively; a secret named exactly that
word wins when there is one, and several matches open a picker (←/→ narrows by
folder, typing filters). Without a terminal there is no picker: an ambiguous
word is an error that lists what it matched, so a script never reads a secret
nobody chose.

Paths are the logical ones an operator types, mount first: kv/teams/sre/x.
What you may list and read is decided by your token's Vault policies, per
path, on the server; vctl adds nothing and takes nothing away. 'vctl rbac
whoami' shows the policies you hold.

Values stay hidden unless asked for. On a terminal a secret opens in a viewer:
↑/↓ moves through the fields and only the row under the cursor shows its value,
enter copies that value to the clipboard, q leaves and nothing stays on the
screen. Piped, the keys are listed and the values masked; --reveal prints them
all, --field <key> prints exactly one for a script. 'search' walks paths only
and never reads a secret.

  TOKEN=$(vctl kv gitlab-albert --field token)

Every read lands in Vault's own audit log under your identity.`,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: firstArgOnly(completeKVPath(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKVGet(cmd, env, args, opts)
		},
	}
	addKVGetFlags(cmd, &opts)
	cmd.AddCommand(kvListCmd(env), kvGetCmd(env), kvSearchCmd(env), kvExecCmd(env))
	return cmdkit.SupportsStructuredOutput(cmdkit.Gate(cmd, "kv"))
}

// withKV builds the app, makes sure of a login, and hands fn the KV port.
// Vault only — none of these commands opens Postgres.
func withKV(env cmdkit.Env, ctx context.Context, fn func(*app.App, kvReader) error) error {
	return env.WithApp(func(a *app.App) error {
		if err := a.EnsureLogin(ctx); err != nil {
			return err
		}
		return fn(a, a.Vault)
	})
}

// kvWalkLimit bounds every walk of the tree — search and the picker alike. The
// fleet's mount is a few hundred paths; the cap is for a mount that is not.
const kvWalkLimit = 20000

// kvRoot is where a walk starts when nothing narrower is given.
//
// Derived from the farm-credential prefix rather than configured on its own:
// that prefix already names the team's KV mount, and a second setting for the
// same mount is a second place for it to be wrong. "kv" when nothing says.
func kvRoot(cfg *config.Config) string {
	if cfg != nil {
		if mount, _, _ := strings.Cut(strings.Trim(cfg.VaultFarmPrefix, "/"), "/"); mount != "" {
			return mount
		}
	}
	return "kv"
}

// normalizeKVPath turns what was typed into the logical path Vault expects:
// no surrounding slashes, no empty segments, no stray spaces.
func normalizeKVPath(p string) string {
	parts := strings.FieldsFunc(strings.TrimSpace(p), func(r rune) bool { return r == '/' })
	return strings.Join(parts, "/")
}

// kvError turns Vault's answer into the sentence an operator needs. The two
// that look alike from a distance — nothing there, not allowed to look — are the
// ones worth separating: one is a typo and the other is a policy.
func kvError(err error, path string) error {
	switch {
	case errors.Is(err, vaultc.ErrKVNotFound):
		return fmt.Errorf("nothing at %s — check the path, or find it with 'vctl kv search <word>'", path)
	case vaultc.IsPermissionDenied(err):
		return fmt.Errorf("%s: permission denied — your Vault token's policies do not cover this path ('vctl rbac whoami' lists them)", path)
	}
	return err
}

// fetchKVSecret is the one read every verb that needs a secret goes through:
// the version asked for, with Vault's answer turned into the operator's
// sentence, and one refinement a bare read cannot make — a path that lists is
// a folder, and "kv/teams/sre is a folder" beats "nothing at kv/teams/sre" for
// whoever typed one segment too few. Only for the current version: a numbered
// version that is missing is a missing version, and the list is not made.
func fetchKVSecret(ctx context.Context, kv kvReader, path string, version int) (vaultc.KVSecret, error) {
	sec, err := kv.ReadKVSecret(ctx, path, version)
	if err == nil {
		return sec, nil
	}
	if errors.Is(err, vaultc.ErrKVNotFound) && version == 0 {
		if keys, lerr := kv.ListKV(ctx, path); lerr == nil && len(keys) > 0 {
			return vaultc.KVSecret{}, fmt.Errorf("%s is a folder, not a secret — 'vctl kv list %s' shows what is under it", path, path)
		}
	}
	return vaultc.KVSecret{}, kvError(err, path)
}

// kvNonStringNote stands where a field's value would, for a field that is not
// a string. The print and the viewer say the same thing in the same place.
const kvNonStringNote = "(not a string — not rendered here)"

// warnDeniedFolders names the folders a walk could not list. It goes to stderr
// so a script reading stdout gets paths alone, and it is a note rather than an
// error: the answer is what the token may see, and this is how much it may not.
func warnDeniedFolders(w io.Writer, denied []string) {
	if len(denied) == 0 {
		return
	}
	ui.Warnf(w, "%d folder(s) your token may not list were skipped: %s", len(denied), strings.Join(denied, ", "))
}
