package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// kvSetCmd wires the flags for `vctl kv set`; the work is runKVSet.
func kvSetCmd(env cmdkit.Env) *cobra.Command {
	var opts kvSetOpts
	cmd := &cobra.Command{
		Use:   "set <path> [<key>=<value>...] [--rm <key>]...",
		Short: "Write fields of a KV secret — merged, check-and-set, values never echoed",
		Long: `set writes string fields into a KV v2 secret. By default it merges: the
fields you name are written, every other field the secret has is kept, and
the write is refused if the secret changed between the read and the write
(check-and-set), so two people editing one secret cannot silently undo each
other — set re-reads and retries. --replace writes exactly the fields given.

A value comes from the argument, a file, or stdin:

  vctl kv set kv/users/<entity>/wg address=10.0.100.3/32 dns=192.168.201.12
  vctl kv set kv/teams/sre/k8s/core-sre ca=@ca.pem token=-    # token from stdin
  vctl kv set kv/teams/sre/x --rm old_field

A value typed on the command line stays in shell history; key=@file or key=-
keeps a secret out of it. Nothing written is ever printed back — field names
only. The path must be the full path: a bare word is matched by search for
reads, never for a write. Vault's own policy decides where you may write;
this command is the vctl-side gate on top.`,
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: firstArgOnly(completeKVPath(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKVSet(cmd, env, args, opts)
		},
	}
	cmd.Flags().BoolVar(&opts.replace, "replace", false, "write exactly the given fields and drop every other field")
	cmd.Flags().StringArrayVar(&opts.remove, "rm", nil, "remove a field while merging (repeatable)")
	return cmdkit.Gate(cmd, "kv-set")
}

// kvSetOpts is the bound flag set of `kv set`.
type kvSetOpts struct {
	replace bool
	remove  []string
}

// kvWriter is the KV port a write needs: the current version, and a write
// that names the version it expects.
type kvWriter interface {
	ReadKVSecret(ctx context.Context, path string, version int) (vaultc.KVSecret, error)
	WriteKV(ctx context.Context, path string, data map[string]string, cas int) (int, error)
}

var _ kvWriter = (*vaultc.Client)(nil)

func runKVSet(cmd *cobra.Command, env cmdkit.Env, args []string, opts kvSetOpts) error {
	path := normalizeKVPath(args[0])
	if !strings.Contains(path, "/") {
		return fmt.Errorf("%q is not a path; a write needs the full path — find it with `vctl kv search %s`", args[0], args[0])
	}
	sets, literal, err := parseKVAssignments(args[1:], cmd.InOrStdin())
	if err != nil {
		return err
	}
	if len(sets) == 0 && len(opts.remove) == 0 {
		return errors.New("nothing to write: give key=value pairs, or --rm keys")
	}
	if opts.replace && len(opts.remove) > 0 {
		return errors.New("--rm has no meaning with --replace; leave the field out instead")
	}
	return env.WithApp(func(a *app.App) error {
		ctx := cmd.Context()
		if err := a.EnsureLogin(ctx); err != nil {
			return err
		}
		res, err := kvSet(ctx, a.Vault, path, sets, opts.remove, opts.replace)
		if err != nil {
			return err
		}
		ui.Successf(os.Stderr, "%s", res.summary(path))
		if literal {
			ui.Infof(os.Stderr, "values typed on the command line stay in shell history; key=@file or key=- keeps them out")
		}
		return nil
	})
}

// kvFieldName is what Vault accepts as a key and what nobody will mistake for
// a value: letters, digits, and _ - . only.
var kvFieldName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// parseKVAssignments reads key=value arguments. @file reads the value from a
// file and - from stdin (one field at most); \@ is a literal @. It reports
// whether any value came straight from the command line, so the caller can
// say a word about shell history.
func parseKVAssignments(args []string, stdin io.Reader) (sets map[string]string, literal bool, err error) {
	sets = map[string]string{}
	usedStdin := false
	for _, arg := range args {
		k, v, ok := strings.Cut(arg, "=")
		if !ok || k == "" {
			return nil, false, fmt.Errorf("%q is not key=value", arg)
		}
		if !kvFieldName.MatchString(k) {
			return nil, false, fmt.Errorf("%q is not a field name (letters, digits, _ - .)", k)
		}
		if _, dup := sets[k]; dup {
			return nil, false, fmt.Errorf("field %s is given twice", k)
		}
		switch {
		case v == "-":
			if usedStdin {
				return nil, false, fmt.Errorf("stdin can feed one field, and %s is the second", k)
			}
			usedStdin = true
			b, err := io.ReadAll(stdin)
			if err != nil {
				return nil, false, fmt.Errorf("read stdin for %s: %w", k, err)
			}
			sets[k] = strings.TrimSuffix(string(b), "\n")
		case strings.HasPrefix(v, "@"):
			b, err := os.ReadFile(v[1:])
			if err != nil {
				return nil, false, fmt.Errorf("read %s for %s: %w", v[1:], k, err)
			}
			sets[k] = string(b)
		case strings.HasPrefix(v, `\@`):
			sets[k] = v[1:]
			literal = true
		default:
			sets[k] = v
			literal = true
		}
	}
	return sets, literal, nil
}

// kvSetResult is what happened, in field names only.
type kvSetResult struct {
	Version int
	Created bool
	Set     []string
	Removed []string
	Kept    int
}

func (r kvSetResult) summary(path string) string {
	var parts []string
	if len(r.Set) > 0 {
		parts = append(parts, "set "+strings.Join(r.Set, ", "))
	}
	if len(r.Removed) > 0 {
		parts = append(parts, "removed "+strings.Join(r.Removed, ", "))
	}
	if r.Kept > 0 {
		parts = append(parts, fmt.Sprintf("kept %d", r.Kept))
	}
	state := fmt.Sprintf("version %d", r.Version)
	if r.Created {
		state = "new secret, " + state
	}
	return fmt.Sprintf("%s (%s): %s", path, state, strings.Join(parts, " · "))
}

// kvSet applies the change under check-and-set. In merge mode it reads the
// current version, applies the sets and removals to a copy, and writes with
// cas=that version — a secret that moved in between is re-read and the edit
// reapplied onto the winner, up to three times. A secret that does not exist
// is created with cas=0. Replace mode writes exactly the given fields, with no
// version condition, because that is what "replace" means.
func kvSet(ctx context.Context, kv kvWriter, path string, sets map[string]string, remove []string, replace bool) (kvSetResult, error) {
	const attempts = 3
	for attempt := 1; ; attempt++ {
		res := kvSetResult{Set: slices.Sorted(maps.Keys(sets))}
		data := map[string]string{}
		cas := -1
		if !replace {
			cur, err := kv.ReadKVSecret(ctx, path, 0)
			switch {
			case err == nil:
				maps.Copy(data, cur.Data)
				cas = cur.Version
			case errors.Is(err, vaultc.ErrKVNotFound):
				cas = 0
				res.Created = true
			default:
				return res, err
			}
			for _, k := range remove {
				if _, ok := data[k]; ok {
					delete(data, k)
					res.Removed = append(res.Removed, k)
				}
			}
			for k := range data {
				if _, replaced := sets[k]; !replaced {
					res.Kept++
				}
			}
		}
		maps.Copy(data, sets)
		if len(data) == 0 {
			return res, fmt.Errorf("%s would be left with no fields; delete the secret instead of emptying it", path)
		}
		version, err := kv.WriteKV(ctx, path, data, cas)
		if err == nil {
			res.Version = version
			return res, nil
		}
		if errors.Is(err, vaultc.ErrKVConflict) && !replace && attempt < attempts {
			continue
		}
		return res, err
	}
}
