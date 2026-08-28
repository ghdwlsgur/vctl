package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// kvReader is what `vctl kv` may ask Vault: list one level, read one secret.
//
// Nothing here writes. A secret's copy in Vault belongs to the IaC that manages
// the path, and a CLI that could edit it in place is how the two stop agreeing.
type kvReader interface {
	ListKV(ctx context.Context, path string) ([]string, error)
	ReadKVSecret(ctx context.Context, path string, version int) (vaultc.KVSecret, error)
}

var _ kvReader = (*vaultc.Client)(nil)

func kvCmd(env CommandEnv) *cobra.Command {
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

Values stay hidden unless asked for: keys are listed and values masked.
--reveal shows them, --field <key> prints exactly one for a script. 'search'
walks paths only and never reads a secret.

  TOKEN=$(vctl kv gitlab-albert --field token)

Every read lands in Vault's own audit log under your identity.`,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: firstArgOnly(completeKVPath(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKVGet(cmd, env, args, opts)
		},
	}
	addKVGetFlags(cmd, &opts)
	cmd.AddCommand(kvListCmd(env), kvGetCmd(env), kvSearchCmd(env))
	return supportsStructuredOutput(gate(cmd, "kv"))
}

// withKV builds the app, makes sure of a login, and hands fn the KV port.
// Vault only — none of these commands opens Postgres.
func (e CommandEnv) withKV(ctx context.Context, fn func(*app.App, kvReader) error) error {
	return e.withApp(func(a *app.App) error {
		if err := a.EnsureLogin(ctx); err != nil {
			return err
		}
		return fn(a, a.Vault)
	})
}

// kvRoot is where `kv list` and `kv search` start when given no path.
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

// kvListing is the structured shape of one level: Vault's own, folders with a
// trailing slash, so anything already reading `vault kv list -format=json`
// reads this.
type kvListing struct {
	Path string   `json:"path"`
	Keys []string `json:"keys"`
}

func kvListCmd(env CommandEnv) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list [path]",
		Aliases: []string{"ls"},
		Short:   "List the secrets and folders under a path",
		Long: `list shows one level of the KV tree: the secrets and the folders directly
under a path. With no path it starts at the mount.

  vctl kv list
  vctl kv list kv/teams/sre`,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: firstArgOnly(completeKVPath(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := requestedOutput(cmd)
			if err != nil {
				return err
			}
			return env.withKV(cmd.Context(), func(a *app.App, kv kvReader) error {
				path := kvRoot(a.Cfg)
				if len(args) == 1 {
					if p := normalizeKVPath(args[0]); p != "" {
						path = p
					}
				}
				keys, err := kv.ListKV(cmd.Context(), path)
				if err != nil {
					return kvError(err, path)
				}
				if format != outputTable {
					return writeStructured(format, kvListing{Path: path, Keys: keys})
				}
				renderKVListing(os.Stdout, path, keys)
				return nil
			})
		},
	}
	return supportsStructuredOutput(gate(cmd, "kv"))
}

// renderKVListing prints folders first, the way a directory listing does, so
// the eye finds where to descend before what to read.
func renderKVListing(w io.Writer, path string, keys []string) {
	folders, secrets := splitKVKeys(keys)
	fmt.Fprintln(w, ui.GroupHeading(path, fmt.Sprintf("%d folders · %d secrets", len(folders), len(secrets))))
	for _, f := range folders {
		fmt.Fprintf(w, "  %s\n", ui.Title(f))
	}
	for _, s := range secrets {
		fmt.Fprintf(w, "  %s\n", ui.Value(s))
	}
}

// splitKVKeys separates a level's entries by the trailing slash KV puts on
// folders. Order within each half is preserved — ListKV already sorted it.
func splitKVKeys(keys []string) (folders, secrets []string) {
	for _, k := range keys {
		if strings.HasSuffix(k, "/") {
			folders = append(folders, k)
		} else {
			secrets = append(secrets, k)
		}
	}
	return folders, secrets
}

// kvMask stands in for every hidden value. Fixed width on purpose: a mask that
// tracked the value's length would say how long the credential is.
const kvMask = "••••••••"

// kvGetOutput is the structured shape of one secret. Data is present only when
// the caller asked to reveal — absent, not a placeholder, so nothing downstream
// can mistake a mask for the value.
type kvGetOutput struct {
	Path           string            `json:"path"`
	Version        int               `json:"version,omitempty"`
	CreatedAt      *time.Time        `json:"created_at,omitempty"`
	DeletedAt      *time.Time        `json:"deleted_at,omitempty"`
	Destroyed      bool              `json:"destroyed,omitempty"`
	Keys           []string          `json:"keys"`
	NonStringKeys  []string          `json:"non_string_keys,omitempty"`
	Data           map[string]string `json:"data,omitempty"`
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
}

func newKVGetOutput(sec vaultc.KVSecret, reveal bool) kvGetOutput {
	out := kvGetOutput{
		Path:           sec.Path,
		Version:        sec.Version,
		Destroyed:      sec.Destroyed,
		Keys:           kvKeyNames(sec),
		NonStringKeys:  sec.NonString,
		CustomMetadata: sec.CustomMetadata,
	}
	if !sec.CreatedAt.IsZero() {
		t := sec.CreatedAt
		out.CreatedAt = &t
	}
	if !sec.DeletedAt.IsZero() {
		t := sec.DeletedAt
		out.DeletedAt = &t
	}
	if reveal {
		out.Data = sec.Data
	}
	return out
}

// kvKeyNames is the sorted list of a secret's string fields — the answer to
// "what is in here" that needs no value shown.
func kvKeyNames(sec vaultc.KVSecret) []string {
	keys := make([]string, 0, len(sec.Data))
	for k := range sec.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// kvGetOpts are the flags a read takes. Declared once and attached to both the
// bare command and `get`, so `vctl kv gitlab --field token` and `vctl kv get
// gitlab --field token` are the same command spelled two ways.
type kvGetOpts struct {
	field   string
	reveal  bool
	version int
}

func addKVGetFlags(cmd *cobra.Command, o *kvGetOpts) {
	f := cmd.Flags()
	f.StringVar(&o.field, "field", "", "print this one value and nothing else (for scripts)")
	f.BoolVar(&o.reveal, "reveal", false, "show the values instead of masking them")
	f.IntVar(&o.version, "version", 0, "read this version instead of the current one")
	cmd.MarkFlagsMutuallyExclusive("field", "reveal")
}

func kvGetCmd(env CommandEnv) *cobra.Command {
	var opts kvGetOpts
	cmd := &cobra.Command{
		Use:   "get [word|path]",
		Short: "Show a secret's keys, and its values when asked",
		Long: `get shows what a secret holds. Name it by full path, or by a word — the way
'vctl ssh' takes a host: a word that matches one secret reads it, a word that
matches several opens a picker, and no argument picks from everything you can
list. Without a terminal a word has to match exactly one.

By default the keys are listed and the values masked, which answers "is the
field there" without putting a credential on the screen. --reveal shows the
values; --field <key> prints one value and nothing else, for a script.

  vctl kv get kv/teams/sre/gitlab-albert
  vctl kv get gitlab-albert --reveal
  TOKEN=$(vctl kv get kv/teams/sre/gitlab-albert --field token)

With -o json the data object is present only under --reveal. Without it the
output carries the key names and no data at all — absent, rather than a
placeholder something might take for the value.`,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: firstArgOnly(completeKVPath(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKVGet(cmd, env, args, opts)
		},
	}
	addKVGetFlags(cmd, &opts)
	return supportsStructuredOutput(gate(cmd, "kv"))
}

// runKVGet is the read behind both `vctl kv [word|path]` and `vctl kv get`.
func runKVGet(cmd *cobra.Command, env CommandEnv, args []string, o kvGetOpts) error {
	format, err := requestedOutput(cmd)
	if err != nil {
		return err
	}
	if o.field != "" && format != outputTable {
		return fmt.Errorf("--field prints one bare value; it does not combine with --output %s", format)
	}
	if o.version < 0 {
		return fmt.Errorf("--version must be a version number, 1 or higher")
	}
	return env.withKV(cmd.Context(), func(a *app.App, kv kvReader) error {
		ctx := cmd.Context()
		path, err := resolveKVPath(ctx, kv, kvRoot(a.Cfg), args)
		if err != nil {
			return err
		}
		sec, err := kv.ReadKVSecret(ctx, path, o.version)
		if err != nil {
			if errors.Is(err, vaultc.ErrKVNotFound) && o.version == 0 {
				// A folder reads as nothing at all. One list tells the
				// operator which of the two they typed.
				if keys, lerr := kv.ListKV(ctx, path); lerr == nil && len(keys) > 0 {
					return fmt.Errorf("%s is a folder, not a secret — 'vctl kv list %s' shows what is under it", path, path)
				}
			}
			return kvError(err, path)
		}
		if o.field != "" {
			v, ok := sec.Data[o.field]
			if !ok {
				has := append(kvKeyNames(sec), sec.NonString...)
				return fmt.Errorf("%s has no field %q (has: %s)", path, o.field, strings.Join(has, ", "))
			}
			fmt.Fprintln(os.Stdout, v)
			return nil
		}
		if format != outputTable {
			return writeStructured(format, newKVGetOutput(sec, o.reveal))
		}
		renderKVSecret(os.Stdout, sec, o.reveal)
		return nil
	})
}

// kvWalkLimit bounds every walk of the tree — search and the picker alike. The
// fleet's mount is a few hundred paths; the cap is for a mount that is not.
const kvWalkLimit = 20000

// resolveKVPath answers "which secret?" the way `vctl ssh` answers "which
// host?": a full path is taken as is, a word is matched against every secret
// the token can list, and a picker settles what a word leaves open.
//
// A word matches anywhere in the path, case-insensitively, and a secret whose
// own name is exactly the word wins when there is one — "gitlab" reads
// kv/teams/sre/gitlab even though a dozen other paths contain the word. That
// is inv.Resolve's rule for hostnames, carried over.
//
// Without a terminal there is no picker and no guess. An ambiguous word is an
// error that names what it matched, because the alternative — a script that
// reads whichever secret sorted first — is a credential handed to the wrong
// place with nobody having chosen it.
func resolveKVPath(ctx context.Context, kv kvReader, root string, args []string) (string, error) {
	query := ""
	if len(args) == 1 {
		query = normalizeKVPath(args[0])
	}
	if strings.Contains(query, "/") {
		return query, nil
	}
	if query == "" && !isTerminal() {
		return "", fmt.Errorf("a secret path is required when there is no terminal to pick at")
	}
	walk, err := walkKV(ctx, kv, root, kvWalkLimit)
	if err != nil {
		return "", kvError(err, root)
	}
	if n := len(walk.Denied); n > 0 {
		ui.Warnf(os.Stderr, "%d folder(s) your token may not list were skipped: %s", n, strings.Join(walk.Denied, ", "))
	}
	if query == "" {
		if len(walk.Secrets) == 0 {
			return "", fmt.Errorf("nothing to choose from under %s", root)
		}
		return pickKVPath(walk.Secrets, root, "Select a secret")
	}
	terms := strings.Fields(query)
	var cands, exact []string
	for _, p := range walk.Secrets {
		if !matchesAllFold(p, terms) {
			continue
		}
		cands = append(cands, p)
		if strings.EqualFold(p[strings.LastIndex(p, "/")+1:], query) {
			exact = append(exact, p)
		}
	}
	switch {
	case len(exact) == 1:
		return exact[0], nil
	case len(cands) == 0:
		return "", fmt.Errorf("no secret matches %q under %s", query, root)
	case len(cands) == 1:
		return cands[0], nil
	}
	if !isTerminal() {
		return "", fmt.Errorf("%q matches %d secrets and there is no terminal to pick at — give the full path:\n  %s",
			query, len(cands), strings.Join(firstN(cands, 15), "\n  "))
	}
	return pickKVPath(cands, root, fmt.Sprintf("Select a secret matching %q", query))
}

// firstN keeps an error message readable when a word matched half the mount.
func firstN(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return append(append([]string{}, list[:n]...), fmt.Sprintf("… and %d more", len(list)-n))
}

// pickKVPath runs the same list picker every other selection in the tool uses.
// Typing filters by every word at once, as search does; ←/→ narrows by folder.
func pickKVPath(paths []string, root, title string) (string, error) {
	match := func(i int, q string) bool { return matchesAllFold(paths[i], strings.Fields(q)) }
	i, err := pickIndexMatch(paths, kvPickGroups(paths, root), match, title)
	if err != nil {
		return "", err
	}
	return paths[i], nil
}

// kvPickGroups is the folder each secret sits under, for the picker's tabs.
func kvPickGroups(paths []string, root string) *listGroups {
	of := make([]string, 0, len(paths))
	for _, p := range paths {
		of = append(of, kvPickGroup(p, root))
	}
	return &listGroups{name: "folder", of: of}
}

// kvPickGroup names a secret's tab: two segments below the mount when there
// are that many (teams/sre), one when there are not (backups). That is the
// depth at which this kind of tree stops being "everything" and starts being
// somebody's — the level ←/→ is for, the way the host picker's tabs are
// datacenters.
func kvPickGroup(path, root string) string {
	rel := strings.TrimPrefix(strings.TrimPrefix(path, root), "/")
	segs := strings.Split(rel, "/")
	switch {
	case len(segs) >= 3:
		return segs[0] + "/" + segs[1]
	case len(segs) == 2:
		return segs[0]
	}
	return ""
}

// renderKVSecret prints a secret the way `vctl status` prints its rows: a
// heading with which version this is, then key by key. Values are masked unless
// reveal is set, and a deleted or destroyed version says so instead of showing
// an empty list that would read as a secret with no fields.
func renderKVSecret(w io.Writer, sec vaultc.KVSecret, reveal bool) {
	var meta []string
	if sec.Version > 0 {
		meta = append(meta, fmt.Sprintf("v%d", sec.Version))
	}
	if !sec.CreatedAt.IsZero() {
		meta = append(meta, sec.CreatedAt.Local().Format("2006-01-02")+" "+ui.StripANSI(ui.Ago(sec.CreatedAt)))
	}
	fmt.Fprintln(w, ui.GroupHeading(sec.Path, strings.Join(meta, " · ")))

	switch {
	case sec.Destroyed:
		fmt.Fprintln(w, ui.Fail("this version was destroyed — its data is gone"))
		return
	case !sec.DeletedAt.IsZero():
		fmt.Fprintln(w, ui.Warn("this version was deleted "+sec.DeletedAt.Local().Format(ui.TimeLayout)+" — its data is hidden until undeleted"))
		return
	}

	rows := make([]ui.KV, 0, len(sec.Data)+len(sec.NonString))
	for _, k := range kvKeyNames(sec) {
		v := ui.Muted(kvMask)
		if reveal {
			v = ui.Value(sec.Data[k])
		}
		rows = append(rows, ui.KV{Key: k, Raw: v})
	}
	for _, k := range sec.NonString {
		rows = append(rows, ui.KV{Key: k, Raw: ui.Muted("(not a string — not rendered here)")})
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, ui.Muted("(no fields)"))
		return
	}
	ui.KVs(w, rows)
	if len(sec.CustomMetadata) > 0 {
		fmt.Fprintln(w, ui.Muted("metadata: "+joinSortedKV(sec.CustomMetadata)))
	}
	if !reveal && len(sec.Data) > 0 {
		fmt.Fprintln(w, ui.Muted("values hidden · --reveal shows them · --field <key> prints one"))
	}
}

// joinSortedKV renders a small map as "k=v k=v" in key order, so two runs of
// the same command print the same line.
func joinSortedKV(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + m[k]
	}
	return strings.Join(parts, " ")
}

// kvWalk is what a walk of the tree found and what it could not reach.
type kvWalk struct {
	// Secrets are full logical paths, sorted.
	Secrets []string
	// Denied are the folders the token may not list, sorted. Reported, not
	// fatal: the answer is what the caller may see and a note of what it may
	// not.
	Denied []string
	// Folders is how many LIST calls answered.
	Folders int
	// Capped is set when the limit stopped the walk before the tree ended.
	Capped bool
}

// kvWalkWorkers bounds the LIST calls in flight. Vault answers one in
// milliseconds and the fleet's tree is a few hundred paths, so this is about
// not looking like a scraper in the audit log, not about speed.
const kvWalkWorkers = 8

// walkKV lists everything under root, one depth at a time.
//
// Level by level rather than a recursive fan-out: a pool whose workers add work
// for the same pool can wait on itself, and the next level's frontier is a
// plain slice the coordinator owns. The tree is shallow — teams, then a name or
// a folder or two — so the sync point per level costs nothing visible.
//
// A 403 on a folder is recorded and the walk goes on. A 404 below the root is a
// folder that vanished between its parent's answer and ours, and is ignored; at
// the root it is the answer, and returned. Anything else aborts, because a
// transport failure half way through would otherwise read as "those paths do
// not exist".
func walkKV(ctx context.Context, kv kvReader, root string, limit int) (kvWalk, error) {
	var out kvWalk
	seen := 0
	frontier := []string{root}
	for depth := 0; len(frontier) > 0 && !out.Capped; depth++ {
		var next []string
		for _, r := range listLevel(ctx, kv, frontier) {
			switch {
			case r.err == nil:
				out.Folders++
			case vaultc.IsPermissionDenied(r.err):
				out.Denied = append(out.Denied, r.dir)
				continue
			case errors.Is(r.err, vaultc.ErrKVNotFound):
				if depth == 0 {
					return kvWalk{}, r.err
				}
				continue
			default:
				return kvWalk{}, r.err
			}
			for _, k := range r.keys {
				if seen++; seen > limit {
					out.Capped = true
					break
				}
				full := r.dir + "/" + strings.TrimSuffix(k, "/")
				if strings.HasSuffix(k, "/") {
					next = append(next, full)
				} else {
					out.Secrets = append(out.Secrets, full)
				}
			}
			if out.Capped {
				break
			}
		}
		frontier = next
	}
	sort.Strings(out.Secrets)
	sort.Strings(out.Denied)
	return out, nil
}

type kvLevelResult struct {
	dir  string
	keys []string
	err  error
}

// listLevel lists every folder of one level, at most kvWalkWorkers at a time,
// and returns the answers in the frontier's order so the walk is deterministic
// whatever the scheduling.
func listLevel(ctx context.Context, kv kvReader, dirs []string) []kvLevelResult {
	results := make([]kvLevelResult, len(dirs))
	sem := make(chan struct{}, kvWalkWorkers)
	var wg sync.WaitGroup
	for i, dir := range dirs {
		wg.Add(1)
		go func(i int, dir string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			keys, err := kv.ListKV(ctx, dir)
			results[i] = kvLevelResult{dir: dir, keys: keys, err: err}
		}(i, dir)
	}
	wg.Wait()
	return results
}

// matchesAllFold reports whether every term appears in s, case-insensitively.
// Terms AND together: "gitlab token" finds paths mentioning both.
func matchesAllFold(s string, terms []string) bool {
	ls := strings.ToLower(s)
	for _, t := range terms {
		if !strings.Contains(ls, strings.ToLower(t)) {
			return false
		}
	}
	return true
}

// kvSearchOutput is the structured shape of a search: what matched, how much
// was looked at, and what could not be.
type kvSearchOutput struct {
	Terms   []string `json:"terms"`
	Under   string   `json:"under"`
	Matches []string `json:"matches"`
	Folders int      `json:"folders_listed"`
	Denied  []string `json:"denied,omitempty"`
	Capped  bool     `json:"capped,omitempty"`
}

func kvSearchCmd(env CommandEnv) *cobra.Command {
	var under string
	var limit int
	cmd := &cobra.Command{
		Use:   "search <word> [word...]",
		Short: "Find secrets whose path contains every word",
		Long: `search walks the KV tree and prints the paths that contain every word given,
case-insensitively. It lists paths and nothing more — no secret is read, so a
search leaves list entries in Vault's audit log and never a read.

Folders your token may not list are skipped and counted, not fatal: the answer
is what you can see, with a note about how much you could not.

  vctl kv search gitlab
  vctl kv search gitlab token            # both words
  vctl kv search oidc --under kv/teams/sre`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := requestedOutput(cmd)
			if err != nil {
				return err
			}
			var terms []string
			for _, a := range args {
				if t := strings.TrimSpace(a); t != "" {
					terms = append(terms, t)
				}
			}
			if len(terms) == 0 {
				return fmt.Errorf("give at least one word to search for")
			}
			if limit <= 0 {
				return fmt.Errorf("--limit must be positive")
			}
			return env.withKV(cmd.Context(), func(a *app.App, kv kvReader) error {
				root := kvRoot(a.Cfg)
				if u := normalizeKVPath(under); u != "" {
					root = u
				}
				walk, err := walkKV(cmd.Context(), kv, root, limit)
				if err != nil {
					return kvError(err, root)
				}
				matches := []string{}
				for _, p := range walk.Secrets {
					if matchesAllFold(p, terms) {
						matches = append(matches, p)
					}
				}
				if format != outputTable {
					return writeStructured(format, kvSearchOutput{
						Terms: terms, Under: root, Matches: matches,
						Folders: walk.Folders, Denied: walk.Denied, Capped: walk.Capped,
					})
				}
				renderKVSearch(os.Stdout, os.Stderr, terms, root, matches, walk)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&under, "under", "", "start the walk here instead of at the mount root")
	cmd.Flags().IntVar(&limit, "limit", 20000, "stop after this many entries have been seen")
	registerCompletion(cmd, "under", completeKVPath(env))
	return supportsStructuredOutput(gate(cmd, "kv"))
}

// renderKVSearch prints the matches with the words that matched picked out, and
// puts what the walk could not reach on stderr: it is about the answer, not
// part of it, and a script reading stdout should get paths alone.
func renderKVSearch(w, errw io.Writer, terms []string, root string, matches []string, walk kvWalk) {
	fmt.Fprintln(w, ui.GroupHeading(
		fmt.Sprintf("search %q under %s", strings.Join(terms, " "), root),
		fmt.Sprintf("%d matches · %d folders listed", len(matches), walk.Folders)))
	for _, m := range matches {
		fmt.Fprintf(w, "  %s\n", highlightFold(m, terms))
	}
	if len(matches) == 0 {
		fmt.Fprintln(w, ui.Muted("  no matches"))
	}
	if n := len(walk.Denied); n > 0 {
		ui.Warnf(errw, "%d folder(s) your token may not list were skipped: %s", n, strings.Join(walk.Denied, ", "))
	}
	if walk.Capped {
		ui.Warnf(errw, "stopped at --limit before the tree ended — narrow with --under or raise --limit")
	}
}

// highlightFold renders s with every occurrence of every term picked out, so
// the eye lands on why a path matched. Case-insensitive, like the match. A
// string whose lower-casing changes length is printed plain rather than
// mis-aligned — it does not happen to Vault paths, and a wrong highlight is
// worse than none.
func highlightFold(s string, terms []string) string {
	rs := []rune(s)
	lower := []rune(strings.ToLower(s))
	if len(lower) != len(rs) {
		return ui.Value(s)
	}
	mark := make([]bool, len(rs))
	for _, t := range terms {
		lt := []rune(strings.ToLower(t))
		if len(lt) == 0 {
			continue
		}
		for i := 0; i+len(lt) <= len(lower); i++ {
			if slices.Equal(lower[i:i+len(lt)], lt) {
				for j := i; j < i+len(lt); j++ {
					mark[j] = true
				}
			}
		}
	}
	var b strings.Builder
	for i := 0; i < len(rs); {
		j := i + 1
		for j < len(rs) && mark[j] == mark[i] {
			j++
		}
		seg := string(rs[i:j])
		if mark[i] {
			b.WriteString(ui.Title(seg))
		} else {
			b.WriteString(ui.Value(seg))
		}
		i = j
	}
	return b.String()
}

// completeKVPath offers the entries under whatever folder is being typed.
//
// One LIST per Tab — the parent of the partial path — and only with a token
// already on disk: a completion must never be what opens a login. A folder
// completes with its slash and no space, so the next Tab descends into it; once
// a secret is among the candidates the space comes back.
func completeKVPath(env CommandEnv) completer {
	return func(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		defer silenceStderr()()
		a, err := env.newApp()
		if err != nil || a.WouldPromptForLogin() {
			return noCompletions()
		}
		parent := cmd.Context()
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, completionBudget)
		defer cancel()
		if err := a.EnsureLogin(ctx); err != nil {
			return noCompletions()
		}
		root := kvRoot(a.Cfg)
		typed := strings.TrimLeft(toComplete, "/")
		cut := strings.LastIndex(typed, "/")
		if cut < 0 {
			// Still typing the mount.
			if hasPrefixFold(root, typed) {
				return []string{root + "/"}, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
			}
			return noCompletions()
		}
		dir, partial := typed[:cut], typed[cut+1:]
		keys, err := a.Vault.ListKV(ctx, dir)
		if err != nil {
			return noCompletions()
		}
		var out []string
		directive := cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
		for _, k := range keys {
			if !hasPrefixFold(k, partial) {
				continue
			}
			out = append(out, dir+"/"+k)
			if !strings.HasSuffix(k, "/") {
				directive = cobra.ShellCompDirectiveNoFileComp
			}
		}
		if len(out) == 0 {
			return noCompletions()
		}
		return out, directive
	}
}

// firstArgOnly limits a positional completer to the first argument, for
// commands that take exactly one: past it there is nothing to offer.
func firstArgOnly(fn completer) completer {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return noCompletions()
		}
		return fn(cmd, args, toComplete)
	}
}
