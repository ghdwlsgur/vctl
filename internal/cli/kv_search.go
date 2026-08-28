package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

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
				if seen == limit {
					out.Capped = true
					break
				}
				seen++
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
	slices.Sort(out.Secrets)
	slices.Sort(out.Denied)
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
	cmd.Flags().IntVar(&limit, "limit", kvWalkLimit, "stop after this many entries have been seen")
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
	warnDeniedFolders(errw, walk.Denied)
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
