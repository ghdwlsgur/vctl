package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

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
	warnDeniedFolders(os.Stderr, walk.Denied)
	if query == "" {
		if len(walk.Secrets) == 0 {
			return "", fmt.Errorf("nothing to choose from under %s", root)
		}
		return pickKVPath(walk.Secrets, root, "Select a secret")
	}
	cands, exact := matchKVWord(walk.Secrets, query)
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

// matchKVWord sorts the secrets a word matches into all of them and the ones
// it names outright. Every space-separated term has to appear somewhere in the
// path; the name is the path's last segment.
func matchKVWord(secrets []string, query string) (cands, exact []string) {
	terms := strings.Fields(query)
	for _, p := range secrets {
		if !matchesAllFold(p, terms) {
			continue
		}
		cands = append(cands, p)
		if strings.EqualFold(lastSegment(p), query) {
			exact = append(exact, p)
		}
	}
	return cands, exact
}

// lastSegment is a secret's own name: what follows the final slash.
func lastSegment(p string) string {
	return p[strings.LastIndex(p, "/")+1:]
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
