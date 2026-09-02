package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// kvListing is the structured shape of one level: Vault's own, folders with a
// trailing slash, so anything already reading `vault kv list -format=json`
// reads this.
type kvListing struct {
	Path string   `json:"path"`
	Keys []string `json:"keys"`
}

func kvListCmd(env cmdkit.Env) *cobra.Command {
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
			format, err := cmdkit.RequestedOutput(cmd)
			if err != nil {
				return err
			}
			return withKV(env, cmd.Context(), func(a *app.App, kv kvReader) error {
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
				if format != cmdkit.OutputTable {
					return cmdkit.WriteStructured(format, kvListing{Path: path, Keys: keys})
				}
				renderKVListing(os.Stdout, path, keys)
				return nil
			})
		},
	}
	return cmdkit.SupportsStructuredOutput(cmdkit.Gate(cmd, "kv"))
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
