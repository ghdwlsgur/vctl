package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/kubeconfig"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func k8sClusterCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Declare or remove clusters in the inventory (admin)",
	}
	cmd.AddCommand(cmdkit.Gate(k8sClusterSetCmd(env), "k8s-inventory"), cmdkit.Gate(k8sClusterRmCmd(env), "k8s-inventory"))
	return cmd
}

// k8sClusterSetCmd wires the flags for `k8s cluster set`; the work is runK8sClusterSet.
func k8sClusterSetCmd(env cmdkit.Env) *cobra.Command {
	var opts k8sClusterSetOptions
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Declare a cluster, or change fields of one",
		Long: `set declares a cluster in the inventory. Only the flags given are written;
a field of an existing cluster that is not named keeps its value.

  vctl k8s cluster set core-sre --from-context innogrid-core-sre \
      --site seoul --source vault:kubernetes/core-sre
  vctl k8s cluster set edge-lab --api https://10.20.0.5:6443 --ca @ca.pem \
      --reach direct --source kv:kv/teams/sre/k8s/edge-lab

--from-context copies the API server, CA and tls-server-name out of a context in
your own kubeconfig, so a cluster you already reach is declared in one line.
--source names where tokens come from: vault:<mount> for Vault's Kubernetes
secrets engine, or kv:<path> for a KV secret whose 'token' field is used as is.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runK8sClusterSet(cmd, env, args[0], opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.api, "api", "", "API server URL, https://host:port")
	f.StringVar(&opts.site, "site", "", "site the cluster lives in")
	f.StringVar(&opts.ca, "ca", "", "cluster CA: PEM text, @file, or - for stdin (empty keeps the current value)")
	f.StringVar(&opts.serverName, "server-name", "", "tls-server-name when the API address is not in the certificate")
	f.StringVar(&opts.reach, "reach", "", "tunnel (through vctl wg connect) or direct")
	f.StringVar(&opts.source, "source", "", "token source: vault:<mount> or kv:<path>")
	f.StringVar(&opts.note, "note", "", "free text")
	f.StringVar(&opts.fromContext, "from-context", "", "copy api/ca/server-name from this kubectl context")
	return cmd
}

type k8sClusterSetOptions struct {
	api, site, ca, serverName, reach, source, note, fromContext string
}

func runK8sClusterSet(cmd *cobra.Command, env cmdkit.Env, name string, opts k8sClusterSetOptions) error {
	ctx := cmd.Context()
	changed := cmd.Flags().Changed
	return env.WithStore(ctx, true, func(a *app.App, st *store.Store) error {
		c, err := st.K8sCluster(ctx, name)
		switch {
		case err == nil:
		case errors.Is(err, store.ErrK8sClusterNotFound):
			c = store.K8sCluster{Name: name, Reach: "tunnel"}
		default:
			return err
		}
		if opts.fromContext != "" {
			files, err := loadKubeconfigs()
			if err != nil {
				return err
			}
			imp, err := k8sImportContext(files, opts.fromContext)
			if err != nil {
				return err
			}
			c.APIServer, c.CAPEM, c.TLSServerName = imp.server, imp.caPEM, imp.serverName
		}
		if changed("api") {
			c.APIServer = opts.api
		}
		if changed("site") {
			c.Site = opts.site
		}
		if changed("ca") {
			pem, err := readValueArg(opts.ca, cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("--ca: %w", err)
			}
			c.CAPEM = pem
		}
		if changed("server-name") {
			c.TLSServerName = opts.serverName
		}
		if changed("reach") {
			c.Reach = opts.reach
		}
		if changed("source") {
			c.TokenSource = opts.source
		}
		if changed("note") {
			c.Note = opts.note
		}
		if c.TokenSource == "" {
			return errors.New("--source is required for a new cluster: vault:<mount> or kv:<path>")
		}
		if c.UpdatedBy, err = a.Vault.Identity(ctx); err != nil {
			return err
		}
		if err := st.K8sClusterUpsert(ctx, c); err != nil {
			return err
		}
		ui.Successf(os.Stderr, "%s: %s · reach %s · tokens %s", c.Name, c.APIServer, c.Reach, c.TokenSource)
		return nil
	})
}

func k8sClusterRmCmd(env cmdkit.Env) *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name>",
		Short: "Remove a cluster from the inventory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.WithStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.K8sClusterDelete(cmd.Context(), args[0]); err != nil {
					return err
				}
				ui.Successf(os.Stderr, "%s removed from the inventory (kubeconfig entries are left to you)", args[0])
				return nil
			})
		},
	}
}

// readValueArg is the value convention `kv set` uses: @file, - for stdin, or
// the text itself.
func readValueArg(v string, stdin io.Reader) (string, error) {
	switch {
	case v == "-":
		b, err := io.ReadAll(stdin)
		return string(b), err
	case strings.HasPrefix(v, "@"):
		b, err := os.ReadFile(v[1:])
		return string(b), err
	default:
		return v, nil
	}
}

// loadKubeconfigs reads every file kubectl itself would consult.
func loadKubeconfigs() ([]*kubeconfig.File, error) {
	paths := []string{}
	if env := os.Getenv("KUBECONFIG"); env != "" {
		for _, p := range strings.Split(env, string(os.PathListSeparator)) {
			if p != "" {
				paths = append(paths, p)
			}
		}
	}
	if len(paths) == 0 {
		p, err := kubeconfig.DefaultPath()
		if err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}
	var out []*kubeconfig.File
	for _, p := range paths {
		f, err := kubeconfig.Load(p)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// k8sImport is what --from-context takes out of a kubeconfig.
type k8sImport struct {
	server, caPEM, serverName string
}

// k8sImportContext finds a context by name across the loaded kubeconfigs and
// returns its cluster's address, CA and tls-server-name. Credentials are not
// read: the point of the inventory is that they never leave the user entry.
func k8sImportContext(files []*kubeconfig.File, ctxName string) (k8sImport, error) {
	for _, f := range files {
		ctx, ok := f.Context(ctxName)
		if !ok {
			continue
		}
		clusterName, _ := ctx["cluster"].(string)
		cl, ok := f.Cluster(clusterName)
		if !ok {
			return k8sImport{}, fmt.Errorf("context %s names cluster %q, which is not in the same kubeconfig", ctxName, clusterName)
		}
		out := k8sImport{}
		out.server, _ = cl["server"].(string)
		out.serverName, _ = cl["tls-server-name"].(string)
		if data, ok := cl["certificate-authority-data"].(string); ok && data != "" {
			raw, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				return k8sImport{}, fmt.Errorf("context %s: certificate-authority-data is not base64: %w", ctxName, err)
			}
			out.caPEM = string(raw)
		} else if file, ok := cl["certificate-authority"].(string); ok && file != "" {
			raw, err := os.ReadFile(file)
			if err != nil {
				return k8sImport{}, fmt.Errorf("context %s: certificate-authority: %w", ctxName, err)
			}
			out.caPEM = string(raw)
		}
		if out.server == "" {
			return k8sImport{}, fmt.Errorf("context %s: its cluster has no server", ctxName)
		}
		return out, nil
	}
	return k8sImport{}, fmt.Errorf("no context %q in the kubeconfig(s) kubectl would read", ctxName)
}

// k8sClusterFor is the read every access command starts with.
func k8sClusterFor(ctx context.Context, env cmdkit.Env, name string, fn func(*app.App, store.K8sCluster) error) error {
	return env.WithStore(ctx, false, func(a *app.App, st *store.Store) error {
		c, err := k8sLookup(ctx, st, name)
		if err != nil {
			return err
		}
		return fn(a, c)
	})
}
