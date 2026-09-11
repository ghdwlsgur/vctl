package cli

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/kubeconfig"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// defaultK8sProxy is where `vctl wg connect` serves SOCKS5 by default.
const defaultK8sProxy = "socks5://127.0.0.1:1080"

// k8sUseCmd wires the flags for `k8s use`; the work is runK8sUse.
func k8sUseCmd(env cmdkit.Env) *cobra.Command {
	var opts k8sUseOptions
	cmd := &cobra.Command{
		Use:   "use <cluster>",
		Short: "Write a kubeconfig context for a cluster and make it current",
		Long: `use writes three kubeconfig entries and selects the context:

  cluster vctl-<name>          server, CA, tls-server-name, and — for reach=tunnel —
                               proxy-url pointing at vctl wg connect's SOCKS proxy
  user    vctl-<name>-<role>   an exec plugin: kubectl runs 'vctl k8s token …' and
                               gets a short-lived token; nothing is stored in the file
  context <name>               the two above

Everything else in the file is left as it was. A context called <name> that
is not vctl's is refused; --context picks another name.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: firstArgOnly(completeK8sCluster(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runK8sUse(cmd, env, args[0], opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.role, "role", "viewer", "access tier: viewer, editor or admin")
	f.StringVar(&opts.kubeconfig, "kubeconfig", "", "file to edit (default: first KUBECONFIG entry, else ~/.kube/config)")
	f.StringVar(&opts.context, "context", "", "context name to write (default: the cluster name)")
	f.StringVar(&opts.proxy, "proxy", defaultK8sProxy, "proxy-url for reach=tunnel clusters; empty writes none")
	cmdkit.RegisterCompletion(cmd, "role", completeK8sRole)
	return cmd
}

type k8sUseOptions struct {
	role, kubeconfig, context, proxy string
}

func runK8sUse(cmd *cobra.Command, env cmdkit.Env, name string, opts k8sUseOptions) error {
	if err := validK8sRole(opts.role); err != nil {
		return err
	}
	return k8sClusterFor(cmd.Context(), env, name, func(_ *app.App, c store.K8sCluster) error {
		path := opts.kubeconfig
		if path == "" {
			var err error
			if path, err = kubeconfig.DefaultPath(); err != nil {
				return err
			}
		}
		f, err := kubeconfig.Load(path)
		if err != nil {
			return err
		}
		ctxName := opts.context
		if ctxName == "" {
			ctxName = c.Name
		}
		if existing, ok := f.Context(ctxName); ok {
			if cl, _ := existing["cluster"].(string); !strings.HasPrefix(cl, "vctl-") {
				return fmt.Errorf("context %q already exists in %s and is not vctl's (cluster %q); pick another with --context", ctxName, path, cl)
			}
		}
		cluster, user := k8sKubeconfigEntries(c, opts.role, opts.proxy)
		f.SetCluster("vctl-"+c.Name, cluster)
		f.SetUser("vctl-"+c.Name+"-"+opts.role, user)
		f.SetContext(ctxName, map[string]any{"cluster": "vctl-" + c.Name, "user": "vctl-" + c.Name + "-" + opts.role})
		f.Use(ctxName)
		if err := f.Save(path); err != nil {
			return err
		}
		ui.Successf(os.Stderr, "context %s → %s as %s (%s)", ctxName, c.APIServer, opts.role, path)
		if c.Reach == "tunnel" && opts.proxy != "" {
			ui.Infof(os.Stderr, "reach is tunnel: kubectl goes through %s and starts `vctl wg connect` in the background when it is not up (`vctl wg status` / `vctl wg down`)", opts.proxy)
		}
		ui.Infof(os.Stderr, "try: kubectl get nodes")
		return nil
	})
}

func validK8sRole(role string) error {
	for _, r := range k8sRoles {
		if r == role {
			return nil
		}
	}
	return fmt.Errorf("role %q is not one of %s", role, strings.Join(k8sRoles, ", "))
}

// k8sKubeconfigEntries renders the cluster and user entries `use` writes. The
// user is an exec plugin whose arguments carry everything `k8s token` needs —
// including the proxy to bring up — so kubectl's call does not touch the
// inventory database.
func k8sKubeconfigEntries(c store.K8sCluster, role, proxy string) (cluster, user map[string]any) {
	cluster = map[string]any{"server": c.APIServer}
	if c.CAPEM != "" {
		cluster["certificate-authority-data"] = base64.StdEncoding.EncodeToString([]byte(c.CAPEM))
	}
	if c.TLSServerName != "" {
		cluster["tls-server-name"] = c.TLSServerName
	}
	if c.Reach == "tunnel" && proxy != "" {
		cluster["proxy-url"] = proxy
	}
	args := []string{"k8s", "token", "--cluster", c.Name, "--role", role, "--source", c.TokenSource, "--server", c.APIServer}
	if c.Reach == "tunnel" && proxy != "" {
		// The plugin brings the tunnel up on demand when this proxy is not answering.
		args = append(args, "--proxy", proxy)
	}
	user = map[string]any{"exec": map[string]any{
		"apiVersion":         "client.authentication.k8s.io/v1",
		"command":            "vctl",
		"args":               args,
		"interactiveMode":    "IfAvailable",
		"provideClusterInfo": false,
		"installHint":        "vctl is the fleet CLI: brew install ghdwlsgur/vctl/vctl",
	}}
	return cluster, user
}

// completeK8sRole offers the fixed access tiers.
func completeK8sRole(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var out []string
	for _, r := range k8sRoles {
		if cmdkit.HasPrefixFold(r, toComplete) {
			out = append(out, r)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completeK8sCluster offers inventory names.
func completeK8sCluster(env cmdkit.Env) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var names []string
		_ = env.WithStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
			cs, err := st.K8sClusters(cmd.Context())
			for _, c := range cs {
				if cmdkit.HasPrefixFold(c.Name, toComplete) {
					names = append(names, c.Name)
				}
			}
			return err
		})
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}
