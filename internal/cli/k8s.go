package cli

import (
	"context"
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// The Kubernetes surface splits a kubeconfig into the two things it mixes.
// Where a cluster is — API server, CA, how to reach it, where its tokens come
// from — is inventory, in Postgres, shared with everyone who can list hosts.
// Who you are to it is never stored: `vctl k8s token` mints a short-lived
// ServiceAccount token from Vault per use, and `vctl k8s use` writes a
// kubeconfig entry that holds only the address, the CA and an instruction to
// call vctl. The file on disk carries no credential.
//
// A cluster reached through the fleet's WireGuard hub gets proxy-url pointed
// at `vctl wg connect`'s SOCKS proxy, so a new laptop is three commands away
// from any cluster: vctl login, vctl wg connect, vctl k8s use <cluster>.

// k8sAccessNamespace is where Vault's Kubernetes secrets engine creates the
// per-lease service accounts. deploy/k8s/vault-issuer.yaml creates it.
const k8sAccessNamespace = "vctl-access"

// k8sRoles are the access tiers a token can be minted for; each is a role
// under the cluster's Vault mount, bound to the matching built-in ClusterRole.
var k8sRoles = []string{"viewer", "editor", "admin"}

// k8sCmd wires `vctl k8s`; the bare command lists, like `vctl dns`.
func k8sCmd(env cmdkit.Env) *cobra.Command {
	var opts k8sListOptions
	cmd := &cobra.Command{
		Use:   "k8s",
		Short: "Kubernetes clusters: inventory, kubeconfig contexts, short-lived tokens",
		Long: `k8s is how a person reaches a cluster with nothing but vctl.

  vctl k8s                              the clusters, where they are, how tokens come
  vctl k8s use core-sre [--role admin]  write a kubeconfig context that calls vctl for tokens
  kubectl get nodes                     kubectl → vctl k8s token → Vault → short-lived token
  vctl k8s exec core-sre -- kubectl get pods   one command with a throwaway kubeconfig

  vctl k8s cluster set <name> --api https://… --source vault:kubernetes/<name> …
  vctl k8s cluster set <name> --from-context <kubectl-context>
  vctl k8s cluster rm <name>

A cluster reached through the WireGuard hub (reach=tunnel) needs 'vctl wg connect'
running; its kubeconfig entry carries proxy-url for that proxy. Tokens come from
Vault's Kubernetes secrets engine (source vault:<mount>, roles viewer/editor/admin)
or, for a cluster not yet wired to it, from a KV secret's token field (kv:<path>).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runK8sList(cmd, env, opts)
		},
	}
	cmd.Flags().BoolVar(&opts.asJSON, "json", false, "machine-readable listing")
	cmd.AddCommand(
		cmdkit.Gate(k8sListCmd(env), "k8s"),
		k8sClusterCmd(env),
		cmdkit.Gate(k8sUseCmd(env), "k8s"),
		cmdkit.Gate(k8sTokenCmd(env), "k8s-access"),
		cmdkit.Gate(k8sExecCmd(env), "k8s"),
	)
	return cmdkit.SupportsStructuredOutput(cmdkit.Gate(cmd, "k8s"))
}

type k8sListOptions struct {
	asJSON bool
}

func k8sListCmd(env cmdkit.Env) *cobra.Command {
	var opts k8sListOptions
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List the clusters in the inventory",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runK8sList(cmd, env, opts)
		},
	}
	cmd.Flags().BoolVar(&opts.asJSON, "json", false, "machine-readable listing")
	return cmdkit.SupportsStructuredOutput(cmd)
}

// k8sClusterRow is the listing's structured form.
type k8sClusterRow struct {
	Name        string `json:"name" yaml:"name"`
	Site        string `json:"site,omitempty" yaml:"site,omitempty"`
	APIServer   string `json:"api_server" yaml:"api_server"`
	Reach       string `json:"reach" yaml:"reach"`
	TokenSource string `json:"token_source" yaml:"token_source"`
	Note        string `json:"note,omitempty" yaml:"note,omitempty"`
}

func runK8sList(cmd *cobra.Command, env cmdkit.Env, opts k8sListOptions) error {
	format, err := cmdkit.CommandOutput(cmd, opts.asJSON)
	if err != nil {
		return err
	}
	return env.WithStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
		clusters, err := st.K8sClusters(cmd.Context())
		if err != nil {
			return err
		}
		rows := make([]k8sClusterRow, 0, len(clusters))
		for _, c := range clusters {
			rows = append(rows, k8sClusterRow{Name: c.Name, Site: c.Site, APIServer: c.APIServer, Reach: c.Reach, TokenSource: c.TokenSource, Note: c.Note})
		}
		if format != cmdkit.OutputTable {
			return cmdkit.WriteStructured(format, rows)
		}
		if len(rows) == 0 {
			ui.Infof(os.Stdout, "no clusters declared yet — `vctl k8s cluster set <name> --from-context <kubectl-context> --source …`")
			return nil
		}
		table := make([][]string, 0, len(rows))
		for _, r := range rows {
			table = append(table, []string{r.Name, ui.OrDash(r.Site), r.APIServer, r.Reach, r.TokenSource, ui.OrDash(r.Note)})
		}
		return ui.Table(os.Stdout, []string{"name", "site", "api server", "reach", "tokens", "note"}, table)
	})
}

// k8sLookup reads one cluster from the inventory, with the not-found case
// phrased for the person typing.
func k8sLookup(ctx context.Context, st *store.Store, name string) (store.K8sCluster, error) {
	c, err := st.K8sCluster(ctx, name)
	if err != nil {
		return store.K8sCluster{}, err
	}
	return c, nil
}
