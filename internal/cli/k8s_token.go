package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/securefile"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// k8sTokenCmd wires the flags for `k8s token`; the work is runK8sToken. It is
// the kubectl exec credential plugin: kubectl runs it, reads one JSON document
// from stdout, and uses the token in it. Everything for a person goes to
// stderr — a stray line on stdout is a broken kubectl.
func k8sTokenCmd(env cmdkit.Env) *cobra.Command {
	var opts k8sTokenOptions
	cmd := &cobra.Command{
		Use:   "token --cluster <name> [--role viewer|editor|admin]",
		Short: "Mint a short-lived token for a cluster (kubectl exec credential plugin)",
		Long: `token prints an ExecCredential for kubectl. The token comes from Vault: for
source vault:<mount>, a ServiceAccount token minted by the Kubernetes secrets
engine under <mount>/creds/<role> (short TTL; the service account is created
per lease, so the cluster's own audit log names the person); for source
kv:<path>, the 'token' field of that secret, as is.

Minted tokens are cached in ~/.vctl/k8s (mode 0600) until two minutes before
they expire, so twenty kubectl calls are one Vault call. Each mint is recorded
in the access log like an SSH session. 'vctl k8s use' writes the exec entry
that calls this; nobody types it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runK8sToken(cmd, env, opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.cluster, "cluster", "", "cluster name (inventory)")
	f.StringVar(&opts.role, "role", "viewer", "access tier")
	f.StringVar(&opts.source, "source", "", "token source, as `k8s use` wrote it (default: look the cluster up)")
	f.StringVar(&opts.server, "server", "", "API server, for the audit row (default: look the cluster up)")
	f.DurationVar(&opts.ttl, "ttl", 0, "requested token TTL; 0 takes the role's default")
	f.BoolVar(&opts.noCache, "no-cache", false, "always mint, never read or write the local cache")
	_ = cmd.MarkFlagRequired("cluster")
	cmdkit.RegisterCompletion(cmd, "role", completeK8sRole)
	cmdkit.RegisterCompletion(cmd, "cluster", completeK8sCluster(env))
	return cmd
}

type k8sTokenOptions struct {
	cluster, role, source, server string
	ttl                           time.Duration
	noCache                       bool
}

// k8sToken is one minted token and when it stops working.
type k8sToken struct {
	Token          string    `json:"token"`
	ExpiresAt      time.Time `json:"expires_at"`
	ServiceAccount string    `json:"service_account,omitempty"`
	Server         string    `json:"server,omitempty"`
}

// k8sIssuer is the Vault surface a mint needs; *vaultc.Client satisfies it and
// tests use a fake.
type k8sIssuer interface {
	KubernetesCreds(ctx context.Context, mount, role, namespace string, ttl time.Duration) (vaultc.K8sCreds, error)
	ReadKV(ctx context.Context, path string) (map[string]string, error)
}

var _ k8sIssuer = (*vaultc.Client)(nil)

func runK8sToken(cmd *cobra.Command, env cmdkit.Env, opts k8sTokenOptions) error {
	if err := validK8sRole(opts.role); err != nil {
		return err
	}
	ctx := cmd.Context()
	return env.WithApp(func(a *app.App) error {
		if err := a.EnsureLogin(ctx); err != nil {
			return err
		}
		source, server := opts.source, opts.server
		if source == "" {
			c, err := k8sClusterViaStore(ctx, a, opts.cluster)
			if err != nil {
				return err
			}
			source, server = c.TokenSource, c.APIServer
		}
		cache := k8sTokenCache{dir: filepath.Join(a.Cfg.StateDir, "k8s"), disabled: opts.noCache}
		tok, cached, err := cache.get(opts.cluster, opts.role, time.Now())
		if err != nil {
			ui.Warnf(os.Stderr, "token cache: %v", err)
		}
		if !cached {
			identity, _ := a.Vault.Identity(ctx)
			tok, err = issueK8sToken(ctx, a.Vault, source, opts.role, opts.ttl)
			logK8sAccess(ctx, a, identity, opts.cluster, opts.role, server, err)
			if err != nil {
				return err
			}
			tok.Server = server
			if err := cache.put(opts.cluster, opts.role, tok); err != nil {
				ui.Warnf(os.Stderr, "token cache: %v", err)
			}
		}
		out, err := execCredentialJSON(tok)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return err
	})
}

// k8sClusterViaStore is the slow path: a token asked for by hand, without
// the source `k8s use` bakes into the kubeconfig.
func k8sClusterViaStore(ctx context.Context, a *app.App, name string) (store.K8sCluster, error) {
	st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
	if err != nil {
		return store.K8sCluster{}, err
	}
	defer st.Close()
	return k8sLookup(ctx, st, name)
}

// issueK8sToken mints from the source `k8s cluster set --source` declared.
func issueK8sToken(ctx context.Context, v k8sIssuer, source, role string, ttl time.Duration) (k8sToken, error) {
	kind, ref, ok := strings.Cut(source, ":")
	if !ok || ref == "" {
		return k8sToken{}, fmt.Errorf("token source %q is neither vault:<mount> nor kv:<path>", source)
	}
	switch kind {
	case "vault":
		creds, err := v.KubernetesCreds(ctx, ref, role, k8sAccessNamespace, ttl)
		if err != nil {
			return k8sToken{}, err
		}
		if creds.TTL <= 0 {
			return k8sToken{}, fmt.Errorf("%s: the engine returned a token with no TTL", ref)
		}
		return k8sToken{Token: creds.Token, ExpiresAt: time.Now().Add(creds.TTL), ServiceAccount: creds.ServiceAccount + "@" + creds.Namespace}, nil
	case "kv":
		sec, err := v.ReadKV(ctx, ref)
		if err != nil {
			return k8sToken{}, err
		}
		if sec["token"] == "" {
			return k8sToken{}, fmt.Errorf("%s has no token field", ref)
		}
		// A stand-in token has no known expiry: kubectl gets it without one and
		// asks again next time, and it is not cached.
		return k8sToken{Token: sec["token"]}, nil
	default:
		return k8sToken{}, fmt.Errorf("token source %q is neither vault:<mount> nor kv:<path>", source)
	}
}

// execCredentialJSON is the document kubectl reads: apiVersion, kind, and a
// status with the token and — when known — its expiry.
func execCredentialJSON(tok k8sToken) ([]byte, error) {
	status := map[string]any{"token": tok.Token}
	if !tok.ExpiresAt.IsZero() {
		status["expirationTimestamp"] = tok.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return json.Marshal(map[string]any{
		"apiVersion": "client.authentication.k8s.io/v1",
		"kind":       "ExecCredential",
		"status":     status,
	})
}

// k8sTokenCache keeps minted tokens on disk, 0600, keyed by cluster and role.
// A token that has no expiry is never cached; one within two minutes of its
// expiry is treated as gone, so a kubectl call never gets a token that dies
// mid-request.
type k8sTokenCache struct {
	dir      string
	disabled bool
}

const k8sTokenSlack = 2 * time.Minute

func (c k8sTokenCache) path(cluster, role string) string {
	return filepath.Join(c.dir, cluster+"-"+role+".json")
}

func (c k8sTokenCache) get(cluster, role string, now time.Time) (k8sToken, bool, error) {
	if c.disabled {
		return k8sToken{}, false, nil
	}
	raw, err := os.ReadFile(c.path(cluster, role))
	if errors.Is(err, os.ErrNotExist) {
		return k8sToken{}, false, nil
	}
	if err != nil {
		return k8sToken{}, false, err
	}
	var tok k8sToken
	if err := json.Unmarshal(raw, &tok); err != nil || tok.Token == "" || tok.ExpiresAt.IsZero() {
		return k8sToken{}, false, nil // unreadable is the same as absent
	}
	if now.Add(k8sTokenSlack).After(tok.ExpiresAt) {
		return k8sToken{}, false, nil
	}
	return tok, true, nil
}

func (c k8sTokenCache) put(cluster, role string, tok k8sToken) error {
	if c.disabled || tok.ExpiresAt.IsZero() {
		return nil
	}
	if err := securefile.EnsurePrivateDir(c.dir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	return securefile.WriteAtomic(c.path(cluster, role), raw, 0o600)
}

// logK8sAccess records a mint like an SSH access: who, which cluster, which
// tier, and whether it worked. Best effort; a failed write spools.
func logK8sAccess(ctx context.Context, a *app.App, identity, cluster, role, server string, cause error) {
	e := store.AccessEntry{
		VaultUser: identity, Hostname: cluster, ClientUser: "k8s-" + role, TargetAddr: server,
		SignedAt: time.Now(), OK: cause == nil,
	}
	if cause != nil {
		e.Error = cause.Error()
	}
	if err := a.LogAccess(ctx, e); err != nil {
		ui.Warnf(os.Stderr, "access log: %v", err)
	}
}
