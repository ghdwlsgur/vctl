package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/kubeconfig"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// k8sExecCmd wires `k8s exec`; the work is runK8sExec.
func k8sExecCmd(env cmdkit.Env) *cobra.Command {
	var opts k8sExecOptions
	cmd := &cobra.Command{
		Use:   "exec <cluster> -- <command> [args...]",
		Short: "Run one command against a cluster with a throwaway kubeconfig",
		Long: `exec writes a kubeconfig holding only this cluster's vctl entries into a
private temporary directory, runs the command with KUBECONFIG pointing at it,
and removes it afterwards. Nothing in your own kubeconfig changes.

  vctl k8s exec core-sre -- kubectl get pods -A
  vctl k8s exec core-sre --role admin -- helm list -A`,
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: firstArgOnly(completeK8sCluster(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runK8sExec(cmd, env, args[0], args[1:], opts)
		},
	}
	cmd.Flags().StringVar(&opts.role, "role", "viewer", "access tier: viewer, editor or admin")
	cmd.Flags().StringVar(&opts.proxy, "proxy", defaultK8sProxy, "proxy-url for reach=tunnel clusters; empty writes none")
	cmdkit.RegisterCompletion(cmd, "role", completeK8sRole)
	return cmd
}

type k8sExecOptions struct {
	role, proxy string
}

func runK8sExec(cmd *cobra.Command, env cmdkit.Env, name string, command []string, opts k8sExecOptions) error {
	if err := validK8sRole(opts.role); err != nil {
		return err
	}
	return k8sClusterFor(cmd.Context(), env, name, func(_ *app.App, c store.K8sCluster) error {
		dir, err := os.MkdirTemp("", "vctl-k8s-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		path := filepath.Join(dir, "kubeconfig")
		f := &kubeconfig.File{APIVersion: "v1", Kind: "Config"}
		cluster, user := k8sKubeconfigEntries(c, opts.role, opts.proxy)
		f.SetCluster("vctl-"+c.Name, cluster)
		f.SetUser("vctl-"+c.Name+"-"+opts.role, user)
		f.SetContext(c.Name, map[string]any{"cluster": "vctl-" + c.Name, "user": "vctl-" + c.Name + "-" + opts.role})
		f.Use(c.Name)
		if err := f.Save(path); err != nil {
			return err
		}
		child := exec.CommandContext(cmd.Context(), command[0], command[1:]...)
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		child.Env = append(os.Environ(), "KUBECONFIG="+path)
		if err := child.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return &CommandExitError{Code: ee.ExitCode()}
			}
			return fmt.Errorf("%s: %w", command[0], err)
		}
		return nil
	})
}
