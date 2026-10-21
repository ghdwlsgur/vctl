// Package vsphere is the `vctl vsphere` subtree.
//
// It lives apart from package cli on purpose: govmomi registers every vSphere
// type at init, about 11MB of binary that the linker cannot drop. The node-agent
// binary runs on every host in the fleet and imports package cli, so the poller
// is wired into the operator binary only, which the one polling host runs.
package vsphere

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
	vs "github.com/ghdwlsgur/vctl/internal/vsphere"
)

// pollTimeout bounds one host: login, three property reads, logout. An
// ESXi host that is powered off must not hold the rest of the list.
const pollTimeout = 60 * time.Second

// Cmd is the `vsphere` parent. version names the binary in the heartbeat's
// agent_version, as "vsphere-poll/<version>".
func Cmd(env cmdkit.Env, version func() string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vsphere",
		Short: "Standalone ESXi hosts, observed through the vSphere API",
	}
	cmd.AddCommand(pollCmd(env, version))
	return cmd
}

type pollOptions struct {
	version  string
	hosts    []string
	insecure bool
	dryRun   bool
}

func pollCmd(env cmdkit.Env, version func() string) *cobra.Command {
	var opts pollOptions
	cmd := &cobra.Command{
		Use:   "poll",
		Short: "Poll ESXi hosts and record a heartbeat, platform facts and hardware spec for each",
		Long: "ESXi cannot run the node-agent, so a fleet host polls it instead and writes what the\n" +
			"agent would have: a heartbeat (`vctl list` shows it up or stale), a vmware/esxi\n" +
			"capability row, and the hardware spec (`vctl spec`). Guest VMs are not collected.\n\n" +
			"Each --host must be in the inventory; its address is the inventory IP unless the\n" +
			"secret names a url. Logins are read from Vault at use time, from\n" +
			config.Defaults().VaultFarmPrefix + "/" + vs.Key("<host>") + " (username, password; optional url, thumbprint).",
		Example: "  vctl vsphere poll --host sre-srv-0028 --host sre-srv-0046 --insecure",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.version = version()
			return runPoll(cmd, env, opts)
		},
	}
	cmd.Flags().StringArrayVar(&opts.hosts, "host", nil, "inventory hostname of an ESXi host (repeatable)")
	cmd.Flags().BoolVar(&opts.insecure, "insecure", false,
		"accept the host's self-signed certificate when the secret pins no thumbprint")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "poll and print, write nothing")
	_ = cmd.MarkFlagRequired("host")
	cmdkit.RegisterCompletion(cmd, "host", cmdkit.CompleteInventoryHost(env))
	return cmd
}

// pollPort is everything a poll touches: the inventory address, and the
// three rows the node-agent would otherwise write. It is the heartbeat role's
// surface, which is why the poller runs under PurposeStatus.
type pollPort interface {
	Get(ctx context.Context, hostname string) (*store.Server, error)
	UpsertServerStatus(ctx context.Context, st store.ServerStatus) (bool, error)
	ReplaceCapabilities(ctx context.Context, hostname, kind string, caps []store.Capability) (bool, error)
	RecordCapabilityError(ctx context.Context, hostname, kind, message string) error
	UpsertServerSpec(ctx context.Context, sp store.ServerSpec) (bool, error)
}

var _ pollPort = (*store.Store)(nil)

func runPoll(cmd *cobra.Command, env cmdkit.Env, opts pollOptions) error {
	return env.WithPurposeStore(cmd.Context(), app.PurposeStatus, func(a *app.App, st *store.Store) error {
		creds := vs.Creds{KV: a.Vault, Prefix: a.Cfg.VaultFarmPrefix}
		failed := 0
		for _, host := range opts.hosts {
			if err := pollOne(cmd.Context(), st, creds, host, opts); err != nil {
				failed++
				ui.Errorf(os.Stderr, "%s: %v", host, err)
			}
		}
		if failed > 0 {
			return fmt.Errorf("%d of %d ESXi host(s) could not be polled", failed, len(opts.hosts))
		}
		return nil
	})
}

func pollOne(ctx context.Context, st pollPort, creds vs.Creds, host string, opts pollOptions) error {
	sv, err := st.Get(ctx, host)
	if err != nil {
		return fmt.Errorf("not in the inventory: %w", err)
	}
	tgt, err := creds.Target(ctx, host, sv.IP, opts.insecure)
	if err != nil {
		return err
	}
	pctx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()
	o, err := vs.Observe(pctx, tgt)
	if err != nil {
		// Beside the last facts, never over them: an unreachable host has not
		// stopped being an ESXi host, and its heartbeat going stale already
		// says it is down.
		if !opts.dryRun {
			_ = st.RecordCapabilityError(ctx, host, vs.Kind, err.Error())
		}
		return err
	}
	sp := o.Spec()
	ui.Successf(os.Stderr, "%s: %s · %s %s · %d cores · %dGB · %s",
		host, o.Product, o.Vendor, o.Model, o.CPUCores, sp.Memory.TotalMB>>10, o.Overall)
	if opts.dryRun {
		return nil
	}

	if _, err := st.UpsertServerStatus(ctx, store.ServerStatus{
		Hostname:      host,
		AgentVersion:  "vsphere-poll/" + opts.version,
		OS:            "esxi",
		Kernel:        o.Product,
		UptimeSeconds: o.UptimeSeconds,
		MemoryUsedPct: o.MemoryUsedPct,
		ObservedIPs:   o.VMKernelIPs,
	}); err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	if _, err := st.ReplaceCapabilities(ctx, host, vs.Kind, []store.Capability{{
		Hostname: host, Kind: vs.Kind, Role: vs.Role, Detected: true, Active: o.Active(),
		Components: map[string]store.CapabilityComponent{
			"esxi": {Version: o.Version, Package: o.Build, Service: true, Active: o.Active()},
		},
		Details: o.Details(),
	}}); err != nil {
		return fmt.Errorf("capability: %w", err)
	}
	if _, err := st.UpsertServerSpec(ctx, store.ServerSpec{
		Hostname: host, Source: store.SpecSourceVSphere, Spec: sp, Collector: "vsphere-poll/" + opts.version,
	}); err != nil {
		return fmt.Errorf("spec: %w", err)
	}
	return nil
}
