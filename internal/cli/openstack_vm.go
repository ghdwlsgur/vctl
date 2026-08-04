package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// providerIDPrefix is how Kubernetes names an OpenStack VM in
// Node.spec.providerID. It is the join between a cluster and the farm under it.
const providerIDPrefix = "openstack:///"

func openstackVMCmd() *cobra.Command {
	var (
		farm     string
		host     string
		project  string
		address  string
		id       string
		showGone bool
		asJSON   bool
	)
	cmd := &cobra.Command{
		Use:     "vm",
		Aliases: []string{"vms", "instances"},
		Short:   "VMs per deployment, and which physical host each one sits on",
		Long: "The chain this walks:\n\n" +
			"  OpenStack farm → physical compute host → VM → Kubernetes node → cluster\n\n" +
			"--host takes an inventory hostname and resolves it to nova's name for the same\n" +
			"machine, so a physical host answers for the VMs on it. --id takes a Nova UUID or a\n" +
			"Kubernetes providerID (openstack:///<uuid>) and goes the other way.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				ctx := cmd.Context()
				if len(args) > 0 && id == "" {
					id = args[0]
				}
				f := store.InstanceFilter{
					ProjectID: project, Address: address,
					InstanceID:     normalizeInstanceID(id),
					IncludeMissing: showGone,
				}
				if farm != "" {
					resolved, err := resolveFarmID(ctx, st, farm)
					if err != nil {
						return err
					}
					f.DeploymentID = resolved
				}
				if host != "" {
					nova, err := novaNameFor(ctx, st, host, f.DeploymentID)
					if err != nil {
						return err
					}
					f.Hypervisor = nova
				}
				vms, err := st.Instances(ctx, f)
				if err != nil {
					return err
				}
				if asJSON {
					return writeJSON(vms)
				}
				renderVMs(os.Stdout, vms, time.Now())
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&farm, "farm", "", "only this deployment, by name or Keystone endpoint")
	cmd.Flags().StringVar(&host, "host", "", "only VMs on this physical host (inventory hostname)")
	cmd.Flags().StringVar(&project, "project", "", "only this project id")
	cmd.Flags().StringVar(&address, "address", "", "the VM answering on this IP")
	cmd.Flags().StringVar(&id, "id", "", "a Nova UUID, or a Kubernetes providerID (openstack:///<uuid>)")
	cmd.Flags().BoolVar(&showGone, "missing", false, "include VMs the control plane no longer lists")
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (for dataset/agent export)")
	return cmd
}

// normalizeInstanceID accepts what Kubernetes writes as well as a bare UUID.
//
// A node's spec.providerID is openstack:///<uuid>, and making somebody strip
// that by hand before pasting it is the kind of friction that ends in the wrong
// substring being pasted.
func normalizeInstanceID(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), providerIDPrefix)
}

// resolveFarmID turns a name people use into the deployment id rows carry.
func resolveFarmID(ctx context.Context, st *store.Store, v string) (string, error) {
	farms, err := farmChoices(ctx, st)
	if err != nil {
		return "", err
	}
	i := indexOfFarm(farms, v)
	if i < 0 {
		return "", fmt.Errorf("no deployment %q; run 'vctl openstack' to see them", v)
	}
	return farms[i].ID, nil
}

// novaNameFor maps an inventory hostname onto the name nova files VMs under.
//
// The instance rows carry nova's name as reported, not a resolved one — so this
// re-derives the join with the same matcher the reconciler uses. Storing the
// resolved name instead would bake today's matching rules into data that
// outlives them, and the rules have already changed twice.
func novaNameFor(ctx context.Context, st *store.Store, inventoryHost, deployment string) (string, error) {
	names, err := st.HypervisorNames(ctx, deployment)
	if err != nil {
		return "", err
	}
	pairs, ambiguous := store.MatchHosts([]string{inventoryHost}, names)
	if nova, ok := pairs[inventoryHost]; ok {
		return nova, nil
	}
	if len(ambiguous) > 0 {
		return "", fmt.Errorf("%s matches more than one hypervisor name (%s); name the deployment with --farm",
			inventoryHost, strings.Join(ambiguous, ", "))
	}
	return "", fmt.Errorf("no VMs are recorded on %s; it may not be a compute node, or nothing has collected yet", inventoryHost)
}

func renderVMs(w io.Writer, vms []store.Instance, now time.Time) {
	if len(vms) == 0 {
		ui.Infof(w, "no VMs to show.")
		return
	}
	cells := make([][]string, len(vms))
	for i, v := range vms {
		cells[i] = []string{
			ui.Truncate(nameOrID(v), 32),
			vmStateCell(v),
			ui.Truncate(v.HypervisorHostname, 20),
			ui.Truncate(primaryAddress(v), 24),
			ui.Muted(ui.Truncate(v.AvailabilityZone, 12)),
			vmMissingCell(v, now),
		}
	}
	widths := ui.ColumnWidths(cells)
	for i := range vms {
		var line strings.Builder
		line.WriteString("  ")
		for j, c := range cells[i] {
			if j > 0 {
				line.WriteString("  ")
			}
			line.WriteString(ui.PadRight(c, widths[j]))
		}
		fmt.Fprintln(w, strings.TrimRight(line.String(), " "))
	}
	fmt.Fprintln(w, ui.Muted(fmt.Sprintf("%d VMs", len(vms))))
}

func nameOrID(v store.Instance) string {
	if v.Name != "" {
		return v.Name
	}
	// A VM with no name still has to be identifiable, and the UUID is the only
	// thing it definitely has.
	return v.InstanceID
}

// vmStateCell folds nova's three state fields into the one thing a reader wants
// to know, and keeps them apart when they disagree.
//
// task_state leads when set: a VM stuck mid-migration is neither running nor
// stopped, and reporting it as ACTIVE hides the only interesting thing about it.
func vmStateCell(v store.Instance) string {
	if v.TaskState != "" {
		return ui.Warn(v.TaskState)
	}
	switch strings.ToUpper(v.Status) {
	case "ACTIVE":
		if v.PowerState != "" && v.PowerState != "running" {
			// The API and the hypervisor disagree, which is worth seeing.
			return ui.Warn("ACTIVE/" + v.PowerState)
		}
		return ui.OK("ACTIVE")
	case "ERROR":
		return ui.Fail("ERROR")
	case "SHUTOFF", "STOPPED", "PAUSED", "SUSPENDED":
		return ui.Muted(strings.ToUpper(v.Status))
	default:
		return v.Status
	}
}

// primaryAddress prefers a floating address, which is the one somebody reaches
// the VM on.
func primaryAddress(v store.Instance) string {
	var fixed string
	for _, a := range v.Addresses {
		if a.Type == "floating" {
			return a.Address
		}
		if fixed == "" {
			fixed = a.Address
		}
	}
	if extra := len(v.Addresses) - 1; extra > 0 && fixed != "" {
		return fixed + ui.Muted(fmt.Sprintf(" (+%d)", extra))
	}
	return fixed
}

func vmMissingCell(v store.Instance, now time.Time) string {
	if v.MissingSince == nil {
		return ""
	}
	return ui.Fail("gone " + ui.CompactDuration(now.Sub(*v.MissingSince)))
}
