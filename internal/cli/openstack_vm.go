package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/openstack"
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
			"Kubernetes providerID (openstack:///<uuid>) and goes the other way.\n\n" +
			"An argument that is not a UUID is searched for in VM names and addresses:\n\n" +
			"  vctl openstack vm bastion        every VM whose name contains it\n" +
			"  vctl openstack vm 10.3.1         every VM answering on an address that starts there",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				ctx := cmd.Context()
				// One argument, read by its shape. A UUID is an identity and a
				// word is a search, and asking somebody to say which is which
				// with a flag would be asking them to describe what they can
				// already see.
				search := ""
				if len(args) > 0 {
					if v := normalizeInstanceID(args[0]); isInstanceID(v) {
						if id == "" {
							id = v
						}
					} else {
						search = args[0]
					}
				}
				f := store.InstanceFilter{
					ProjectID: project, Address: address, Search: search,
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
				names, err := farmNames(ctx, st)
				if err != nil {
					return err
				}
				// A config that will not load is not a reason to refuse a
				// listing; it only costs the address preference.
				var nets []string
				if cfg, err := config.Load(); err == nil {
					nets = cfg.OperatorNetworks
				}
				renderVMs(os.Stdout, vms, names, nets, time.Now())
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

// isInstanceID reports whether a string is a Nova UUID rather than a search.
//
// Shape, not a lookup: deciding by querying would make an argument that finds
// nothing change meaning, so "the VM I called abc-123 that was deleted" would
// silently become a substring search across the fleet.
func isInstanceID(v string) bool {
	if len(v) != 36 {
		return false
	}
	for i, c := range v {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

// resolveFarmID turns a name people use into the deployment id rows carry.
func resolveFarmID(ctx context.Context, st *store.Store, v string) (string, error) {
	farms, err := farmChoices(ctx, st)
	if err != nil {
		return "", err
	}
	f, err := resolveFarm(farms, v)
	if err != nil {
		return "", err
	}
	return f.ID, nil
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

// farmNames maps deployment id to what people call it, for the grouping header.
func farmNames(ctx context.Context, st *store.Store) (map[string]string, error) {
	deps, err := st.Deployments(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(deps))
	for _, d := range deps {
		if d.DisplayName != "" {
			out[d.ID] = d.DisplayName
		}
	}
	return out, nil
}

// renderVMs groups by farm and names the owning project.
//
// The farm is a header rather than a column: without --farm this listing mixes
// every deployment together, and a VM's name says nothing about which one it is
// in. Repeating the farm on every row would cost more width than it buys, and
// the same listing already groups this way for hosts.
//
// The project is a column because it varies within a farm — it is the question
// "whose VM is this", asked one row at a time.
func renderVMs(w io.Writer, vms []store.Instance, farms map[string]string, operatorNets []string, now time.Time) {
	if len(vms) == 0 {
		ui.Infof(w, "no VMs to show.")
		return
	}
	byFarm := map[string][]store.Instance{}
	for _, v := range vms {
		byFarm[v.DeploymentID] = append(byFarm[v.DeploymentID], v)
	}
	ids := make([]string, 0, len(byFarm))
	for id := range byFarm {
		ids = append(ids, id)
	}
	// By what is printed, not by the id behind it — sorting on the endpoint
	// while showing the name produces an order that looks like no order at all.
	sort.Slice(ids, func(i, j int) bool {
		return vmFarmLabel(ids[i], farms) < vmFarmLabel(ids[j], farms)
	})

	// The same header the host listing uses, so one farm reads the same in both.
	farmStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	for _, id := range ids {
		group := byFarm[id]
		fmt.Fprintf(w, "\n%s %s\n", farmStyle.Render("▌ "+vmFarmLabel(id, farms)),
			ui.Muted(fmt.Sprintf("· %d VMs", len(group))))
		cells := make([][]string, len(group))
		for i, v := range group {
			cells[i] = []string{
				ui.Truncate(nameOrID(v), 32),
				vmStateCell(v),
				ui.Muted(ui.Truncate(vmProjectLabel(v), 22)),
				ui.Truncate(v.HypervisorHostname, 20),
				ui.Truncate(primaryAddress(v, operatorNets), 24),
				ui.Muted(ui.Truncate(v.AvailabilityZone, 12)),
				vmMissingCell(v, now),
			}
		}
		widths := ui.ColumnWidths(cells)
		for i := range group {
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
	}
	fmt.Fprintln(w, ui.Muted(fmt.Sprintf("\n%d VMs · %d farms", len(vms), len(byFarm))))
}

// vmFarmLabel is the name if the farm has one, the endpoint otherwise. Nothing
// claims the farm is unnamed — an endpoint is a real answer to "which one".
func vmFarmLabel(id string, farms map[string]string) string {
	if n := farms[id]; n != "" {
		return n
	}
	return id
}

// vmProjectLabel prefers the name and falls back to the id.
//
// The id is kept in the data because it is the identifier; the name is what the
// last collection saw it called. An empty name means nothing has resolved it
// yet — usually a farm collected before this column existed — and showing the
// id then is better than showing a blank.
func vmProjectLabel(v store.Instance) string {
	if v.ProjectName != "" {
		return v.ProjectName
	}
	return v.ProjectID
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

// primaryAddress leads with the address somebody can actually reach the VM on
// and mutes the rest.
//
// A VM answers on several — a tenant network that does not route past its own
// farm, sometimes a storage one, and one an operator can open. Nothing in the
// data marks them apart, so leading with whichever nova listed first was right
// by accident: half the rows showed a 10.x that nobody outside the farm can
// open, and the address column is the column people copy out of.
//
// Order: a floating address, then one on an operator network, then anything —
// and that ranking is openstack.ReachableAddress, the same function the SSH
// path resolves a VM with, so the address on screen is the address a connection
// will use. It was inline here, decoration and all, which is why the two could
// not share it.
func primaryAddress(v store.Instance, operatorNets []string) string {
	best := openstack.ReachableAddress(v.Addresses, operatorNets)
	if extra := len(v.Addresses) - 1; extra > 0 && best != "" {
		return best + ui.Muted(fmt.Sprintf(" (+%d)", extra))
	}
	return best
}

func vmMissingCell(v store.Instance, now time.Time) string {
	if v.MissingSince == nil {
		return ""
	}
	return ui.Fail("gone " + ui.CompactDuration(now.Sub(*v.MissingSince)))
}
