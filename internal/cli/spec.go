package cli

import (
	"context"
	"fmt"
	"os"
	osuser "os/user"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/hwspec"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// specCmd is `vctl spec`: the bare-metal asset sheet, built from what each
// machine reports about its hardware plus what operators recorded about it.
func specCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "spec [host]",
		Short: "Hardware specs and asset notes of bare-metal hosts",
		Long: "Without a host, one line per bare-metal machine: vendor, model, serial, CPUs,\n" +
			"memory, disks, NIC ports and where it sits. With a host, the full sheet for it.\n\n" +
			"Hardware is collected by the node-agent (SMBIOS and sysfs, daily) and, for ESXi,\n" +
			"by the vSphere poller. IDC, rack, labels, usage and the rest are operator notes:\n" +
			"set them with `vctl spec set`. VMs are not listed; their hardware is a flavor.",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: firstArgOnly(cmdkit.CompleteInventoryHost(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := ""
			if len(args) == 1 {
				host = args[0]
			}
			return runSpec(cmd, env, host)
		},
	}
	cmd.AddCommand(cmdkit.Gate(specSetCmd(env), "spec"))
	return cmdkit.SupportsStructuredOutput(cmd)
}

// specPort is what `vctl spec` reads.
type specPort interface {
	SpecRows(ctx context.Context, hostname string) ([]store.SpecRow, error)
}

var _ specPort = (*store.Store)(nil)

func runSpec(cmd *cobra.Command, env cmdkit.Env, host string) error {
	format, err := cmdkit.CommandOutput(cmd, false)
	if err != nil {
		return err
	}
	return cmdkit.WithStorePort(env, cmd.Context(), false, func(_ *app.App, st specPort) error {
		rows, err := st.SpecRows(cmd.Context(), host)
		if err != nil {
			return err
		}
		if host != "" && len(rows) == 0 {
			return fmt.Errorf("%s is not in the inventory", host)
		}
		// The sheet is bare metal: a host with neither a collected spec nor an
		// operator note is a VM or has never reported, and listing it would
		// pad the sheet with empty lines.
		sheet := rows[:0:0]
		for _, r := range rows {
			if r.Spec != nil || r.Asset != nil || host != "" {
				sheet = append(sheet, r)
			}
		}
		if format != cmdkit.OutputTable {
			return cmdkit.WriteStructured(format, specDocuments(sheet))
		}
		if host != "" {
			renderSpecHost(sheet[0])
			return nil
		}
		return renderSpecSheet(sheet, len(rows)-len(sheet))
	})
}

// specDocument is the structured form: the collected spec and the notes side
// by side, never merged, so a consumer can tell which side said what.
type specDocument struct {
	Hostname   string       `json:"hostname"`
	IP         string       `json:"ip,omitempty"`
	Source     string       `json:"source,omitempty"`
	ObservedAt *time.Time   `json:"observed_at,omitempty"`
	Spec       *hwspec.Spec `json:"spec,omitempty"`
	Asset      *assetDoc    `json:"asset,omitempty"`
}

type assetDoc struct {
	IDC         string `json:"idc,omitempty"`
	Rack        string `json:"rack,omitempty"`
	Label       string `json:"label,omitempty"`
	LegacyLabel string `json:"legacy_label,omitempty"`
	RackUnits   string `json:"rack_units,omitempty"`
	Usage       string `json:"usage,omitempty"`
	Purpose     string `json:"purpose,omitempty"`
	Solution    string `json:"solution,omitempty"`
	Department  string `json:"department,omitempty"`
	RAID        string `json:"raid,omitempty"`
	Note        string `json:"note,omitempty"`
	UpdatedBy   string `json:"updated_by,omitempty"`
}

func specDocuments(rows []store.SpecRow) []specDocument {
	out := make([]specDocument, 0, len(rows))
	for _, r := range rows {
		d := specDocument{Hostname: r.Hostname, IP: r.IP}
		if r.Spec != nil {
			sp, at := r.Spec.Spec, r.Spec.ObservedAt
			d.Source, d.ObservedAt, d.Spec = r.Spec.Source, &at, &sp
		}
		if a := r.Asset; a != nil {
			d.Asset = &assetDoc{IDC: a.IDC, Rack: a.Rack, Label: a.Label, LegacyLabel: a.LegacyLabel,
				RackUnits: a.RackUnits, Usage: a.Usage, Purpose: a.Purpose, Solution: a.Solution,
				Department: a.Department, RAID: a.RAID, Note: a.Note, UpdatedBy: a.UpdatedBy}
		}
		out = append(out, d)
	}
	return out
}

func renderSpecSheet(rows []store.SpecRow, skipped int) error {
	columns := []ui.Column{
		{Header: "HOST", MinWidth: 12},
		{Header: "MODEL", MinWidth: 10, MaxWidth: 28},
		{Header: "SERIAL", Optional: true, Priority: 4},
		{Header: "CPU", MinWidth: 8},
		{Header: "MEMORY", MinWidth: 8},
		{Header: "DISK", Optional: true, Priority: 2, MaxWidth: 34},
		{Header: "NIC", Optional: true, Priority: 3, MaxWidth: 34},
		{Header: "LOCATION", Optional: true, Priority: 1},
		{Header: "USAGE", Optional: true, Priority: 5},
	}
	var cells [][]string
	for _, r := range rows {
		var sp hwspec.Spec
		if r.Spec != nil {
			sp = r.Spec.Spec
		}
		var a store.Asset
		if r.Asset != nil {
			a = *r.Asset
		}
		cells = append(cells, []string{
			r.Hostname,
			orDash(strings.TrimSpace(sp.System.Vendor + " " + sp.System.Model)),
			orDash(sp.System.Serial),
			orDash(cpuCell(sp.CPU)),
			orDash(memoryCell(sp.Memory)),
			orDash(diskCell(sp.Disks)),
			orDash(nicCell(sp.NICs)),
			orDash(locationCell(a)),
			orDash(a.Usage),
		})
	}
	if err := ui.ResponsiveTable(os.Stdout, columns, cells, ui.TableOptions{}); err != nil {
		return err
	}
	if skipped > 0 {
		ui.Infof(os.Stderr, "%d inventory host(s) have no spec yet (VMs, or no agent report)", skipped)
	}
	return nil
}

func renderSpecHost(r store.SpecRow) {
	w := os.Stdout
	var sp hwspec.Spec
	if r.Spec != nil {
		sp = r.Spec.Spec
	}
	var a store.Asset
	if r.Asset != nil {
		a = *r.Asset
	}
	kv := func(k, v string) ui.KV { return ui.KV{Key: k, Value: orDash(v), State: ui.StatePlain} }

	ui.Section(w, r.Hostname)
	collected := "never collected — no agent report and no vSphere poll yet"
	if r.Spec != nil {
		collected = fmt.Sprintf("%s · %s %s", r.Spec.Source, r.Spec.ObservedAt.Local().Format("2006-01-02 15:04"), ui.Ago(r.Spec.ObservedAt))
	}
	ui.KVs(w, []ui.KV{
		{Key: "Collected", Raw: collected},
		kv("IDC", a.IDC), kv("Rack", a.Rack), kv("Label", a.Label), kv("Legacy label", a.LegacyLabel),
		kv("Unit", a.RackUnits), kv("Usage", a.Usage), kv("Purpose", a.Purpose),
		kv("Solution", a.Solution), kv("Department", a.Department),
		kv("Vendor", sp.System.Vendor), kv("Model", sp.System.Model), kv("Serial", sp.System.Serial),
		kv("Hostname", r.Hostname), kv("OS", sp.OS),
	})

	fmt.Fprintln(w)
	ui.Section(w, "CPU")
	c := sp.CPU
	ui.KVs(w, []ui.KV{
		kv("Model", c.Model),
		kv("Sockets (used/total)", fraction(c.Sockets, c.SocketsTotal)),
		kv("Cores (1 CPU/total)", fraction(c.CoresPerSocket, c.Cores)),
		kv("Threads", count(c.Threads)),
	})

	fmt.Fprintln(w)
	ui.Section(w, "Memory")
	m := sp.Memory
	modSize, modType, modSpeed := moduleSummary(m.Modules)
	ui.KVs(w, []ui.KV{
		kv("Capacity (GB)", gbOf(m.TotalMB)),
		kv("Module (GB)", modSize), kv("Type", modType), kv("Speed (MHz)", modSpeed),
		kv("Slots (used/total)", fraction(m.MemorySlotsUsed(), m.SlotsTotal)),
	})

	fmt.Fprintln(w)
	ui.Section(w, "Disk")
	if a.RAID != "" {
		ui.KVs(w, []ui.KV{kv("RAID", a.RAID)})
	}
	if len(sp.Disks) == 0 {
		fmt.Fprintln(w, ui.Muted("  -"))
	}
	var drows [][]string
	for _, d := range sp.Disks {
		drows = append(drows, []string{d.Name, sizeOf(d.SizeBytes), orDash(d.Media), orDash(d.Interface),
			orDash(strings.TrimSpace(d.Vendor + " " + d.Model))})
	}
	if len(drows) > 0 {
		_ = ui.Table(w, []string{"DEVICE", "SIZE", "TYPE", "INTERFACE", "MODEL"}, drows)
	}

	fmt.Fprintln(w)
	ui.Section(w, "NIC")
	var nrows [][]string
	for _, g := range nicGroups(sp.NICs) {
		nrows = append(nrows, []string{speedOf(g.maxMb), orDash(g.port), fmt.Sprint(g.ports), fmt.Sprint(g.up), strings.Join(g.names, " ")})
	}
	if len(nrows) == 0 {
		fmt.Fprintln(w, ui.Muted("  -"))
	} else {
		_ = ui.Table(w, []string{"SPEED", "TYPE", "PORTS", "UP", "INTERFACES"}, nrows)
	}
	if a.Note != "" {
		fmt.Fprintln(w)
		ui.Section(w, "Note")
		fmt.Fprintln(w, a.Note)
	}
}

func cpuCell(c hwspec.CPU) string {
	if c.Sockets == 0 && c.Cores == 0 {
		return ""
	}
	return fmt.Sprintf("%s×%dC", fraction(c.Sockets, c.SocketsTotal), c.CoresPerSocket)
}

func memoryCell(m hwspec.Memory) string {
	if m.TotalMB == 0 {
		return ""
	}
	s := gbOf(m.TotalMB) + "GB"
	if m.SlotsTotal > 0 {
		s += " (" + fraction(m.MemorySlotsUsed(), m.SlotsTotal) + ")"
	}
	return s
}

func diskCell(disks []hwspec.Disk) string {
	type key struct{ size, media, iface string }
	n := map[key]int{}
	var order []key
	for _, d := range disks {
		k := key{sizeOf(d.SizeBytes), d.Media, d.Interface}
		if n[k] == 0 {
			order = append(order, k)
		}
		n[k]++
	}
	parts := make([]string, 0, len(order))
	for _, k := range order {
		parts = append(parts, strings.TrimSpace(fmt.Sprintf("%d×%s %s %s", n[k], k.size, k.media, k.iface)))
	}
	return strings.Join(parts, ", ")
}

func nicCell(nics []hwspec.NIC) string {
	var parts []string
	for _, g := range nicGroups(nics) {
		parts = append(parts, strings.TrimSpace(fmt.Sprintf("%d×%s %s", g.ports, speedOf(g.maxMb), g.port)))
	}
	return strings.Join(parts, ", ")
}

type nicGroup struct {
	maxMb     int
	port      string
	ports, up int
	names     []string
}

// nicGroups is the sheet's NIC block: ports counted by speed class and
// connector, fastest first — "4 × 10Gb SFP+" — with how many have a link.
func nicGroups(nics []hwspec.NIC) []nicGroup {
	idx := map[string]int{}
	var out []nicGroup
	for _, n := range nics {
		k := fmt.Sprintf("%d/%s", n.MaxSpeedMb, n.Port)
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, nicGroup{maxMb: n.MaxSpeedMb, port: n.Port})
		}
		out[i].ports++
		if n.SpeedMb > 0 {
			out[i].up++
		}
		out[i].names = append(out[i].names, n.Name)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].maxMb > out[j].maxMb })
	return out
}

func moduleSummary(mods []hwspec.Module) (size, typ, speed string) {
	if len(mods) == 0 {
		return "", "", ""
	}
	sizes, types, speeds := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, m := range mods {
		sizes[gbOf(m.SizeMB)] = true
		if m.Type != "" {
			types[m.Type] = true
		}
		if m.SpeedMHz > 0 {
			speeds[fmt.Sprint(m.SpeedMHz)] = true
		}
	}
	// Mixed DIMMs are listed rather than averaged: a 16+32 machine is a
	// finding, not a 24GB module.
	return joinKeys(sizes), joinKeys(types), joinKeys(speeds)
}

func joinKeys(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, "/")
}

func locationCell(a store.Asset) string {
	parts := []string{}
	for _, v := range []string{a.IDC, a.Rack, a.RackUnits} {
		if v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, " ")
}

func fraction(used, total int) string {
	switch {
	case used == 0 && total == 0:
		return ""
	case total == 0:
		return fmt.Sprintf("%d/?", used)
	}
	return fmt.Sprintf("%d/%d", used, total)
}

func count(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprint(n)
}

func gbOf(mb int64) string {
	if mb == 0 {
		return ""
	}
	if mb%1024 == 0 {
		return fmt.Sprint(mb / 1024)
	}
	return fmt.Sprintf("%.1f", float64(mb)/1024)
}

// sizeOf renders a disk the way the sheet does: 279.4GB for what the kernel
// counts as 299966445568 bytes (GiB, labelled GB), TB from 1024GB up.
func sizeOf(b int64) string {
	gib := float64(b) / (1 << 30)
	if gib >= 1024 {
		return fmt.Sprintf("%.1fTB", gib/1024)
	}
	return fmt.Sprintf("%.1fGB", gib)
}

func speedOf(mb int) string {
	switch {
	case mb == 0:
		return "?"
	case mb%1000 == 0:
		return fmt.Sprintf("%dGb", mb/1000)
	}
	return fmt.Sprintf("%dMb", mb)
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// specSetCmd is `vctl spec set <host> --field value...`: the operator half of
// the sheet. Only the flags given are written; an empty value clears a field.
func specSetCmd(env cmdkit.Env) *cobra.Command {
	values := make(map[string]*string, len(store.AssetFields))
	cmd := &cobra.Command{
		Use:   "set <host>",
		Short: "Record a bare-metal host's asset notes (IDC, rack, labels, usage, ...)",
		Example: "  vctl spec set sre-srv-0060 --idc 가산 --rack A-07 --rack-units 3U --usage 사용중 \\\n" +
			"      --department '클라우드 연구개발 센터' --raid 'RAID1 2×300GB'\n" +
			"  vctl spec set sre-srv-0060 --rack ''        # clear one field",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: firstArgOnly(cmdkit.CompleteInventoryHost(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			fields := map[string]string{}
			for name, v := range values {
				if cmd.Flags().Changed(flagName(name)) {
					fields[name] = *v
				}
			}
			if len(fields) == 0 {
				return fmt.Errorf("nothing to set: pass at least one of --%s", strings.Join(flagNames(), ", --"))
			}
			return cmdkit.WithStorePort(env, cmd.Context(), true, func(_ *app.App, st specSetPort) error {
				ok, err := st.SetAsset(cmd.Context(), args[0], specActor(), fields)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%s is not in the inventory", args[0])
				}
				ui.Successf(os.Stderr, "%s: %d field(s) recorded", args[0], len(fields))
				return nil
			})
		},
	}
	help := map[string]string{
		"idc": "IDC", "rack": "rack", "label": "new asset label", "legacy_label": "previous asset label",
		"rack_units": "rack units, e.g. 2U", "usage": "usage state, e.g. 사용중", "purpose": "purpose",
		"solution": "solution", "department": "owning department", "raid": "RAID layout", "note": "free-form note",
	}
	for _, name := range store.AssetFields {
		values[name] = cmd.Flags().String(flagName(name), "", help[name])
	}
	return cmd
}

type specSetPort interface {
	SetAsset(ctx context.Context, hostname, by string, fields map[string]string) (bool, error)
}

var _ specSetPort = (*store.Store)(nil)

func flagName(field string) string { return strings.ReplaceAll(field, "_", "-") }

func flagNames() []string {
	out := make([]string, 0, len(store.AssetFields))
	for _, f := range store.AssetFields {
		out = append(out, flagName(f))
	}
	return out
}

// specActor is who the asset record says made the change: the local login,
// as the DNS commands record it.
func specActor() string {
	if u, err := osuser.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}
