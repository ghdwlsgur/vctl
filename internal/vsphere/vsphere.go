// Package vsphere observes standalone ESXi hosts through the vSphere API, for
// machines the node-agent cannot run on.
//
// ESXi has no systemd, no /proc mount table and a root filesystem that is a
// ramdisk, so the agent that reports every Linux host has nowhere to live. A
// poller on a fleet host asks each ESXi host for the same facts instead and
// writes them where the agent would have: a server_status heartbeat, so the
// listing shows up/stale like any other machine, and a server_capabilities row
// (kind vmware, role esxi) for the hardware. The guests are not its business:
// what is tracked here is the bare-metal machine.
package vsphere

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/vmware/govmomi/find"

	"github.com/ghdwlsgur/vctl/internal/hwspec"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/session"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
)

// Kind and Role are the server_capabilities key the poller writes under.
const (
	Kind = "vmware"
	Role = "esxi"
)

// Target is one host to observe: where its API is and how to log in.
type Target struct {
	// URL is the SDK endpoint, https://<address>/sdk.
	URL      string
	Username string
	Password string
	// Thumbprint pins the host's self-signed certificate (SHA-1 or SHA-256,
	// colon-separated hex, as `openssl x509 -fingerprint` prints it). Empty
	// means the system trust store decides, unless Insecure.
	Thumbprint string
	Insecure   bool
}

// Observation is what one poll learned about a host.
type Observation struct {
	Product string // "VMware ESXi 7.0.3 build-19193900"
	Version string
	Build   string

	Overall     string // green | yellow | red | gray
	Connection  string // connected | disconnected | notResponding
	Maintenance bool

	UptimeSeconds int64
	CPUUsedPct    *float64
	MemoryUsedPct *float64

	Vendor, Model, Serial string
	CPUModel              string
	CPUPackages           int
	CPUCores              int
	CPUThreads            int
	CPUMHz                int
	MemoryBytes           int64

	VMKernelIPs []string
	NICs        []NIC
	Disks       []hwspec.Disk
	Datastores  []Datastore
}

// NIC is one physical uplink.
type NIC struct {
	Device  string
	Driver  string
	SpeedMb int // 0 when the link is down
	// MaxSpeedMb is the fastest link specification the port accepts.
	MaxSpeedMb int
	MAC        string
}

// Datastore is one mounted datastore's capacity.
type Datastore struct {
	Name       string
	Type       string
	Capacity   int64
	Free       int64
	Accessible bool
}

// Observe logs into the host, reads it, and logs out.
func Observe(ctx context.Context, t Target) (Observation, error) {
	u, err := soap.ParseURL(t.URL)
	if err != nil {
		return Observation{}, fmt.Errorf("endpoint %q: %w", t.URL, err)
	}
	if u == nil {
		return Observation{}, errors.New("no endpoint")
	}
	sc := soap.NewClient(u, t.Insecure && t.Thumbprint == "")
	if t.Thumbprint != "" {
		sc.SetThumbprint(u.Host, strings.ToUpper(t.Thumbprint))
	}
	vc, err := vim25.NewClient(ctx, sc)
	if err != nil {
		return Observation{}, err
	}
	sm := session.NewManager(vc)
	if err := sm.Login(ctx, url.UserPassword(t.Username, t.Password)); err != nil {
		return Observation{}, fmt.Errorf("login: %w", err)
	}
	// Each poll is one session; an ESXi host caps concurrent sessions, and a
	// poller that leaked one per run would exhaust it within a day.
	defer func() { _ = sm.Logout(context.WithoutCancel(ctx)) }()
	return read(ctx, vc)
}

func read(ctx context.Context, vc *vim25.Client) (Observation, error) {
	hs, err := find.NewFinder(vc).DefaultHostSystem(ctx)
	if err != nil {
		return Observation{}, fmt.Errorf("host system: %w", err)
	}
	pc := property.DefaultCollector(vc)
	var h mo.HostSystem
	if err := pc.RetrieveOne(ctx, hs.Reference(),
		[]string{"summary", "hardware.systemInfo", "hardware.cpuInfo", "hardware.cpuPkg",
			"hardware.memorySize", "config.network.vnic", "config.network.pnic", "config.storageDevice.scsiLun",
			"datastore"}, &h); err != nil {
		return Observation{}, err
	}

	var o Observation
	s := h.Summary
	if p := s.Config.Product; p != nil {
		o.Product, o.Version, o.Build = p.FullName, p.Version, p.Build
	}
	o.Overall = string(s.OverallStatus)
	o.Connection = string(s.Runtime.ConnectionState)
	o.Maintenance = s.Runtime.InMaintenanceMode
	o.UptimeSeconds = int64(s.QuickStats.Uptime)

	if hw := h.Hardware; hw != nil {
		o.Vendor, o.Model = hw.SystemInfo.Vendor, hw.SystemInfo.Model
		o.Serial = serial(hw.SystemInfo)
		o.CPUPackages = int(hw.CpuInfo.NumCpuPackages)
		o.CPUCores = int(hw.CpuInfo.NumCpuCores)
		o.CPUThreads = int(hw.CpuInfo.NumCpuThreads)
		o.CPUMHz = int(hw.CpuInfo.Hz / 1_000_000)
		o.MemoryBytes = hw.MemorySize
		if len(hw.CpuPkg) > 0 {
			o.CPUModel = strings.Join(strings.Fields(hw.CpuPkg[0].Description), " ")
		}
	}
	if total := float64(o.CPUMHz) * float64(o.CPUCores); total > 0 && s.QuickStats.OverallCpuUsage > 0 {
		o.CPUUsedPct = pct(float64(s.QuickStats.OverallCpuUsage), total)
	}
	if o.MemoryBytes > 0 && s.QuickStats.OverallMemoryUsage > 0 {
		o.MemoryUsedPct = pct(float64(s.QuickStats.OverallMemoryUsage)*(1<<20), float64(o.MemoryBytes))
	}

	if n := h.Config; n != nil && n.Network != nil {
		for _, v := range n.Network.Vnic {
			if v.Spec.Ip != nil && v.Spec.Ip.IpAddress != "" {
				o.VMKernelIPs = append(o.VMKernelIPs, v.Spec.Ip.IpAddress)
			}
		}
		for _, p := range n.Network.Pnic {
			nic := NIC{Device: p.Device, Driver: p.Driver, MAC: p.Mac}
			if p.LinkSpeed != nil {
				nic.SpeedMb = int(p.LinkSpeed.SpeedMb)
			}
			nic.MaxSpeedMb = nic.SpeedMb
			for _, l := range p.ValidLinkSpecification {
				nic.MaxSpeedMb = max(nic.MaxSpeedMb, int(l.SpeedMb))
			}
			o.NICs = append(o.NICs, nic)
		}
		if n.StorageDevice != nil {
			for _, l := range n.StorageDevice.ScsiLun {
				d, ok := l.(*types.HostScsiDisk)
				// Local disks only: a SAN LUN is storage the host borrows, not
				// hardware in its chassis.
				if !ok || (d.LocalDisk != nil && !*d.LocalDisk) {
					continue
				}
				disk := hwspec.Disk{
					Name:      d.CanonicalName,
					SizeBytes: d.Capacity.Block * int64(d.Capacity.BlockSize),
					Vendor:    strings.TrimSpace(d.Vendor),
					Model:     strings.TrimSpace(d.Model),
					Media:     "HDD",
				}
				if d.Ssd != nil && *d.Ssd {
					disk.Media = "SSD"
				}
				o.Disks = append(o.Disks, disk)
			}
			sort.Slice(o.Disks, func(i, j int) bool { return o.Disks[i].Name < o.Disks[j].Name })
		}
	}

	if len(h.Datastore) > 0 {
		var dss []mo.Datastore
		if err := pc.Retrieve(ctx, h.Datastore, []string{"summary"}, &dss); err != nil {
			return Observation{}, fmt.Errorf("datastores: %w", err)
		}
		for _, d := range dss {
			o.Datastores = append(o.Datastores, Datastore{Name: d.Summary.Name, Type: d.Summary.Type,
				Capacity: d.Summary.Capacity, Free: d.Summary.FreeSpace, Accessible: d.Summary.Accessible})
		}
		sort.Slice(o.Datastores, func(i, j int) bool { return o.Datastores[i].Name < o.Datastores[j].Name })
	}

	return o, nil
}

// serial prefers the field 6.7 added, and falls back to the identifying info
// older builds and some vendors still put it in.
func serial(si types.HostSystemInfo) string {
	if si.SerialNumber != "" {
		return si.SerialNumber
	}
	for _, key := range []string{"SerialNumberTag", "ServiceTag", "EnclosureSerialNumberTag"} {
		for _, oi := range si.OtherIdentifyingInfo {
			if el := oi.IdentifierType.GetElementDescription(); el != nil && el.Key == key && oi.IdentifierValue != "" {
				return oi.IdentifierValue
			}
		}
	}
	return ""
}

func pct(used, total float64) *float64 {
	v := used / total * 100
	if v > 100 {
		v = 100
	}
	v = float64(int(v*10+0.5)) / 10
	return &v
}

// Details flattens the observation into the string map server_capabilities
// keeps, in the units a reader wants on screen.
func (o Observation) Details() map[string]string {
	d := map[string]string{
		"product":      o.Product,
		"overall":      o.Overall,
		"connection":   o.Connection,
		"maintenance":  strconv.FormatBool(o.Maintenance),
		"vendor":       o.Vendor,
		"model":        o.Model,
		"serial":       o.Serial,
		"cpu_model":    o.CPUModel,
		"cpu_packages": strconv.Itoa(o.CPUPackages),
		"cpu_cores":    strconv.Itoa(o.CPUCores),
		"cpu_threads":  strconv.Itoa(o.CPUThreads),
		"cpu_mhz":      strconv.Itoa(o.CPUMHz),
		"memory_gb":    strconv.FormatInt(o.MemoryBytes>>30, 10),
	}
	if o.CPUUsedPct != nil {
		d["cpu_used_pct"] = strconv.FormatFloat(*o.CPUUsedPct, 'f', 1, 64)
	}
	var nics []string
	for _, n := range o.NICs {
		speed := "down"
		if n.SpeedMb > 0 {
			speed = fmt.Sprintf("%dMb", n.SpeedMb)
		}
		nics = append(nics, fmt.Sprintf("%s %s %s", n.Device, speed, n.Driver))
	}
	d["nics"] = strings.Join(nics, ", ")
	var dss []string
	for _, ds := range o.Datastores {
		state := ""
		if !ds.Accessible {
			state = " inaccessible"
		}
		dss = append(dss, fmt.Sprintf("%s %s %d/%dGB free%s", ds.Name, ds.Type, ds.Free>>30, ds.Capacity>>30, state))
	}
	d["datastores"] = strings.Join(dss, ", ")
	for k, v := range d {
		if v == "" {
			delete(d, k)
		}
	}
	return d
}

// Spec is the hardware part of the observation in the shape the Linux
// collector reports. ESXi does not expose DIMMs, the board's socket count or a
// port's connector through this API; those stay zero, and the sheet shows them
// as unknown.
func (o Observation) Spec() hwspec.Spec {
	sp := hwspec.Spec{
		System: hwspec.System{Vendor: o.Vendor, Model: o.Model, Serial: o.Serial},
		OS:     o.Product,
		CPU: hwspec.CPU{
			Model: o.CPUModel, Sockets: o.CPUPackages,
			Cores: o.CPUCores, Threads: o.CPUThreads, MHz: o.CPUMHz,
		},
		Memory: hwspec.Memory{TotalMB: o.MemoryBytes >> 20},
		Disks:  o.Disks,
	}
	if o.CPUPackages > 0 {
		sp.CPU.CoresPerSocket = o.CPUCores / o.CPUPackages
	}
	for _, n := range o.NICs {
		sp.NICs = append(sp.NICs, hwspec.NIC{Name: n.Device, MAC: n.MAC, SpeedMb: n.SpeedMb,
			MaxSpeedMb: n.MaxSpeedMb, Driver: n.Driver})
	}
	return sp
}

// Active is whether the host is doing its job: reachable by its own API and
// not parked in maintenance.
func (o Observation) Active() bool {
	return o.Connection == string(types.HostSystemConnectionStateConnected) && !o.Maintenance
}
