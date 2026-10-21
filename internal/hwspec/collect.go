package hwspec

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ErrVirtual is returned for a guest. The spec sheet is about bare metal: a
// VM's "hardware" is its flavor, which the hypervisor's inventory already owns.
var ErrVirtual = errors.New("virtual machine: hardware specs are collected for bare-metal hosts only")

// Collector reads a Linux host. Root is "/" in production and a fake tree in
// tests; PortOf answers a NIC's connector and fastest speed (ethtool), and is
// nil where the platform has no way to ask.
type Collector struct {
	Root   string
	PortOf func(ifname string) (fibre, copper bool, maxMb int, ok bool)
}

// NewCollector reads the running host.
func NewCollector() Collector { return Collector{Root: "/", PortOf: ethtoolPort} }

func (c Collector) path(p string) string { return filepath.Join(c.Root, p) }

func (c Collector) read(p string) string {
	b, err := os.ReadFile(c.path(p))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Collect reads the machine. It refuses guests with ErrVirtual.
func (c Collector) Collect() (Spec, error) {
	cpu := c.cpuinfo()
	if cpu.virtual {
		return Spec{}, ErrVirtual
	}
	var sp Spec
	sp.OS = c.osName()
	sp.CPU = cpu.CPU
	sp.Memory.TotalMB = c.memTotalMB()
	// The world-readable DMI files first, so a host whose table cannot be read
	// still names its vendor and model.
	sp.System = System{
		Vendor: clean(c.read("sys/class/dmi/id/sys_vendor")),
		Model:  clean(c.read("sys/class/dmi/id/product_name")),
		Serial: clean(c.read("sys/class/dmi/id/product_serial")),
	}
	if raw, err := os.ReadFile(c.path("sys/firmware/dmi/tables/DMI")); err == nil {
		ParseSMBIOS(raw).Apply(&sp)
	}
	sp.Disks = c.disks()
	sp.NICs = c.nics()
	return sp, nil
}

type cpuFacts struct {
	CPU
	virtual bool
}

// cpuinfo is the fallback for what SMBIOS says about processors, and the one
// place that says whether this is a guest: the hypervisor flag is set by every
// mainstream hypervisor and by no bare-metal CPU.
func (c Collector) cpuinfo() cpuFacts {
	f, err := os.Open(c.path("proc/cpuinfo"))
	if err != nil {
		return cpuFacts{}
	}
	defer f.Close()
	var out cpuFacts
	sockets := map[string]bool{}
	cores := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var phys string
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "processor":
			out.Threads++
		case "model name":
			if out.Model == "" {
				out.Model = strings.Join(strings.Fields(v), " ")
			}
		case "physical id":
			phys = v
			sockets[v] = true
		case "core id":
			cores[phys+"/"+v] = true
		case "cpu MHz":
			if out.MHz == 0 {
				if mhz, err := strconv.ParseFloat(v, 64); err == nil {
					out.MHz = int(mhz)
				}
			}
		case "flags":
			if !out.virtual {
				for _, fl := range strings.Fields(v) {
					if fl == "hypervisor" {
						out.virtual = true
						break
					}
				}
			}
		}
	}
	out.Sockets = len(sockets)
	out.Cores = len(cores)
	if out.Sockets > 0 {
		out.CoresPerSocket = out.Cores / out.Sockets
	}
	return out
}

func (c Collector) memTotalMB() int64 {
	f, err := os.Open(c.path("proc/meminfo"))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			kb, _ := strconv.ParseInt(strings.Fields(v)[0], 10, 64)
			return kb / 1024
		}
	}
	return 0
}

func (c Collector) osName() string {
	f, err := os.Open(c.path("etc/os-release"))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// skipDisk is everything in /sys/block that is not a device someone installed.
var skipDisk = regexp.MustCompile(`^(loop|ram|zram|dm-|md|sr|nbd|fd|rbd|drbd)`)

var scsiHost = regexp.MustCompile(`/host(\d+)/`)

func (c Collector) disks() []Disk {
	ents, err := os.ReadDir(c.path("sys/block"))
	if err != nil {
		return nil
	}
	var out []Disk
	for _, e := range ents {
		name := e.Name()
		if skipDisk.MatchString(name) {
			continue
		}
		base := "sys/block/" + name
		if _, err := os.Stat(c.path(base + "/device")); err != nil {
			continue
		}
		sectors, _ := strconv.ParseInt(c.read(base+"/size"), 10, 64)
		if sectors == 0 {
			continue // empty card reader, ejected media
		}
		d := Disk{
			Name:      name,
			SizeBytes: sectors * 512,
			Vendor:    clean(c.read(base + "/device/vendor")),
			Model:     clean(c.read(base + "/device/model")),
		}
		if c.read(base+"/queue/rotational") == "1" {
			d.Media = "HDD"
		} else {
			d.Media = "SSD"
		}
		d.Interface = c.diskInterface(name, base)
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// diskInterface names the bus a disk hangs off, by the driver of the SCSI host
// it sits behind. That is the only place the kernel says it: a SATA drive and a
// SAS drive are both sdX, and a RAID volume looks like a single disk.
func (c Collector) diskInterface(name, base string) string {
	switch {
	case strings.HasPrefix(name, "nvme"):
		return "NVMe"
	case strings.HasPrefix(name, "vd"):
		return "virtio"
	case strings.HasPrefix(name, "mmcblk"):
		return "MMC"
	}
	link, err := filepath.EvalSymlinks(c.path(base + "/device"))
	if err != nil {
		return ""
	}
	if strings.Contains(link, "/usb") {
		return "USB"
	}
	m := scsiHost.FindStringSubmatch(link)
	if m == nil {
		return ""
	}
	drv := c.read("sys/class/scsi_host/host" + m[1] + "/proc_name")
	switch {
	case drv == "ahci" || strings.HasPrefix(drv, "ata_") || strings.HasSuffix(drv, "_sata"):
		return "SATA"
	case strings.HasPrefix(drv, "mpt") || drv == "pm80xx" || drv == "isci" || drv == "hisi_sas":
		return "SAS"
	case drv == "hpsa" || drv == "smartpqi" || drv == "megaraid_sas" || drv == "aacraid" || drv == "cciss" || drv == "mpi3mr":
		return "RAID " + drv
	case drv == "virtio_scsi":
		return "virtio"
	}
	return drv
}

func (c Collector) nics() []NIC {
	ents, err := os.ReadDir(c.path("sys/class/net"))
	if err != nil {
		return nil
	}
	var out []NIC
	for _, e := range ents {
		name := e.Name()
		base := "sys/class/net/" + name
		// Physical ports have a device; bridges, bonds, VLANs, taps and veths
		// do not. SR-IOV VFs do, and are skipped by their physfn link.
		if _, err := os.Stat(c.path(base + "/device")); err != nil {
			continue
		}
		if _, err := os.Stat(c.path(base + "/device/physfn")); err == nil {
			continue
		}
		n := NIC{Name: name, MAC: c.read(base + "/address")}
		if sp, err := strconv.Atoi(c.read(base + "/speed")); err == nil && sp > 0 {
			n.SpeedMb = sp
		}
		if drv, err := filepath.EvalSymlinks(c.path(base + "/device/driver")); err == nil {
			n.Driver = filepath.Base(drv)
		}
		if c.PortOf != nil {
			if fibre, copper, maxMb, ok := c.PortOf(name); ok {
				n.MaxSpeedMb = maxMb
				n.Port = PortName(fibre, copper, max(maxMb, n.SpeedMb))
			}
		}
		if n.MaxSpeedMb < n.SpeedMb {
			n.MaxSpeedMb = n.SpeedMb
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
