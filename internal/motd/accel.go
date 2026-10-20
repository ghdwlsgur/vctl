package motd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Where the banner learns what accelerators the machine carries. The PCI bus
// is read, not the inventory: a GPU line typed into a spreadsheet goes stale
// the same way the hand-maintained /etc/motd did, while sysfs is the card
// itself.
const SysPCIDevices = "/sys/bus/pci/devices"

// PCIIDs are the pci.ids databases tried in order: Rocky keeps it in hwdata,
// Ubuntu in misc (with hwdata a symlink to it on newer releases).
var PCIIDs = []string{"/usr/share/hwdata/pci.ids", "/usr/share/misc/pci.ids"}

// GPUs are display-class devices from these vendors only. Every server in the
// fleet also has a display-class BMC chip (ASPEED 1a03:2000), which is not a
// GPU, and class alone cannot tell the two apart.
var gpuVendors = map[string]bool{"10de": true, "1002": true} // NVIDIA, AMD

type accel struct {
	kind, vendor, device string
	passthrough          bool
}

// Accelerators reports the machine's GPUs and processing accelerators (PCI
// class 0x12 — the NPUs) as banner lines, one per model, e.g.
//
//	GPU         : 1x NVIDIA Tesla V100 PCIe 32GB
//	Accelerator : 2x FuriosaAI 1ed2:0001 (2 passed through to VMs)
//
// A device bound to vfio-pci is still in the machine but belongs to a VM, so
// it is counted and says so. Nil when there is nothing, including when sysfs
// cannot be read — the banner then simply has no hardware line.
func Accelerators(sysPCI string, pciIDs []string) []string {
	ents, err := os.ReadDir(sysPCI)
	if err != nil {
		return nil
	}
	var found []accel
	for _, e := range ents {
		d := filepath.Join(sysPCI, e.Name())
		class, vendor, device := sysHex(d, "class"), sysHex(d, "vendor"), sysHex(d, "device")
		var kind string
		switch {
		case strings.HasPrefix(class, "03") && gpuVendors[vendor]:
			kind = "GPU"
		case strings.HasPrefix(class, "12"):
			kind = "Accelerator"
		default:
			continue
		}
		drv, _ := os.Readlink(filepath.Join(d, "driver"))
		found = append(found, accel{kind: kind, vendor: vendor, device: device,
			passthrough: filepath.Base(drv) == "vfio-pci"})
	}
	if len(found) == 0 {
		return nil
	}

	names := lookupNames(pciIDs, found)
	type group struct {
		kind, name string
		n, vfio    int
	}
	var groups []*group
	byKey := map[string]*group{}
	for _, a := range found {
		name := names[a.vendor+":"+a.device]
		if name == "" {
			name = a.vendor + ":" + a.device
		}
		k := a.kind + "\x00" + name
		g := byKey[k]
		if g == nil {
			g = &group{kind: a.kind, name: name}
			byKey[k] = g
			groups = append(groups, g)
		}
		g.n++
		if a.passthrough {
			g.vfio++
		}
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].kind > groups[j].kind }) // GPU first

	labelW := 0
	for _, g := range groups {
		labelW = max(labelW, len(g.kind))
	}
	lines := make([]string, 0, len(groups))
	for _, g := range groups {
		ln := fmt.Sprintf("%-*s : %dx %s", labelW, g.kind, g.n, g.name)
		if g.vfio > 0 {
			ln += fmt.Sprintf(" (%d passed through to VMs)", g.vfio)
		}
		lines = append(lines, ln)
	}
	return lines
}

// sysHex reads a sysfs id file ("0x10de\n") as bare lowercase hex ("10de").
func sysHex(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(string(b))), "0x")
}

// lookupNames maps "vendor:device" to a readable model name from the first
// pci.ids that opens. Only the ids asked for are kept, so a 1.5 MB database
// costs a scan, not a 1.5 MB map, under the agent's memory limit.
func lookupNames(paths []string, want []accel) map[string]string {
	vendors := map[string]bool{}
	for _, a := range want {
		vendors[a.vendor] = true
	}
	out := map[string]string{}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()
		var vendor, vendorName string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			ln := sc.Text()
			if ln == "" || ln[0] == '#' || strings.HasPrefix(ln, "\t\t") {
				continue
			}
			if ln[0] != '\t' {
				// "C xx" opens the class list at the end of the file; vendors are done.
				if strings.HasPrefix(ln, "C ") {
					break
				}
				id, name, _ := strings.Cut(ln, "  ")
				vendor, vendorName = id, shortVendor(name)
				continue
			}
			if !vendors[vendor] {
				continue
			}
			id, name, _ := strings.Cut(ln[1:], "  ")
			out[vendor+":"+id] = modelName(vendorName, name)
		}
		// A read error leaves the rest unnamed; those print as vendor:device.
		_ = sc.Err()
		return out
	}
	return out
}

// shortVendor turns "NVIDIA Corporation" into "NVIDIA" and
// "Advanced Micro Devices, Inc. [AMD/ATI]" into "AMD/ATI".
func shortVendor(name string) string {
	if b := bracketed(name); b != "" {
		return b
	}
	for _, s := range []string{" Corporation", ", Inc.", " Inc.", " Co., Ltd.", " Ltd."} {
		name = strings.TrimSuffix(name, s)
	}
	return name
}

// modelName prefers the marketing name pci.ids keeps in brackets
// ("GV100GL [Tesla V100 PCIe 32GB]" → "NVIDIA Tesla V100 PCIe 32GB").
func modelName(vendor, device string) string {
	if b := bracketed(device); b != "" {
		device = b
	}
	if vendor == "" || strings.HasPrefix(device, vendor) {
		return device
	}
	return vendor + " " + device
}

func bracketed(s string) string {
	i, j := strings.LastIndex(s, "["), strings.LastIndex(s, "]")
	if i < 0 || j < i {
		return ""
	}
	return s[i+1 : j]
}
