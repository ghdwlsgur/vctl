// Package hwspec describes a bare-metal machine's hardware — the part of an
// asset sheet a machine can report about itself.
//
// The sheet the SRE team kept by hand (vendor, model, serial, CPU sockets and
// cores, DIMMs and slots, disks, NIC ports) goes stale the same way the
// hand-written /etc/motd did. Every line of it except the operator's own notes
// (IDC, rack, labels, purpose — store.Asset) is readable from the machine, so
// the collectors fill a Spec and the sheet becomes a view of it.
//
// Two collectors fill it: the node-agent on Linux hosts (SMBIOS and sysfs) and
// the vSphere poller on ESXi hosts. Fields a collector cannot see stay zero, and
// a zero renders as unknown rather than as a measurement of nothing.
package hwspec

// Spec is one machine's hardware.
type Spec struct {
	System System `json:"system"`
	OS     string `json:"os,omitempty"`
	CPU    CPU    `json:"cpu"`
	Memory Memory `json:"memory"`
	Disks  []Disk `json:"disks,omitempty"`
	NICs   []NIC  `json:"nics,omitempty"`
}

// System is the chassis identity.
type System struct {
	Vendor string `json:"vendor,omitempty"`
	Model  string `json:"model,omitempty"`
	Serial string `json:"serial,omitempty"`
}

// CPU is the processors, summed over sockets.
type CPU struct {
	Model string `json:"model,omitempty"`
	// Sockets is how many are populated, SocketsTotal how many the board has.
	// ESXi reports only the first, so SocketsTotal is zero there.
	Sockets      int `json:"sockets,omitempty"`
	SocketsTotal int `json:"sockets_total,omitempty"`
	// CoresPerSocket is one package's cores; Cores and Threads the machine's.
	CoresPerSocket int `json:"cores_per_socket,omitempty"`
	Cores          int `json:"cores,omitempty"`
	Threads        int `json:"threads,omitempty"`
	MHz            int `json:"mhz,omitempty"`
}

// Memory is the installed DIMMs. Modules lists populated slots only; SlotsTotal
// counts every slot the firmware describes, empty or not.
type Memory struct {
	TotalMB    int64    `json:"total_mb,omitempty"`
	Modules    []Module `json:"modules,omitempty"`
	SlotsTotal int      `json:"slots_total,omitempty"`
}

// Module is one populated DIMM slot.
type Module struct {
	Locator  string `json:"locator,omitempty"`
	SizeMB   int64  `json:"size_mb"`
	Type     string `json:"type,omitempty"`      // DDR4, DDR5, ...
	SpeedMHz int    `json:"speed_mhz,omitempty"` // rated speed, MT/s as SMBIOS reports it
}

// Disk is one block device the OS sees. Behind a RAID controller that is the
// logical volume, not the drives in it: Interface then names the controller
// ("RAID hpsa") and the drive count has to come from the operator's notes.
type Disk struct {
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
	Media     string `json:"media,omitempty"`     // HDD | SSD
	Interface string `json:"interface,omitempty"` // SAS | SATA | NVMe | RAID <driver> | ...
	Vendor    string `json:"vendor,omitempty"`
	Model     string `json:"model,omitempty"`
}

// NIC is one physical port.
type NIC struct {
	Name string `json:"name"`
	MAC  string `json:"mac,omitempty"`
	// SpeedMb is the negotiated speed, 0 when the link is down; MaxSpeedMb the
	// fastest the port supports, which is what a sheet calls a "10Gb port".
	SpeedMb    int    `json:"speed_mb"`
	MaxSpeedMb int    `json:"max_speed_mb,omitempty"`
	Port       string `json:"port,omitempty"` // UTP | SFP | SFP+ | SFP28 | QSFP+ | ...
	Driver     string `json:"driver,omitempty"`
}

// MemorySlotsUsed is the populated slot count.
func (m Memory) MemorySlotsUsed() int { return len(m.Modules) }

// PortName names a port by its connector and fastest speed the way the asset
// sheet does: a 10Gb fibre or DAC cage is "SFP+", twisted pair is "UTP".
func PortName(fibre, copper bool, maxMb int) string {
	switch {
	case fibre && maxMb >= 100000:
		return "QSFP28"
	case fibre && maxMb >= 40000:
		return "QSFP+"
	case fibre && maxMb >= 25000:
		return "SFP28"
	case fibre && maxMb >= 10000:
		return "SFP+"
	case fibre:
		return "SFP"
	case copper:
		return "UTP"
	}
	return ""
}
