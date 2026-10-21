package hwspec

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// structure builds one SMBIOS structure: the formatted area (header included)
// and its string set.
func structure(typ byte, formatted []byte, strs ...string) []byte {
	b := append([]byte{typ, byte(len(formatted) + 4), 0, 0}, formatted...)
	if len(strs) == 0 {
		return append(b, 0, 0)
	}
	for _, s := range strs {
		b = append(append(b, s...), 0)
	}
	return append(b, 0)
}

func processor(populated bool, cores, threads byte, mhz uint16) []byte {
	f := make([]byte, 0x28-4)
	f[0x04-4] = 1 // socket string
	f[0x10-4] = 2 // version string
	binary.LittleEndian.PutUint16(f[0x16-4:], mhz)
	if populated {
		f[0x18-4] = 0x41
	}
	f[0x23-4], f[0x25-4] = cores, threads
	return structure(4, f, "Proc 1", "Intel(R) Xeon(R) CPU E5-4620 v3 @ 2.00GHz")
}

func dimm(sizeMB uint16, typ byte, speed uint16) []byte {
	f := make([]byte, 0x22-4)
	binary.LittleEndian.PutUint16(f[0x0C-4:], sizeMB)
	f[0x10-4] = 1
	f[0x12-4] = typ
	binary.LittleEndian.PutUint16(f[0x15-4:], speed)
	return structure(17, f, "PROC 1 DIMM 1")
}

// sre-srv-0060's sheet row: 4/4 sockets of 10 cores, 10 of 48 slots holding
// 16GB DDR4-2133.
func TestSMBIOSFoldsIntoTheSheetRow(t *testing.T) {
	sys := make([]byte, 0x08-4)
	sys[0x04-4], sys[0x05-4], sys[0x07-4] = 1, 2, 3
	table := structure(1, sys, "HP", "ProLiant DL560 Gen9", "SGH610V58C")
	for range 4 {
		table = append(table, processor(true, 10, 20, 2600)...)
	}
	for i := range 48 {
		if i < 10 {
			table = append(table, dimm(16384, 0x1A, 2133)...)
		} else {
			table = append(table, dimm(0, 0x02, 0)...)
		}
	}
	table = append(table, structure(127, nil)...)

	var sp Spec
	ParseSMBIOS(table).Apply(&sp)
	if sp.System != (System{"HP", "ProLiant DL560 Gen9", "SGH610V58C"}) {
		t.Errorf("system = %+v", sp.System)
	}
	c := sp.CPU
	if c.Sockets != 4 || c.SocketsTotal != 4 || c.CoresPerSocket != 10 || c.Cores != 40 || c.Threads != 80 {
		t.Errorf("cpu = %+v, want 4/4 sockets, 10/40 cores, 80 threads", c)
	}
	if c.Model != "Intel(R) Xeon(R) CPU E5-4620 v3 @ 2.00GHz" {
		t.Errorf("model = %q", c.Model)
	}
	m := sp.Memory
	if m.SlotsTotal != 48 || m.MemorySlotsUsed() != 10 || m.TotalMB != 163840 {
		t.Errorf("memory = %d/%d slots, %d MB; want 10/48, 163840", m.MemorySlotsUsed(), m.SlotsTotal, m.TotalMB)
	}
	if mod := m.Modules[0]; mod.SizeMB != 16384 || mod.Type != "DDR4" || mod.SpeedMHz != 2133 {
		t.Errorf("module = %+v", mod)
	}
}

// An empty socket counts toward the board's total and nothing else.
func TestSMBIOSEmptySocket(t *testing.T) {
	table := append(processor(true, 18, 36, 2300), processor(false, 0, 0, 0)...)
	var sp Spec
	ParseSMBIOS(table).Apply(&sp)
	if sp.CPU.Sockets != 1 || sp.CPU.SocketsTotal != 2 || sp.CPU.Cores != 18 {
		t.Fatalf("cpu = %+v, want 1/2 sockets, 18 cores", sp.CPU)
	}
}

// A truncated or garbage table yields what it can, never a panic.
func TestSMBIOSTruncated(t *testing.T) {
	full := processor(true, 10, 20, 2600)
	for i := range full {
		_ = ParseSMBIOS(full[:i])
	}
	_ = ParseSMBIOS([]byte{4, 2, 0, 0})
}

func TestPortName(t *testing.T) {
	for _, c := range []struct {
		fibre, copper bool
		mb            int
		want          string
	}{
		{false, true, 1000, "UTP"},
		{false, true, 10000, "UTP"}, // 10GBASE-T is still twisted pair
		{true, false, 10000, "SFP+"},
		{true, false, 25000, "SFP28"},
		{true, false, 40000, "QSFP+"},
		{true, false, 1000, "SFP"},
		{false, false, 0, ""},
	} {
		if got := PortName(c.fibre, c.copper, c.mb); got != c.want {
			t.Errorf("PortName(%v,%v,%d) = %q, want %q", c.fibre, c.copper, c.mb, got, c.want)
		}
	}
}

func write(t *testing.T, root, p, body string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func link(t *testing.T, root, target, name string) {
	t.Helper()
	full := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, target), full); err != nil {
		t.Fatal(err)
	}
}

// A fake host: one RAID volume behind hpsa, one NVMe drive, a loop device and
// a bridge that must not count, one physical NIC and one SR-IOV VF that must
// not either.
func fakeHost(t *testing.T, flags string) Collector {
	root := t.TempDir()
	write(t, root, "proc/cpuinfo", "processor\t: 0\nmodel name\t: Intel(R) Xeon(R)  Gold 6140\nphysical id\t: 0\ncore id\t: 0\nflags\t: fpu "+flags+"\n\nprocessor\t: 1\nphysical id\t: 0\ncore id\t: 1\n")
	write(t, root, "proc/meminfo", "MemTotal:       263840000 kB\n")
	write(t, root, "etc/os-release", "NAME=\"Rocky Linux\"\nPRETTY_NAME=\"Rocky Linux 9.6 (Blue Onyx)\"\n")
	write(t, root, "sys/class/dmi/id/sys_vendor", "HP\n")
	write(t, root, "sys/class/dmi/id/product_name", "ProLiant DL560 Gen9\n")

	link(t, root, "sys/devices/pci0000:00/0000:00:01.0/host0/target0:1:0/0:1:0:0", "sys/block/sda/device")
	write(t, root, "sys/block/sda/size", "585871964\n")
	write(t, root, "sys/block/sda/queue/rotational", "1\n")
	write(t, root, "sys/block/sda/device/model", "LOGICAL VOLUME  \n")
	write(t, root, "sys/class/scsi_host/host0/proc_name", "hpsa\n")
	link(t, root, "sys/devices/pci0000:00/0000:00:02.0/nvme/nvme0", "sys/block/nvme0n1/device")
	write(t, root, "sys/block/nvme0n1/size", "1953525168\n")
	write(t, root, "sys/block/nvme0n1/queue/rotational", "0\n")
	write(t, root, "sys/block/loop0/size", "100\n")

	link(t, root, "sys/devices/pci0000:00/0000:00:03.0", "sys/class/net/eno1/device")
	write(t, root, "sys/class/net/eno1/address", "28:80:23:b0:07:54\n")
	write(t, root, "sys/class/net/eno1/speed", "-1\n")
	link(t, root, "sys/devices/pci0000:00/0000:00:04.1", "sys/class/net/eno1v0/device")
	link(t, root, "sys/devices/pci0000:00/0000:00:04.0", "sys/class/net/eno1v0/device/physfn")
	write(t, root, "sys/class/net/br0/address", "aa:bb:cc:dd:ee:ff\n")

	return Collector{Root: root, PortOf: func(string) (bool, bool, int, bool) { return true, false, 10000, true }}
}

func TestCollectReadsAFakeHost(t *testing.T) {
	sp, err := fakeHost(t, "sse").Collect()
	if err != nil {
		t.Fatal(err)
	}
	if sp.OS != "Rocky Linux 9.6 (Blue Onyx)" || sp.System.Vendor != "HP" || sp.CPU.Model != "Intel(R) Xeon(R) Gold 6140" {
		t.Errorf("identity = %q %+v %q", sp.OS, sp.System, sp.CPU.Model)
	}
	if len(sp.Disks) != 2 {
		t.Fatalf("disks = %+v, want sda and nvme0n1 only", sp.Disks)
	}
	if d := sp.Disks[1]; d.Name != "sda" || d.Interface != "RAID hpsa" || d.Media != "HDD" || d.Model != "LOGICAL VOLUME" || d.SizeBytes != 585871964*512 {
		t.Errorf("sda = %+v", d)
	}
	if d := sp.Disks[0]; d.Interface != "NVMe" || d.Media != "SSD" {
		t.Errorf("nvme = %+v", d)
	}
	if len(sp.NICs) != 1 {
		t.Fatalf("nics = %+v, want eno1 only (no bridge, no VF)", sp.NICs)
	}
	if n := sp.NICs[0]; n.SpeedMb != 0 || n.MaxSpeedMb != 10000 || n.Port != "SFP+" {
		t.Errorf("eno1 = %+v, want a down 10Gb SFP+ port", n)
	}
}

func TestCollectRefusesGuests(t *testing.T) {
	if _, err := fakeHost(t, "sse hypervisor").Collect(); !errors.Is(err, ErrVirtual) {
		t.Fatalf("err = %v, want ErrVirtual", err)
	}
}
