package cli

import (
	"testing"

	"github.com/ghdwlsgur/vctl/internal/hwspec"
)

// sre-srv-0060 as collected on 2026-10-21, rendered the way its sheet row reads.
func TestSpecCellsReadLikeTheSheet(t *testing.T) {
	sp := hwspec.Spec{
		CPU:    hwspec.CPU{Sockets: 4, SocketsTotal: 4, CoresPerSocket: 10, Cores: 40},
		Memory: hwspec.Memory{TotalMB: 163840, SlotsTotal: 48, Modules: make([]hwspec.Module, 10)},
		Disks:  []hwspec.Disk{{Name: "sda", SizeBytes: 299966445568, Media: "HDD", Interface: "RAID hpsa"}},
	}
	for _, n := range []string{"eno49", "eno50", "eno51", "eno52"} {
		sp.NICs = append(sp.NICs, hwspec.NIC{Name: n, SpeedMb: 1000, MaxSpeedMb: 1000, Port: "UTP"})
	}
	for _, n := range []string{"ens1f0", "ens1f1"} {
		sp.NICs = append(sp.NICs, hwspec.NIC{Name: n, MaxSpeedMb: 10000, Port: "SFP+"})
	}
	sp.NICs[0].SpeedMb = 0

	if got := cpuCell(sp.CPU); got != "4/4×10C" {
		t.Errorf("cpu = %q", got)
	}
	if got := memoryCell(sp.Memory); got != "160GB (10/48)" {
		t.Errorf("memory = %q", got)
	}
	if got := diskCell(sp.Disks); got != "1×279.4GB HDD RAID hpsa" {
		t.Errorf("disk = %q", got)
	}
	if got := nicCell(sp.NICs); got != "2×10Gb SFP+, 4×1Gb UTP" {
		t.Errorf("nic = %q, want fastest first", got)
	}
	g := nicGroups(sp.NICs)
	if g[1].ports != 4 || g[1].up != 3 {
		t.Errorf("1Gb group = %+v, want 4 ports, 3 up", g[1])
	}
}

// What a collector could not see stays visibly unknown, never a zero that
// reads as a measurement.
func TestSpecCellsUnknown(t *testing.T) {
	if got := fraction(2, 0); got != "2" {
		t.Errorf("fraction(2,0) = %q, want 2 (ESXi reports no socket total)", got)
	}
	if got := cpuCell(hwspec.CPU{Sockets: 2, CoresPerSocket: 10, Cores: 20}); got != "2×10C" {
		t.Errorf("esxi cpu = %q", got)
	}
	if got := serialCell(hwspec.System{BoardSerial: "BZUB20801704"}); got != "BZUB20801704 (board)" {
		t.Errorf("board serial = %q", got)
	}
	if got := cpuCell(hwspec.CPU{}); got != "" {
		t.Errorf("empty cpu = %q", got)
	}
	if got := speedOf(0); got != "?" {
		t.Errorf("speedOf(0) = %q", got)
	}
	if got := sizeOf(2 * (1 << 40)); got != "2.0TB" {
		t.Errorf("sizeOf(2TiB) = %q", got)
	}
	if s, ty, sp := moduleSummary([]hwspec.Module{{SizeMB: 16384, Type: "DDR4", SpeedMHz: 2133}, {SizeMB: 32768, Type: "DDR4", SpeedMHz: 2133}}); s != "16/32" || ty != "DDR4" || sp != "2133" {
		t.Errorf("mixed DIMMs = %q %q %q, want them listed", s, ty, sp)
	}
}
