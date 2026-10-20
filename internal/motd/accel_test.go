package motd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// pciDev fakes one /sys/bus/pci/devices entry.
func pciDev(t *testing.T, root, addr, class, vendor, device, driver string) {
	t.Helper()
	d := filepath.Join(root, addr)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"class": class, "vendor": vendor, "device": device} {
		if err := os.WriteFile(filepath.Join(d, name), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if driver != "" {
		if err := os.Symlink("../../../bus/pci/drivers/"+driver, filepath.Join(d, "driver")); err != nil {
			t.Fatal(err)
		}
	}
}

const testPCIIDs = `# comment
10de  NVIDIA Corporation
	1db6  GV100GL [Tesla V100 PCIe 32GB]
		10de 124a  Tesla V100 PCIe 32GB
	20b5  GA100 [A100 PCIe 80GB]
1a03  ASPEED Technology, Inc.
	2000  ASPEED Graphics Family
C 03  Display controller
`

func writeIDs(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pci.ids")
	if err := os.WriteFile(p, []byte(testPCIIDs), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// sre-srv-0037 as found on 2026-10-20: one V100 and the BMC's display chip,
// which every server has and is not a GPU.
func TestAcceleratorsNamesTheGPUAndSkipsTheBMC(t *testing.T) {
	root := t.TempDir()
	pciDev(t, root, "0000:02:00.0", "0x030000", "0x1a03", "0x2000", "ast")
	pciDev(t, root, "0000:18:00.0", "0x030200", "0x10de", "0x1db6", "nvidia")
	pciDev(t, root, "0000:19:00.0", "0x020000", "0x8086", "0x1521", "igb")

	got := Accelerators(root, []string{"/nonexistent", writeIDs(t)})
	want := []string{"GPU : 1x NVIDIA Tesla V100 PCIe 32GB"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestAcceleratorsGroupsCountsPassthroughAndNPUs(t *testing.T) {
	root := t.TempDir()
	pciDev(t, root, "0000:17:00.0", "0x030200", "0x10de", "0x20b5", "vfio-pci")
	pciDev(t, root, "0000:31:00.0", "0x030200", "0x10de", "0x20b5", "nvidia")
	pciDev(t, root, "0000:4b:00.0", "0x120000", "0x1ed2", "0x0001", "vfio-pci")

	got := Accelerators(root, []string{writeIDs(t)})
	want := []string{
		"GPU         : 2x NVIDIA A100 PCIe 80GB (1 passed through to VMs)",
		"Accelerator : 1x 1ed2:0001 (1 passed through to VMs)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestAcceleratorsNoneMeansNoLine(t *testing.T) {
	root := t.TempDir()
	pciDev(t, root, "0000:02:00.0", "0x030000", "0x1a03", "0x2000", "ast")
	if got := Accelerators(root, nil); got != nil {
		t.Fatalf("got %q, want nil", got)
	}
	if got := Accelerators(filepath.Join(root, "missing"), nil); got != nil {
		t.Fatalf("unreadable sysfs: got %q, want nil", got)
	}
}

func TestRenderPrintsHardwareOnAFarmlessHost(t *testing.T) {
	got := Render(Banner{
		Header:    "== ART ==",
		ManagedBy: "Managed by Innogrid SRE Team.",
		Self:      "sre-srv-0037",
		Hardware:  []string{"GPU : 1x NVIDIA Tesla V100 PCIe 32GB"},
	}, nil)
	want := `== ART ==

Managed by Innogrid SRE Team.

GPU : 1x NVIDIA Tesla V100 PCIe 32GB
`
	if got != want {
		t.Fatalf("banner mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderPrintsHardwareAboveTheTopology(t *testing.T) {
	got := Render(Banner{ManagedBy: "M.", Self: "sre-srv-0025", Hardware: []string{"GPU : 1x X"}},
		[]store.FarmTopology{seoulB()})
	if !strings.Contains(got, "Used by AI Native Platform team.\n\nGPU : 1x X\n\n[ Cluster Topology") {
		t.Fatalf("hardware not between the fixed lines and the topology:\n%s", got)
	}
}
