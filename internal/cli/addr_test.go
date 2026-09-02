package cli

import (
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// The port belongs on screen because it varies: in the inventory this was
// written against, 18 of 123 hosts are on something other than 22, across four
// values. Reading a row and dialling the wrong port is the failure that costs a
// round trip through `vctl list` to diagnose.
func TestAddrCellShowsOnlyNonDefaultPorts(t *testing.T) {
	for _, tc := range []struct {
		name string
		ip   string
		port int
		want string
	}{
		{"default is implied", "192.0.2.10", 22, "192.0.2.10"},
		{"unset reads as default", "192.0.2.10", 0, "192.0.2.10"},
		{"non-default is spelled out", "192.0.2.10", 10022, "192.0.2.10:10022"},
		{"low non-default", "192.0.2.10", 122, "192.0.2.10:122"},
		// Bracketing is not cosmetic: "fd00::1:2222" cannot be split back into an
		// address and a port, so an unbracketed IPv6 row would be unusable.
		{"IPv6 is bracketed", "fd00::1", 2222, "[fd00::1]:2222"},
		{"IPv6 on the default port is bare", "fd00::1", 22, "fd00::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cmdkit.AddrCell(tc.ip, tc.port); got != tc.want {
				t.Errorf("cmdkit.AddrCell(%q, %d) = %q, want %q", tc.ip, tc.port, got, tc.want)
			}
		})
	}
}

// The listing's address cell already carries the multi-homed marker. The port
// has to land on the primary and the marker has to survive.
func TestIPCellCarriesThePortAlongsideTheExtrasMarker(t *testing.T) {
	row := store.InventoryRow{
		Server:    store.Server{IP: "172.21.0.11", Port: 10022},
		Addresses: []string{"172.21.0.11", "10.88.0.1", "172.17.0.1"},
	}
	got := ui.StripANSI(ipCell(row, false))
	if !strings.HasPrefix(got, "172.21.0.11:10022") {
		t.Errorf("ipCell = %q, want it to start with the address and port", got)
	}
	if !strings.Contains(got, "(+2)") {
		t.Errorf("ipCell = %q, want the extras marker kept", got)
	}
	// Only the primary is dialled, so repeating the port on the extras would
	// state the same fact three times.
	if n := strings.Count(got, "10022"); n != 1 {
		t.Errorf("ipCell = %q names the port %d times, want once", got, n)
	}
}

// A port on screen has to be typeable, or showing it only answers half the
// question — "which hosts are behind 10022" is the query that motivates it.
func TestPickerFilterMatchesThePort(t *testing.T) {
	c := store.ServerWithStatus{Server: store.Server{
		Hostname: "ctl01", IP: "172.21.0.11", Port: 10022, DC: "coex-onprem", User: "rocky",
	}}
	if !matchServer(c, "10022") {
		t.Error("typing the port does not find the host")
	}
	if matchServer(c, "10023") {
		t.Error("a port that is not this host's matched anyway")
	}
}

// The address column only grows for the lists that need it: the picker
// measures its grid across every row, so a fleet entirely on 22 shows no port
// anywhere, and one host on 2032 is what widens the column — aligned across
// every label, or the grid stops being a grid.
func TestServerPickLabelsGrowTheAddressColumnOnlyWhenNeeded(t *testing.T) {
	plain := []store.ServerWithStatus{
		{Server: store.Server{Hostname: "web-01", IP: "192.168.10.35", Port: 22, DC: "seoul"}},
		{Server: store.Server{Hostname: "web-02", IP: "172.18.0.11", Port: 22, DC: "seoul"}},
	}
	for _, l := range serverPickLabels(plain, false) {
		if strings.Contains(l, ":22") {
			t.Errorf("label %q spells out the default port", l)
		}
	}

	long := append(plain, store.ServerWithStatus{
		Server: store.Server{Hostname: "gw-01", IP: "211.172.228.230", Port: 2032, DC: "seoul"},
	})
	labels := serverPickLabels(long, false)
	if !strings.Contains(labels[2], "211.172.228.230:2032") {
		t.Errorf("label %q lost the non-default port", labels[2])
	}
	// Every label must place the DC cell at the same column, whichever row
	// forced the width.
	col := strings.Index(ui.StripANSI(labels[0]), " seoul")
	for _, l := range labels[1:] {
		if got := strings.Index(ui.StripANSI(l), " seoul"); got != col {
			t.Errorf("DC column drifted: %d vs %d in %q", got, col, l)
		}
	}
}

// The edit/delete picker reads from the same inventory, so a host that answers
// on a non-default port has to say so there too.
func TestHostPickLabelsCarryThePort(t *testing.T) {
	labels := cmdkit.HostPickLabels(rowsFull(
		store.Server{Hostname: "ctl01", IP: "172.21.0.11", Port: 10022, DC: "coex-onprem"},
		store.Server{Hostname: "aio01", IP: "172.18.0.11", Port: 22, DC: "incheon"},
	))
	if !strings.Contains(labels[0], "172.21.0.11:10022") {
		t.Errorf("label %q does not carry the port", labels[0])
	}
	if strings.Contains(labels[1], ":22") {
		t.Errorf("label %q spells out the default port", labels[1])
	}
}
