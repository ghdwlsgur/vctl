package cmdkit

import (
	"net"
	"strconv"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// StateCell renders what an operator declared about a host, and renders nothing
// when that is "active".
//
// Same trade as the port: active is the overwhelming majority, and labelling
// every row with it would bury the handful that are not. What is left is a
// column that is blank unless somebody has something to say.
//
// The colours encode whether a down reading on that row is news. broken is red
// because it is a fault; maintenance is amber because it is planned and
// temporary; retired is muted because nothing is expected of it any more.
func StateCell(state string) string {
	switch store.StateOrActive(state) {
	case store.StateBroken:
		return ui.Fail(store.StateBroken)
	case store.StateMaintenance:
		return ui.Warn("maint")
	case store.StateRetired:
		return ui.Muted(store.StateRetired)
	default:
		return ""
	}
}

// AddrCell renders the address a connection would actually use, showing the
// port only when it is not 22.
//
// Non-default ports are common enough to matter and rare enough that printing
// all of them would be the wrong trade: in the inventory this was written
// against, 18 of 123 hosts differ, across four values. Rendering ":22" on the
// other 105 to surface those 18 puts the noise on the majority of rows and
// makes the exceptions no easier to find — the eye is scanning for a
// difference, and a column where every cell has a suffix has none.
//
// Omitting it is only safe because the omission is unambiguous: nothing else
// puts a colon in this column, so a bare address means 22 rather than "unknown".
func AddrCell(ip string, port int) string {
	if port == 0 || port == defaultSSHPort {
		return ip
	}
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

// defaultSSHPort is the port a bare address implies, and the one worth omitting.
const defaultSSHPort = 22
