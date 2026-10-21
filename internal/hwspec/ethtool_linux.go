//go:build linux

package hwspec

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// ethtoolCmd is struct ethtool_cmd (ETHTOOL_GSET). The legacy call is enough
// here: the connector and the 32-bit supported mask cover every port this
// fleet has up to 40Gb, and every driver still answers it through the kernel's
// link-ksettings translation.
type ethtoolCmd struct {
	Cmd           uint32
	Supported     uint32
	Advertising   uint32
	Speed         uint16
	Duplex        uint8
	Port          uint8
	PhyAddress    uint8
	Transceiver   uint8
	Autoneg       uint8
	MdioSupport   uint8
	Maxtxpkt      uint32
	Maxrxpkt      uint32
	SpeedHi       uint16
	EthTpMdix     uint8
	EthTpMdixCtrl uint8
	LpAdvertising uint32
	Reserved      [2]uint32
}

const (
	ethtoolGSET = 0x00000001

	portTP    = 0x00
	portFibre = 0x03
	portDA    = 0x05

	supportedTP    = 1 << 7
	supportedFibre = 1 << 10
)

// supported-mode bits of the legacy mask and the speed each stands for.
var modeSpeed = []struct {
	bit uint32
	mb  int
}{
	{1 << 0, 10}, {1 << 1, 10}, {1 << 2, 100}, {1 << 3, 100},
	{1 << 4, 1000}, {1 << 5, 1000}, {1 << 17, 1000},
	{1 << 15, 2500},
	{1 << 12, 10000}, {1 << 18, 10000}, {1 << 19, 10000}, {1 << 20, 10000},
	{1 << 21, 20000}, {1 << 22, 20000},
	{1 << 23, 40000}, {1 << 24, 40000}, {1 << 25, 40000}, {1 << 26, 40000},
	{1 << 27, 56000}, {1 << 28, 56000}, {1 << 29, 56000}, {1 << 30, 56000},
}

// ethtoolPort asks the driver what connector a port has and how fast it goes.
func ethtoolPort(ifname string) (fibre, copper bool, maxMb int, ok bool) {
	if len(ifname) >= unix.IFNAMSIZ {
		return false, false, 0, false
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false, false, 0, false
	}
	defer unix.Close(fd)

	cmd := ethtoolCmd{Cmd: ethtoolGSET}
	var ifr [40]byte // struct ifreq: name, then the union holding the data pointer
	copy(ifr[:unix.IFNAMSIZ], ifname)
	*(*uintptr)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = uintptr(unsafe.Pointer(&cmd))
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return false, false, 0, false
	}

	for _, m := range modeSpeed {
		if cmd.Supported&m.bit != 0 && m.mb > maxMb {
			maxMb = m.mb
		}
	}
	switch cmd.Port {
	case portFibre, portDA:
		fibre = true
	case portTP:
		copper = cmd.Supported&supportedTP != 0 || cmd.Supported&supportedFibre == 0
	}
	if !fibre && !copper {
		fibre = cmd.Supported&supportedFibre != 0
		copper = cmd.Supported&supportedTP != 0
	}
	return fibre, copper, maxMb, true
}
