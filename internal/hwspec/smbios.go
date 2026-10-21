package hwspec

import (
	"encoding/binary"
	"strings"
)

// SMBIOS is what the firmware's structure table says, decoded for the three
// structures a spec needs: system (type 1), processor (type 4) and memory
// device (type 17).
//
// The table is /sys/firmware/dmi/tables/DMI, readable by root only. Reading it
// directly rather than running dmidecode keeps the agent free of a package it
// would otherwise depend on being installed on every host.
type SMBIOS struct {
	System     System
	Processors []Processor
	Memory     []MemoryDevice
}

// Processor is one socket, populated or not.
type Processor struct {
	Socket    string
	Version   string // the model string, "Intel(R) Xeon(R) CPU E5-4620 v3 @ 2.00GHz"
	Populated bool
	Cores     int
	Threads   int
	MHz       int // current speed
}

// MemoryDevice is one slot; SizeMB is zero for an empty one.
type MemoryDevice struct {
	Locator  string
	SizeMB   int64
	Type     string
	SpeedMHz int
}

// ParseSMBIOS decodes a raw structure table. It is lenient by design: a
// structure shorter than the field it would read leaves that field zero, and
// an unknown type is skipped, so firmware that is old or odd degrades to fewer
// facts rather than to none.
func ParseSMBIOS(b []byte) SMBIOS {
	var out SMBIOS
	for len(b) >= 4 {
		typ, length := b[0], int(b[1])
		if length < 4 || length > len(b) {
			break
		}
		formatted := b[:length]
		// The string set follows the formatted area and ends with two NULs.
		rest := b[length:]
		end := 0
		for end+1 < len(rest) && !(rest[end] == 0 && rest[end+1] == 0) {
			end++
		}
		strs := splitStrings(rest[:end])
		next := end + 2
		if next > len(rest) {
			next = len(rest)
		}
		b = rest[next:]

		str := func(off int) string {
			if off >= len(formatted) {
				return ""
			}
			i := int(formatted[off])
			if i == 0 || i > len(strs) {
				return ""
			}
			return clean(strs[i-1])
		}
		u8 := func(off int) int {
			if off >= len(formatted) {
				return 0
			}
			return int(formatted[off])
		}
		u16 := func(off int) int {
			if off+2 > len(formatted) {
				return 0
			}
			return int(binary.LittleEndian.Uint16(formatted[off:]))
		}
		u32 := func(off int) int64 {
			if off+4 > len(formatted) {
				return 0
			}
			return int64(binary.LittleEndian.Uint32(formatted[off:]))
		}

		switch typ {
		case 1:
			board := out.System.BoardSerial
			out.System = System{Vendor: str(0x04), Model: str(0x05), Serial: str(0x07), BoardSerial: board}
		case 2:
			out.System.BoardSerial = str(0x07)
		case 4:
			p := Processor{
				Socket:    str(0x04),
				Version:   str(0x10),
				Populated: u8(0x18)&0x40 != 0,
				MHz:       u16(0x16),
				Cores:     u8(0x23),
				Threads:   u8(0x25),
			}
			// 0xFF means "see the 3.0 word fields".
			if p.Cores == 0xFF {
				p.Cores = u16(0x2A)
			}
			if p.Threads == 0xFF {
				p.Threads = u16(0x2E)
			}
			out.Processors = append(out.Processors, p)
		case 17:
			d := MemoryDevice{Locator: str(0x10), Type: memoryType(u8(0x12)), SpeedMHz: u16(0x15)}
			switch size := u16(0x0C); {
			case size == 0 || size == 0xFFFF:
				// empty slot, or size unknown
			case size == 0x7FFF:
				d.SizeMB = u32(0x1C) & 0x7FFFFFFF
			case size&0x8000 != 0:
				d.SizeMB = int64(size&0x7FFF) / 1024 // KB granularity
			default:
				d.SizeMB = int64(size)
			}
			out.Memory = append(out.Memory, d)
		case 127:
			return out // end of table
		}
	}
	return out
}

func splitStrings(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	return strings.Split(string(b), "\x00")
}

// clean drops the placeholders vendors fill unused strings with: the words
// ("To be filled by O.E.M.", "Default string"), a run of dots (Intel S5520UR
// and S2600 chassis), and the digits 0123456789 some boards ship as a serial.
func clean(s string) string {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "not specified", "to be filled by o.e.m.", "default string", "none", "n/a", "unknown",
		"0123456789", "system serial number", "chassis serial number", "base board serial number":
		return ""
	}
	if strings.Trim(s, ". 0") == "" {
		return ""
	}
	return s
}

// memoryType maps the SMBIOS memory type byte to its name.
func memoryType(v int) string {
	switch v {
	case 0x0F:
		return "SDRAM"
	case 0x12:
		return "DDR"
	case 0x13:
		return "DDR2"
	case 0x18:
		return "DDR3"
	case 0x1A:
		return "DDR4"
	case 0x1B:
		return "LPDDR"
	case 0x1E:
		return "LPDDR3"
	case 0x1F:
		return "LPDDR4"
	case 0x22:
		return "DDR5"
	case 0x23:
		return "LPDDR5"
	}
	return ""
}

// Apply folds what the firmware says into a spec.
func (s SMBIOS) Apply(sp *Spec) {
	// Field by field: the table may name the board but not the system, and
	// what sysfs already said must not be blanked by what the table lacks.
	if s.System.Vendor != "" {
		sp.System.Vendor = s.System.Vendor
	}
	if s.System.Model != "" {
		sp.System.Model = s.System.Model
	}
	if s.System.Serial != "" {
		sp.System.Serial = s.System.Serial
	}
	if s.System.BoardSerial != "" {
		sp.System.BoardSerial = s.System.BoardSerial
	}
	if len(s.Processors) > 0 {
		sp.CPU.SocketsTotal = len(s.Processors)
		sp.CPU.Sockets, sp.CPU.Cores, sp.CPU.Threads = 0, 0, 0
		for _, p := range s.Processors {
			if !p.Populated {
				continue
			}
			sp.CPU.Sockets++
			sp.CPU.Cores += p.Cores
			sp.CPU.Threads += p.Threads
			if sp.CPU.Model == "" {
				sp.CPU.Model = p.Version
			}
			if sp.CPU.CoresPerSocket == 0 {
				sp.CPU.CoresPerSocket = p.Cores
			}
			if sp.CPU.MHz == 0 {
				sp.CPU.MHz = p.MHz
			}
		}
	}
	if len(s.Memory) > 0 {
		sp.Memory.SlotsTotal = len(s.Memory)
		sp.Memory.Modules = nil
		var total int64
		for _, d := range s.Memory {
			if d.SizeMB == 0 {
				continue
			}
			sp.Memory.Modules = append(sp.Memory.Modules,
				Module{Locator: d.Locator, SizeMB: d.SizeMB, Type: d.Type, SpeedMHz: d.SpeedMHz})
			total += d.SizeMB
		}
		if total > 0 {
			sp.Memory.TotalMB = total
		}
	}
}
