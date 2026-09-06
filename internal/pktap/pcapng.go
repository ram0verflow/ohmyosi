package pktap

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

// A pcapng reader that keeps Apple's process metadata.
//
// Why this exists instead of gopacket's pcapgo.NgReader: when tcpdump captures
// from pktap across several interfaces it writes pcapng, and the process
// information does NOT arrive as a pktap header in front of each packet. It
// arrives in pcapng's option machinery, using Apple's own extension:
//
//   - A Process Information Block (type 0x80000001) carries a PID and a
//     process name. These accumulate through the section, and are referenced
//     by their order of appearance.
//   - Each Enhanced Packet Block points at one with option 0x8001, and at the
//     "effective" process - the one on whose behalf the socket was opened -
//     with option 0x8003.
//
// gopacket's reader discards packet options (its source says handling them
// "would be expensive"), so the PID is in the file and simply thrown away.
// Hence a small reader of our own. It handles only what tcpdump emits.
//
// The effective-process field is the interesting one long-term: it is how a
// DNS lookup performed by mDNSResponder can be traced back to the application
// that actually wanted it.

const (
	btSHB = 0x0a0d0d0a
	btIDB = 0x00000001
	btSPB = 0x00000003
	btEPB = 0x00000006
	btPIB = 0x80000001 // Apple: Process Information Block

	optEnd = 0

	optIfTsresol = 9 // IDB: timestamp resolution

	optEpbFlags     = 2      // standard: bits 0-1 hold direction
	optEpbPIBIndex  = 0x8001 // Apple: index into the PIB table
	optEpbEPIBIndex = 0x8003 // Apple: effective process

	optPibName = 2 // Apple: process name

	maxBlockLen = 16 << 20 // a corrupt length must not allocate the machine away
)

type ngIface struct {
	linkType uint32
	// tsPerSec is how many timestamp ticks make a second, from if_tsresol.
	// pcapng's default is microseconds, and tcpdump does not always say so.
	tsPerSec float64
}

type ngProc struct {
	pid  int32
	name string
}

type ngPacket struct {
	Ts       time.Time
	CapLen   int
	WireLen  int
	LinkType uint32
	Data     []byte

	PID   int32
	Comm  string
	EPID  int32
	EComm string
	Dir   Direction
}

type ngReader struct {
	r   *bufio.Reader
	end binary.ByteOrder

	ifaces []ngIface
	procs  []ngProc // indexed by order of appearance within the section

	buf []byte
}

func newNgReader(r *bufio.Reader) (*ngReader, error) {
	n := &ngReader{r: r, end: binary.LittleEndian, buf: make([]byte, 0, 64<<10)}
	// The first block must be a section header; reading it establishes byte order.
	bt, body, err := n.readBlock()
	if err != nil {
		return nil, err
	}
	if bt != btSHB {
		return nil, fmt.Errorf("pcapng: first block is %#x, not a section header", bt)
	}
	return n, n.section(body)
}

// readBlock returns one block's type and body. body aliases an internal buffer
// and is only valid until the next call.
func (n *ngReader) readBlock() (uint32, []byte, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(n.r, hdr[:]); err != nil {
		return 0, nil, err
	}
	bt := n.end.Uint32(hdr[0:4])
	blen := n.end.Uint32(hdr[4:8])
	// A section header can flip byte order mid-file, and its own length field
	// is written in the new order. Detect the swapped form and correct.
	if bt == btSHB && (blen < 16 || blen > maxBlockLen) {
		blen = swap32(blen)
	}
	if blen < 12 || blen > maxBlockLen {
		return 0, nil, fmt.Errorf("pcapng: implausible block length %d for type %#x", blen, bt)
	}
	rest := int(blen) - 8
	if cap(n.buf) < rest {
		n.buf = make([]byte, rest)
	}
	n.buf = n.buf[:rest]
	if _, err := io.ReadFull(n.r, n.buf); err != nil {
		return 0, nil, err
	}
	return bt, n.buf[:rest-4], nil // drop the trailing length copy
}

func swap32(v uint32) uint32 {
	return v>>24 | (v>>8)&0xff00 | (v<<8)&0xff0000 | v<<24
}

// section resets per-section state and fixes byte order from the magic.
func (n *ngReader) section(body []byte) error {
	if len(body) < 4 {
		return errors.New("pcapng: short section header")
	}
	switch binary.LittleEndian.Uint32(body[0:4]) {
	case 0x1a2b3c4d:
		n.end = binary.LittleEndian
	case 0x4d3c2b1a:
		n.end = binary.BigEndian
	default:
		return errors.New("pcapng: bad byte-order magic")
	}
	// Interface and process tables are scoped to the section.
	n.ifaces = n.ifaces[:0]
	n.procs = n.procs[:0]
	return nil
}

// eachOption walks a pcapng option list, which runs to an end-of-options marker
// or the end of the body. Values are padded to four bytes.
func (n *ngReader) eachOption(body []byte, fn func(code uint16, val []byte)) {
	for p := 0; p+4 <= len(body); {
		code := n.end.Uint16(body[p : p+2])
		l := int(n.end.Uint16(body[p+2 : p+4]))
		p += 4
		if code == optEnd {
			return
		}
		if p+l > len(body) {
			return
		}
		fn(code, body[p:p+l])
		p += (l + 3) &^ 3
	}
}

func (n *ngReader) u32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return n.end.Uint32(b[:4])
}

// next returns the next packet, consuming and applying any interface, process
// or section blocks it passes along the way.
func (n *ngReader) next() (*ngPacket, error) {
	for {
		bt, body, err := n.readBlock()
		if err != nil {
			return nil, err
		}
		switch bt {
		case btSHB:
			if err := n.section(body); err != nil {
				return nil, err
			}
		case btIDB:
			n.addInterface(body)
		case btPIB:
			n.addProcess(body)
		case btEPB:
			if p := n.packet(body); p != nil {
				return p, nil
			}
		case btSPB:
			// No interface id, no options, no process. Rare from tcpdump.
			if len(body) >= 4 && len(n.ifaces) > 0 {
				return &ngPacket{
					Ts: time.Now(), LinkType: n.ifaces[0].linkType,
					CapLen: len(body) - 4, WireLen: int(n.u32(body)), Data: body[4:],
				}, nil
			}
		}
		// Anything else is a block type we do not need. Skipping is correct:
		// pcapng is explicitly designed so unknown blocks can be ignored.
	}
}

func (n *ngReader) addInterface(body []byte) {
	if len(body) < 8 {
		return
	}
	iface := ngIface{linkType: uint32(n.end.Uint16(body[0:2])), tsPerSec: 1e6}
	n.eachOption(body[8:], func(code uint16, val []byte) {
		if code == optIfTsresol && len(val) > 0 {
			// High bit set means a power of two, otherwise a power of ten.
			if val[0]&0x80 != 0 {
				iface.tsPerSec = math.Pow(2, float64(val[0]&0x7f))
			} else {
				iface.tsPerSec = math.Pow(10, float64(val[0]))
			}
		}
	})
	n.ifaces = append(n.ifaces, iface)
}

func (n *ngReader) addProcess(body []byte) {
	if len(body) < 4 {
		return
	}
	p := ngProc{pid: int32(n.u32(body))}
	n.eachOption(body[4:], func(code uint16, val []byte) {
		if code == optPibName {
			p.name = string(val)
		}
	})
	// Order of appearance is the index EPBs refer to, so duplicates must be
	// appended rather than deduplicated - the same process legitimately gets
	// several entries, and collapsing them shifts every later index.
	n.procs = append(n.procs, p)
}

func (n *ngReader) proc(idx uint32) (int32, string, bool) {
	if int(idx) >= len(n.procs) {
		return 0, "", false
	}
	p := n.procs[idx]
	return p.pid, p.name, true
}

func (n *ngReader) packet(body []byte) *ngPacket {
	if len(body) < 20 {
		return nil
	}
	ifaceID := n.u32(body[0:])
	ticks := uint64(n.u32(body[4:]))<<32 | uint64(n.u32(body[8:]))
	capLen := int(n.u32(body[12:]))
	wireLen := int(n.u32(body[16:]))
	if capLen < 0 || 20+capLen > len(body) {
		return nil
	}

	p := &ngPacket{CapLen: capLen, WireLen: wireLen, Data: body[20 : 20+capLen]}
	perSec := 1e6
	if int(ifaceID) < len(n.ifaces) {
		p.LinkType = n.ifaces[ifaceID].linkType
		perSec = n.ifaces[ifaceID].tsPerSec
	}
	secs := float64(ticks) / perSec
	p.Ts = time.Unix(int64(secs), int64((secs-math.Floor(secs))*1e9))

	n.eachOption(body[20+((capLen+3)&^3):], func(code uint16, val []byte) {
		switch code {
		case optEpbPIBIndex:
			if pid, name, ok := n.proc(n.u32(val)); ok {
				p.PID, p.Comm = pid, name
			}
		case optEpbEPIBIndex:
			if pid, name, ok := n.proc(n.u32(val)); ok {
				p.EPID, p.EComm = pid, name
			}
		case optEpbFlags:
			// pcapng epb_flags: bits 0-1 are direction, 1 inbound, 2 outbound.
			switch n.u32(val) & 0x3 {
			case 1:
				p.Dir = DirIn
			case 2:
				p.Dir = DirOut
			}
		}
	})
	return p
}
