package pktap

import (
	"encoding/binary"
	"io"
	"time"
)

// NgWriter writes pcapng in the shape Apple's tcpdump produces for
// `-i pktap,all`: one Ethernet interface, Process Information Blocks, and
// Enhanced Packet Blocks that point at them with options 0x8001 / 0x8003 and
// carry direction in epb_flags.
//
// It exists so experiments can be built with known ground truth - which app
// asked for which name - and then fed through exactly the same reader the live
// daemon uses. Wireshark 4.6+ opens the result and shows the process fields.
type NgWriter struct {
	w     io.Writer
	procs map[procKey]uint32
	next  uint32
	err   error
}

type procKey struct {
	pid  int32
	name string
}

// NewNgWriter writes the section header and a single Ethernet interface.
func NewNgWriter(w io.Writer) (*NgWriter, error) {
	n := &NgWriter{w: w, procs: map[procKey]uint32{}}
	shb := le32(0x1a2b3c4d)
	shb = binary.LittleEndian.AppendUint16(shb, 1)
	shb = binary.LittleEndian.AppendUint16(shb, 0)
	shb = binary.LittleEndian.AppendUint64(shb, ^uint64(0))
	n.block(btSHB, shb)
	idb := binary.LittleEndian.AppendUint16(nil, 1) // LINKTYPE_ETHERNET
	idb = binary.LittleEndian.AppendUint16(idb, 0)
	idb = binary.LittleEndian.AppendUint32(idb, 65535)
	n.block(btIDB, idb)
	return n, n.err
}

// WritePacket appends one Ethernet frame attributed to pid/comm (and the
// effective process epid/ecomm when non-zero), in the given direction.
func (n *NgWriter) WritePacket(ts time.Time, frame []byte, pid int32, comm string, epid int32, ecomm string, dir Direction) error {
	var opts []byte
	if pid > 0 {
		opts = append(opts, ngOption(optEpbPIBIndex, le32(n.proc(pid, comm)))...)
	}
	if epid > 0 {
		opts = append(opts, ngOption(optEpbEPIBIndex, le32(n.proc(epid, ecomm)))...)
	}
	switch dir {
	case DirIn:
		opts = append(opts, ngOption(optEpbFlags, le32(1))...)
	case DirOut:
		opts = append(opts, ngOption(optEpbFlags, le32(2))...)
	}
	us := uint64(ts.UnixMicro())
	b := le32(0)
	b = append(b, le32(uint32(us>>32))...)
	b = append(b, le32(uint32(us))...)
	b = append(b, le32(uint32(len(frame)))...)
	b = append(b, le32(uint32(len(frame)))...)
	b = append(b, frame...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	b = append(b, opts...)
	b = append(b, ngOption(optEnd, nil)...)
	n.block(btEPB, b)
	return n.err
}

// proc returns the PIB index for a process, emitting the block on first use.
func (n *NgWriter) proc(pid int32, name string) uint32 {
	k := procKey{pid, name}
	if i, ok := n.procs[k]; ok {
		return i
	}
	n.block(btPIB, append(le32(uint32(pid)), append(ngOption(optPibName, []byte(name)), ngOption(optEnd, nil)...)...))
	i := n.next
	n.procs[k] = i
	n.next++
	return i
}

func (n *NgWriter) block(bt uint32, body []byte) {
	if n.err != nil {
		return
	}
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	total := uint32(len(body) + 12)
	b := le32(bt)
	b = append(b, le32(total)...)
	b = append(b, body...)
	b = append(b, le32(total)...)
	_, n.err = n.w.Write(b)
}

func ngOption(code uint16, val []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, code)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(val)))
	b = append(b, val...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
