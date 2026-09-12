package pktap

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

// Builders for a pcapng section, so the reader is tested against the format as
// documented rather than against itself.

func block(bt uint32, body []byte) []byte {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	total := uint32(len(body) + 12)
	b := binary.LittleEndian.AppendUint32(nil, bt)
	b = binary.LittleEndian.AppendUint32(b, total)
	b = append(b, body...)
	return binary.LittleEndian.AppendUint32(b, total)
}

func option(code uint16, val []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, code)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(val)))
	b = append(b, val...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func u32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func shb() []byte {
	b := u32(0x1a2b3c4d)
	b = binary.LittleEndian.AppendUint16(b, 1) // version major
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint64(b, ^uint64(0)) // section length unknown
	return block(btSHB, b)
}

func idb(linkType uint16) []byte {
	b := binary.LittleEndian.AppendUint16(nil, linkType)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 1600)
	return block(btIDB, b)
}

// pib is Apple's Process Information Block: a PID then a name option.
func pib(pid uint32, name string) []byte {
	return block(btPIB, append(u32(pid), option(optPibName, []byte(name))...))
}

func epb(iface uint32, data []byte, opts ...[]byte) []byte {
	b := u32(iface)
	b = append(b, u32(0)...)                 // ts high
	b = append(b, u32(1_000_000)...)         // ts low: 1s at the default resolution
	b = append(b, u32(uint32(len(data)))...) // captured
	b = append(b, u32(uint32(len(data)))...) // original
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	for _, o := range opts {
		b = append(b, o...)
	}
	b = append(b, option(0, nil)...)
	return block(btEPB, b)
}

func read(t *testing.T, file []byte) []*ngPacket {
	t.Helper()
	r, err := newNgReader(bufio.NewReader(bytes.NewReader(file)))
	if err != nil {
		t.Fatalf("newNgReader: %v", err)
	}
	var out []*ngPacket
	for {
		p, err := r.next()
		if err != nil {
			return out
		}
		cp := *p
		cp.Data = append([]byte(nil), p.Data...)
		out = append(out, &cp)
	}
}

// The whole point of this reader: recovering the PID and process name that
// gopacket's pcapng reader discards along with the rest of the packet options.
func TestNgReaderRecoversProcess(t *testing.T) {
	var f []byte
	f = append(f, shb()...)
	f = append(f, idb(1)...)             // Ethernet
	f = append(f, pib(4321, "Brave")...) // index 0
	f = append(f, pib(160, "mDNSResponder")...)
	f = append(f, epb(0, []byte{1, 2, 3, 4},
		option(optEpbPIBIndex, u32(0)),
		option(optEpbEPIBIndex, u32(1)),
		option(optEpbFlags, u32(2)))...) // outbound

	pkts := read(t, f)
	if len(pkts) != 1 {
		t.Fatalf("want 1 packet, got %d", len(pkts))
	}
	p := pkts[0]
	if p.PID != 4321 || p.Comm != "Brave" {
		t.Errorf("process: got %d %q", p.PID, p.Comm)
	}
	if p.EPID != 160 || p.EComm != "mDNSResponder" {
		t.Errorf("effective process: got %d %q", p.EPID, p.EComm)
	}
	if p.Dir != DirOut {
		t.Errorf("direction: got %v want DirOut", p.Dir)
	}
	if p.LinkType != 1 {
		t.Errorf("link type: got %d want 1", p.LinkType)
	}
	if string(p.Data) != string([]byte{1, 2, 3, 4}) {
		t.Errorf("payload: got %x", p.Data)
	}
	if p.Ts.Unix() != 1 {
		t.Errorf("timestamp: got %v", p.Ts)
	}
}

// Apple emits several PIB entries for the same process. They must be appended,
// never deduplicated: EPBs address them by order of appearance, so collapsing
// duplicates silently shifts every later index onto the wrong process.
func TestNgReaderDuplicatePIBsKeepIndices(t *testing.T) {
	var f []byte
	f = append(f, shb()...)
	f = append(f, idb(1)...)
	f = append(f, pib(11422, "Sparrow")...) // 0
	f = append(f, pib(11422, "Sparrow")...) // 1
	f = append(f, pib(58880, "Brave")...)   // 2
	f = append(f, epb(0, []byte{9}, option(optEpbPIBIndex, u32(2)))...)

	pkts := read(t, f)
	if len(pkts) != 1 || pkts[0].PID != 58880 {
		t.Fatalf("index 2 should be Brave, got %+v", pkts)
	}
}

// Interfaces carry different link types in one file (Ethernet on en0, the
// loopback/AF header on utun), and each packet must report its own.
func TestNgReaderPerInterfaceLinkType(t *testing.T) {
	var f []byte
	f = append(f, shb()...)
	f = append(f, idb(1)...) // 0: Ethernet
	f = append(f, idb(0)...) // 1: null/loopback
	f = append(f, epb(0, []byte{1})...)
	f = append(f, epb(1, []byte{2})...)

	pkts := read(t, f)
	if len(pkts) != 2 {
		t.Fatalf("want 2 packets, got %d", len(pkts))
	}
	if pkts[0].LinkType != 1 || pkts[1].LinkType != 0 {
		t.Errorf("link types: got %d and %d", pkts[0].LinkType, pkts[1].LinkType)
	}
}

// Packets with no owning process are normal (kernel-originated traffic), and
// must come back with no process rather than a bogus one.
func TestNgReaderPacketWithoutProcess(t *testing.T) {
	var f []byte
	f = append(f, shb()...)
	f = append(f, idb(1)...)
	f = append(f, epb(0, []byte{1, 2})...)
	pkts := read(t, f)
	if len(pkts) != 1 {
		t.Fatalf("want 1 packet, got %d", len(pkts))
	}
	if pkts[0].PID != 0 || pkts[0].Comm != "" {
		t.Errorf("want no process, got %d %q", pkts[0].PID, pkts[0].Comm)
	}
}

// An out-of-range index must be ignored, not panic. These come from a truncated
// stream where the PIB was cut off.
func TestNgReaderBadProcessIndex(t *testing.T) {
	var f []byte
	f = append(f, shb()...)
	f = append(f, idb(1)...)
	f = append(f, epb(0, []byte{1}, option(optEpbPIBIndex, u32(99)))...)
	pkts := read(t, f)
	if len(pkts) != 1 || pkts[0].PID != 0 {
		t.Fatalf("bad index should yield no process, got %+v", pkts)
	}
}

// Truncation at every offset must error, never panic.
func TestNgReaderTruncation(t *testing.T) {
	var f []byte
	f = append(f, shb()...)
	f = append(f, idb(1)...)
	f = append(f, pib(1, "x")...)
	f = append(f, epb(0, []byte{1, 2, 3, 4}, option(optEpbPIBIndex, u32(0)))...)
	for i := 0; i < len(f); i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %d-byte prefix: %v", i, r)
				}
			}()
			r, err := newNgReader(bufio.NewReader(bytes.NewReader(f[:i])))
			if err != nil {
				return
			}
			for {
				if _, err := r.next(); err != nil {
					return
				}
			}
		}()
	}
}
