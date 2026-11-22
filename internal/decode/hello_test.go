package decode

import (
	"net/netip"
	"testing"
)

var helloK = helloKey{TCP, netip.MustParseAddr("192.168.1.3"), netip.MustParseAddr("203.0.113.7"), 61332, 443}

// A ClientHello longer than one segment (post-quantum key shares make ~1.9 KB
// the norm) is read once the rest arrives, and not guessed at before.
func TestTCPHelloAcrossSegments(t *testing.T) {
	rec := ClientHelloOpts("split.example.com", "h2", false)
	cut := 40 // before server_name
	d := New()
	if sni, ja4, _ := d.tcpHello(helloK, 1000, rec[:cut], cut); sni != "" || ja4 != "" {
		t.Fatalf("first segment: sni %q ja4 %q, want nothing until the hello is whole", sni, ja4)
	}
	// A retransmission of the first segment does not corrupt the buffer.
	d.tcpHello(helloK, 1000, rec[:cut], cut)
	sni, ja4, ech := d.tcpHello(helloK, 1000+uint32(cut), rec[cut:], len(rec)-cut)
	if sni != "split.example.com" || ALPNOf(ja4) != "h2" || ech {
		t.Fatalf("reassembled: sni %q ja4 %q ech %v", sni, ja4, ech)
	}
	if len(d.pending) != 0 {
		t.Fatalf("%d hellos still pending", len(d.pending))
	}
	// A hello that fits in one segment is read straight away, as before.
	if sni, _, _ := New().tcpHello(helloK, 1, rec, len(rec)); sni != "split.example.com" {
		t.Fatalf("single segment: %q", sni)
	}
}

// A gap (lost segment) leaves the hello unread rather than misread - the
// captured part holds no server_name here - and releases the buffer.
func TestTCPHelloGap(t *testing.T) {
	rec := ClientHelloOpts("gap.example.com", "", false)
	d := New()
	d.tcpHello(helloK, 1000, rec[:20], 20)
	if sni, _, _ := d.tcpHello(helloK, 5000, rec[40:], len(rec)-40); sni != "" {
		t.Fatalf("read %q across a gap", sni)
	}
	if len(d.pending) != 0 {
		t.Fatal("buffer not released")
	}
}

func cryptoFrame6(off int, data []byte) []byte {
	f := appendVarint([]byte{0x06}, uint64(off))
	f = appendVarint(f, uint64(len(data)))
	return append(f, data...)
}

// Chrome splits its ClientHello over two Initials and shuffles the CRYPTO
// frames, with PING and ACK frames between them.
func TestQUICHelloAcrossInitials(t *testing.T) {
	ch := clientHelloHandshake("quic-split.example.com")
	dcid := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	var p0, p1 []byte
	p0 = append(p0, cryptoFrame6(80, ch[80:])...)
	p0 = append(p0, 0x01) // PING
	p0 = append(p0, cryptoFrame6(0, ch[:30])...)
	p1 = append(p1, 0x02, 0x00, 0x00, 0x00, 0x00) // ACK: largest 0, delay 0, 0 ranges, first 0
	p1 = append(p1, cryptoFrame6(30, ch[30:80])...)
	init0, init1 := sealInitial(dcid, 0, p0), sealInitial(dcid, 1, p1)

	k := helloKey{UDP, helloK.src, helloK.dst, 55831, 443}
	for _, order := range [][2][]byte{{init0, init1}, {init1, init0}} {
		d := New()
		if sni, _, _ := d.quicHello(k, order[0]); sni != "" {
			t.Fatalf("read %q from half a hello", sni)
		}
		sni, ja4, _ := d.quicHello(k, order[1])
		if sni != "quic-split.example.com" || ja4 == "" || ja4[0] != 'q' {
			t.Fatalf("reassembled: sni %q ja4 %q", sni, ja4)
		}
		if len(d.pending) != 0 {
			t.Fatalf("%d hellos still pending", len(d.pending))
		}
	}
	// One Initial holding the whole hello in shuffled frames reads on its own.
	whole := append(cryptoFrame6(30, ch[30:]), cryptoFrame6(0, ch[:30])...)
	if sni := QUICSNI(sealInitial(dcid, 0, whole)); sni != "quic-split.example.com" {
		t.Fatalf("shuffled single Initial: %q", sni)
	}
}

// Snaplen cut the first segment short (pktap's header counts against it): the
// hello cannot be completed, so the captured part is read as far as it goes,
// as a first-segment reader always did - and a server_name early in the hello
// is still found.
func TestTCPHelloTruncatedBySnaplen(t *testing.T) {
	rec := ClientHelloOpts("trunc.example.com", "", false)
	cut := len(rec) - 7 // drops the trailing supported_versions, keeps server_name
	if sni, _, _ := New().tcpHello(helloK, 1, rec[:cut], len(rec)); sni != "trunc.example.com" {
		t.Fatalf("truncated single segment: %q", sni)
	}
	// Split across segments, the first one truncated: fall back on the next.
	d := New()
	first := 60
	d.tcpHello(helloK, 1000, rec[:first], first)
	if sni, _, _ := d.tcpHello(helloK, 1000+uint32(first), rec[first:cut], len(rec)-first); sni != "trunc.example.com" {
		t.Fatalf("truncated continuation: %q", sni)
	}
	if len(d.pending) != 0 {
		t.Fatal("buffer not released")
	}
}
