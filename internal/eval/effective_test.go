package eval_test

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"ohmyosi/internal/decode"
	"ohmyosi/internal/eval"
	"ohmyosi/internal/pktap"
)

// On macOS 26 Safari's connections are owned by com.apple.WebKit.Networking
// with Safari as pktap's effective process, and mDNSResponder's answers carry
// Safari as effective process too. Per-process correlation must match the two
// by that shared identity, not call Safari's own lookup another app's.
func TestEffectiveProcessMatchesOwnLookup(t *testing.T) {
	var (
		laptop = netip.MustParseAddr("192.168.1.3")
		router = netip.MustParseAddr("192.168.1.1")
		site   = netip.MustParseAddr("203.0.113.7")
		t0     = time.Date(2026, 11, 18, 22, 0, 0, 0, time.UTC)
		mac    = net.HardwareAddr{2, 0, 0, 0, 0, 1}
	)
	path := filepath.Join(t.TempDir(), "webkit.pcapng")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pktap.NewNgWriter(f)
	if err != nil {
		t.Fatal(err)
	}
	frame := func(src, dst netip.Addr, proto layers.IPProtocol, ls ...gopacket.SerializableLayer) []byte {
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: proto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
		for _, l := range ls {
			switch x := l.(type) {
			case *layers.UDP:
				x.SetNetworkLayerForChecksum(ip)
			case *layers.TCP:
				x.SetNetworkLayerForChecksum(ip)
			}
		}
		buf := gopacket.NewSerializeBuffer()
		eth := &layers.Ethernet{SrcMAC: mac, DstMAC: mac, EthernetType: layers.EthernetTypeIPv4}
		all := append([]gopacket.SerializableLayer{eth, ip}, ls...)
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, all...); err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), buf.Bytes()...)
	}
	write := func(sec float64, b []byte, pid int32, comm string, epid int32, ecomm string, dir pktap.Direction) {
		if err := w.WritePacket(t0.Add(time.Duration(sec*float64(time.Second))), b, pid, comm, epid, ecomm, dir); err != nil {
			t.Fatal(err)
		}
	}

	// Safari (672) looks up www.example.com through mDNSResponder (511).
	q := layers.DNSQuestion{Name: []byte("www.example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}
	write(0, frame(laptop, router, layers.IPProtocolUDP, &layers.UDP{SrcPort: 50001, DstPort: 53},
		&layers.DNS{ID: 1, RD: true, Questions: []layers.DNSQuestion{q}}), 511, "mDNSResponder", 672, "Safari", pktap.DirOut)
	resp := &layers.DNS{ID: 1, QR: true, RD: true, RA: true, Questions: []layers.DNSQuestion{q},
		Answers: []layers.DNSResourceRecord{{Name: q.Name, Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 300, IP: site.AsSlice()}}}
	write(0.02, frame(router, laptop, layers.IPProtocolUDP, &layers.UDP{SrcPort: 53, DstPort: 50001}, resp),
		511, "mDNSResponder", 672, "Safari", pktap.DirIn)

	// WebKit's network process (1590) connects on Safari's behalf.
	tcp := func(sec float64, out bool, syn, ack bool, payload []byte) {
		src, dst, sp, dp, dir := laptop, site, layers.TCPPort(60001), layers.TCPPort(443), pktap.DirOut
		if !out {
			src, dst, sp, dp, dir = site, laptop, 443, 60001, pktap.DirIn
		}
		ls := []gopacket.SerializableLayer{&layers.TCP{SrcPort: sp, DstPort: dp, Seq: 1, SYN: syn, ACK: ack, PSH: payload != nil, Window: 65535}}
		if payload != nil {
			ls = append(ls, gopacket.Payload(payload))
		}
		write(sec, frame(src, dst, layers.IPProtocolTCP, ls...), 1590, "com.apple.WebKi", 672, "Safari", dir)
	}
	tcp(0.10, true, true, false, nil)
	tcp(0.13, false, true, true, nil)
	tcp(0.14, true, false, true, decode.ClientHello("www.example.com"))
	tcp(0.18, false, false, true, make([]byte, 600))
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := eval.Run(path, eval.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("%d flows, want 1", len(rep.Results))
	}
	for _, s := range []string{eval.StratLastAnswer, eval.StratPerProcess} {
		v := rep.Results[0].Verdicts[s]
		if v.DNSPick != "www.example.com" || v.CrossProcess {
			t.Errorf("%s: pick %q cross-process %v; want Safari's own lookup", s, v.DNSPick, v.CrossProcess)
		}
	}
}
