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
	"ohmyosi/internal/naming"
	"ohmyosi/internal/pktap"
)

// capW writes a small pktap capture for tests: lookups through mDNSResponder
// on an app's behalf, and TLS connections announcing a name.
type capW struct {
	t    *testing.T
	f    *os.File
	w    *pktap.NgWriter
	t0   time.Time
	id   uint16
	port uint16
}

var (
	capLaptop = netip.MustParseAddr("192.168.1.3")
	capRouter = netip.MustParseAddr("192.168.1.1")
	capMAC    = net.HardwareAddr{2, 0, 0, 0, 0, 1}
)

func newCap(t *testing.T, path string, t0 time.Time) *capW {
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pktap.NewNgWriter(f)
	if err != nil {
		t.Fatal(err)
	}
	return &capW{t: t, f: f, w: w, t0: t0, port: 61000}
}

func (c *capW) frame(src, dst netip.Addr, proto layers.IPProtocol, ls ...gopacket.SerializableLayer) []byte {
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
	eth := &layers.Ethernet{SrcMAC: capMAC, DstMAC: capMAC, EthernetType: layers.EthernetTypeIPv4}
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		append([]gopacket.SerializableLayer{eth, ip}, ls...)...); err != nil {
		c.t.Fatal(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func (c *capW) write(sec float64, b []byte, pid int32, comm string, epid int32, ecomm string, dir pktap.Direction) {
	if err := c.w.WritePacket(c.t0.Add(time.Duration(sec*float64(time.Second))), b, pid, comm, epid, ecomm, dir); err != nil {
		c.t.Fatal(err)
	}
}

// lookup: app (pid, comm) resolves name to ip via mDNSResponder with ttl.
func (c *capW) lookup(sec float64, pid int32, comm, name, ip string, ttl uint32) {
	c.id++
	q := layers.DNSQuestion{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}
	sport := layers.UDPPort(50000 + c.id)
	c.write(sec, c.frame(capLaptop, capRouter, layers.IPProtocolUDP, &layers.UDP{SrcPort: sport, DstPort: 53},
		&layers.DNS{ID: c.id, RD: true, Questions: []layers.DNSQuestion{q}}), 511, "mDNSResponder", pid, comm, pktap.DirOut)
	resp := &layers.DNS{ID: c.id, QR: true, RD: true, RA: true, Questions: []layers.DNSQuestion{q},
		Answers: []layers.DNSResourceRecord{{Name: q.Name, Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: ttl,
			IP: netip.MustParseAddr(ip).AsSlice()}}}
	c.write(sec+0.02, c.frame(capRouter, capLaptop, layers.IPProtocolUDP, &layers.UDP{SrcPort: 53, DstPort: sport}, resp),
		511, "mDNSResponder", pid, comm, pktap.DirIn)
}

// connect: app opens TLS to ip announcing sni.
func (c *capW) connect(sec float64, pid int32, comm, ip, sni string) {
	c.port++
	dst := netip.MustParseAddr(ip)
	pkt := func(s float64, out, syn, ack bool, payload []byte) {
		src, d, sp, dp, dir := capLaptop, dst, layers.TCPPort(c.port), layers.TCPPort(443), pktap.DirOut
		if !out {
			src, d, sp, dp, dir = dst, capLaptop, 443, layers.TCPPort(c.port), pktap.DirIn
		}
		ls := []gopacket.SerializableLayer{&layers.TCP{SrcPort: sp, DstPort: dp, Seq: 1, SYN: syn, ACK: ack, PSH: payload != nil, Window: 65535}}
		if payload != nil {
			ls = append(ls, gopacket.Payload(payload))
		}
		c.write(s, c.frame(src, d, layers.IPProtocolTCP, ls...), pid, comm, 0, "", dir)
	}
	pkt(sec, true, true, false, nil)
	pkt(sec+0.03, false, true, true, nil)
	pkt(sec+0.04, true, false, true, decode.ClientHello(sni))
	pkt(sec+0.08, false, false, true, make([]byte, 600))
}

// teardown: a FIN from a process that has already exited - the kernel closes
// its leftover sockets and pktap still stamps them with the old PID.
func (c *capW) teardown(sec float64, pid int32, comm, ip string) {
	c.port++
	c.write(sec, c.frame(capLaptop, netip.MustParseAddr(ip), layers.IPProtocolTCP,
		&layers.TCP{SrcPort: layers.TCPPort(c.port), DstPort: 443, Seq: 9, FIN: true, ACK: true, Window: 65535}),
		pid, comm, 0, "", pktap.DirOut)
}

func (c *capW) close() {
	if err := c.f.Close(); err != nil {
		c.t.Fatal(err)
	}
}

func writeManifest(t *testing.T, pcap, cache string) {
	body := `{"workload":"tranco-browse","browser":"firefox","doh":"off","repeat":1,"network":"lab","tranco_list":"T","cache":"` + cache + `"}`
	if err := os.WriteFile(pcap[:len(pcap)-len(".pcapng")]+".manifest.json", []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// buildColdWarm writes a cold capture and the warm one a minute later. Cold:
// Firefox (pid 100) resolves a.example (TTL 300) and old.example (TTL 5);
// Safari (pid 200) resolves c.example. Warm: Firefox has been relaunched as
// pid 300 and connects with no fresh lookups - its answers are cached - to
// a.example, to old.example's address announcing new.example, and to the
// address Safari resolved.
func buildColdWarm(t *testing.T, dir string) (cold, warm string) {
	t0 := time.Date(2026, 11, 18, 23, 0, 0, 0, time.UTC)
	cold = filepath.Join(dir, "x-lab-r1-firefox-dohoff-cold.pcapng")
	warm = filepath.Join(dir, "x-lab-r1-firefox-dohoff-warm.pcapng")
	c := newCap(t, cold, t0)
	c.lookup(0, 100, "firefox", "a.example", "203.0.113.10", 300)
	c.lookup(1, 100, "firefox", "old.example", "203.0.113.20", 5)
	c.lookup(2, 200, "Safari", "c.example", "203.0.113.30", 300)
	c.connect(3, 100, "firefox", "203.0.113.10", "a.example")
	c.close()
	w := newCap(t, warm, t0.Add(60*time.Second))
	w.lookup(0, 200, "Safari", "unrelated.example", "198.51.100.9", 300) // Safari still running, same pid
	w.teardown(0.5, 100, "firefox", "203.0.113.99")                      // the old Firefox's sockets closing
	w.connect(1, 300, "firefox", "203.0.113.10", "a.example")
	w.connect(2, 300, "firefox", "203.0.113.20", "new.example")
	w.connect(3, 300, "firefox", "203.0.113.30", "c.example")
	w.close()
	writeManifest(t, cold, "cold")
	writeManifest(t, warm, "warm")
	return cold, warm
}

func verdictFor(t *testing.T, rep *eval.Report, sni, strat string) naming.Verdict {
	t.Helper()
	for _, r := range rep.Results {
		if v := r.Verdicts[strat]; v.Handshake == sni {
			return v
		}
	}
	t.Fatalf("no flow announcing %s", sni)
	return naming.Verdict{}
}

func TestWarmPassWithColdAnswers(t *testing.T) {
	cold, warm := buildColdWarm(t, t.TempDir())

	// Alone, the warm capture has no lookups for Firefox: every flow is bypass.
	alone, err := eval.Run(warm, eval.Options{Slack: naming.DefaultSlack})
	if err != nil {
		t.Fatal(err)
	}
	for _, sni := range []string{"a.example", "new.example", "c.example"} {
		if v := verdictFor(t, alone, sni, eval.StratLastAnswer); v.Class != naming.HandshakeOnly {
			t.Errorf("alone, %s: %s, want handshake-only", sni, v.Class)
		}
	}

	rep, err := eval.Run(warm, eval.Options{Slack: naming.DefaultSlack, Prior: cold})
	if err != nil {
		t.Fatal(err)
	}
	if p := rep.Prior; p == nil || p.Answers != 3 || p.Remapped != 2 || p.Unknown != 0 {
		t.Fatalf("prior %+v: want 3 answers, Firefox's 2 re-keyed to the relaunched pid", p)
	}
	if rep.DNS.Answers != 1 {
		t.Errorf("coverage counts preloaded answers: %d, want this capture's 1", rep.DNS.Answers)
	}
	// Firefox's own cached answer, after relaunch: right, and not another app's.
	for _, s := range []string{eval.StratLastAnswer, eval.StratPerProcess} {
		if v := verdictFor(t, rep, "a.example", s); v.Class != naming.Agree || v.CrossProcess {
			t.Errorf("%s a.example: %+v, want agree, same app", s, v)
		}
	}
	// An answer that expired between the passes: wrong, and the cause is stale.
	if v := verdictFor(t, rep, "new.example", eval.StratLastAnswer); v.Class != naming.Mismatch || v.Cause != naming.CauseStale {
		t.Errorf("new.example: %+v, want mismatch caused by stale", v)
	}
	// Safari's lookup lent to Firefox: cross-process for last-answer; per-process sees nothing.
	if v := verdictFor(t, rep, "c.example", eval.StratLastAnswer); v.Class != naming.Agree || !v.CrossProcess {
		t.Errorf("last-answer c.example: %+v, want agree via another app's lookup", v)
	}
	if v := verdictFor(t, rep, "c.example", eval.StratPerProcess); v.DNSPick != "" {
		t.Errorf("per-process c.example picked %q from Safari's lookup", v.DNSPick)
	}
}

func TestSummarizePreloadsWarmRuns(t *testing.T) {
	dir := t.TempDir()
	_, warm := buildColdWarm(t, dir)
	runs, err := eval.Summarize(dir, naming.DefaultSlack, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range runs {
		switch filepath.Base(r.File) {
		case filepath.Base(warm):
			if r.Prior == nil || r.Prior.Answers != 3 || r.NoPrior {
				t.Errorf("warm run: prior %+v noPrior %v", r.Prior, r.NoPrior)
			}
		default:
			if r.Prior != nil || r.NoPrior {
				t.Errorf("cold run got prior %+v noPrior %v", r.Prior, r.NoPrior)
			}
		}
	}
	// Without its cold capture a warm run is evaluated alone, and says so.
	os.Remove(filepath.Join(dir, "x-lab-r1-firefox-dohoff-cold.pcapng"))
	runs, err = eval.Summarize(dir, naming.DefaultSlack, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Prior != nil || !runs[0].NoPrior {
		t.Errorf("orphan warm run: %+v", runs)
	}
}
