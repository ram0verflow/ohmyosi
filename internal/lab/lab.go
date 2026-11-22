// Package lab builds a pktap-format capture with known ground truth, for
// evaluating how each naming strategy performs against fact.
//
// A field capture can only grade correlation against the handshake name, and
// says nothing about flows that announce no name at all. The lab fixes that:
// every flow here is built from a scenario that says which app wanted which
// name, so `ohmyosi -eval lab.pcapng -truth lab.truth.json` can score
// dns-correlation, the old address cache and read-first on the same packets.
//
// The scenarios are the failure modes, one each, plus an ordinary baseline.
// They are not a sample of real traffic and their proportions mean nothing:
// prevalence comes from a field capture. What the lab shows is mechanism -
// that each failure exists, which strategy it fools, and whether the fool is
// presented as fact.
package lab

import (
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"ohmyosi/internal/decode"
	"ohmyosi/internal/eval"
	"ohmyosi/internal/pktap"
)

var (
	laptop   = netip.MustParseAddr("192.168.1.3")
	resolver = netip.MustParseAddr("192.168.1.1")
	macL     = net.HardwareAddr{0x02, 0, 0, 0, 0, 3}
	macR     = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	t0       = time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
)

type app struct {
	pid  int32
	comm string
}

var (
	mdns    = app{160, "mDNSResponder"}
	safari  = app{410, "Safari"}
	slack   = app{420, "Slack Helper"}
	notion  = app{430, "Notion Helper"}
	brave   = app{440, "Brave Browser He"}
	discord = app{450, "Discord Helper"}
	firefox = app{460, "firefox"}
	cursor  = app{470, "Cursor Helper (P"}
	spotify = app{480, "Spotify"}
	figma   = app{490, "Figma Helper"}
	zoom    = app{500, "zoom.us"}
	updater = app{510, "AcmeUpdater"}
	backupd = app{520, "backupd"}
)

type lab struct {
	w     *pktap.NgWriter
	truth eval.Truth
	port  uint16
	dnsID uint16
	err   error
}

func (l *lab) at(sec float64) time.Time { return t0.Add(time.Duration(sec * float64(time.Second))) }

func (l *lab) frame(src, dst netip.Addr, ls ...gopacket.SerializableLayer) []byte {
	eth := &layers.Ethernet{SrcMAC: macL, DstMAC: macR, EthernetType: layers.EthernetTypeIPv4}
	if src != laptop {
		eth.SrcMAC, eth.DstMAC = macR, macL
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, append([]gopacket.SerializableLayer{eth}, ls...)...); err != nil && l.err == nil {
		l.err = err
	}
	return append([]byte(nil), buf.Bytes()...)
}

func ip4(src, dst netip.Addr, proto layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{Version: 4, TTL: 64, Protocol: proto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
}

func (l *lab) write(sec float64, frame []byte, a, eff app, dir pktap.Direction) {
	if err := l.w.WritePacket(l.at(sec), frame, a.pid, a.comm, eff.pid, eff.comm, dir); err != nil && l.err == nil {
		l.err = err
	}
}

// lookup: asker resolves name through mDNSResponder; the answers are the given
// addresses. pktap stamps the resolver as owner and the asker as effective.
func (l *lab) lookup(sec float64, asker app, name string, addrs ...string) {
	l.lookupTTL(sec, 300, asker, name, addrs...)
}

func (l *lab) lookupTTL(sec float64, ttl uint32, asker app, name string, addrs ...string) {
	l.dnsID++
	sport := 50000 + l.dnsID
	q := layers.DNSQuestion{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}
	ip := ip4(laptop, resolver, layers.IPProtocolUDP)
	u := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: 53}
	u.SetNetworkLayerForChecksum(ip)
	l.write(sec, l.frame(laptop, resolver, ip, u, &layers.DNS{ID: l.dnsID, RD: true, Questions: []layers.DNSQuestion{q}}), mdns, asker, pktap.DirOut)

	resp := &layers.DNS{ID: l.dnsID, QR: true, RD: true, RA: true, Questions: []layers.DNSQuestion{q}}
	for _, a := range addrs {
		resp.Answers = append(resp.Answers, layers.DNSResourceRecord{
			Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: ttl,
			IP: netip.MustParseAddr(a).AsSlice(),
		})
	}
	ip2 := ip4(resolver, laptop, layers.IPProtocolUDP)
	u2 := &layers.UDP{SrcPort: 53, DstPort: layers.UDPPort(sport)}
	u2.SetNetworkLayerForChecksum(ip2)
	l.write(sec+0.02, l.frame(resolver, laptop, ip2, u2, resp), mdns, asker, pktap.DirIn)
}

type conn struct {
	alpn     string // ALPN offered in the ClientHello
	ech      bool   // offer Encrypted Client Hello; sni is then the outer name
	sni      string // name in the ClientHello; "" sends a ClientHello without one
	hello    bool   // send a ClientHello at all
	syn      bool   // witnessed opening; false = established before capture
	answered bool
	port     uint16
}

// tcp opens a connection from a to dst and records the truth for it.
func (l *lab) tcp(sec float64, a app, dst string, c conn, truth, note string) {
	l.port++
	lp := 60000 + l.port
	d := netip.MustParseAddr(dst)
	if c.port == 0 {
		c.port = 443
	}
	seq := uint32(1000)
	pkt := func(s float64, out bool, flags func(*layers.TCP), payload []byte) {
		src, dstA := laptop, d
		sp, dp := lp, c.port
		dir := pktap.DirOut
		if !out {
			src, dstA, sp, dp, dir = d, laptop, c.port, lp, pktap.DirIn
		}
		ip := ip4(src, dstA, layers.IPProtocolTCP)
		t := &layers.TCP{SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp), Seq: seq, Window: 65535}
		flags(t)
		t.SetNetworkLayerForChecksum(ip)
		ls := []gopacket.SerializableLayer{ip, t}
		if payload != nil {
			ls = append(ls, gopacket.Payload(payload))
		}
		l.write(s, l.frame(src, dstA, ls...), a, app{}, dir)
		seq += uint32(len(payload)) + 1
	}
	if c.syn {
		pkt(sec, true, func(t *layers.TCP) { t.SYN = true }, nil)
		pkt(sec+0.03, false, func(t *layers.TCP) { t.SYN, t.ACK = true, true }, nil)
	}
	if c.hello {
		pkt(sec+0.04, true, func(t *layers.TCP) { t.ACK, t.PSH = true, true }, decode.ClientHelloOpts(c.sni, c.alpn, c.ech))
	} else {
		pkt(sec+0.04, true, func(t *layers.TCP) { t.ACK, t.PSH = true, true }, []byte(strings.Repeat("\x17", 64)))
	}
	if c.answered {
		pkt(sec+0.08, false, func(t *layers.TCP) { t.ACK, t.PSH = true, true }, []byte(strings.Repeat("\x16", 900)))
	}
	l.truth[eval.Key("tcp", netip.AddrPortFrom(laptop, lp), netip.AddrPortFrom(d, c.port))] = eval.TruthEntry{App: a.comm, Name: truth, Note: note}
}

// quic opens a QUIC connection whose Initial carries sni.
func (l *lab) quic(sec float64, a app, dst, sni, note string) {
	l.port++
	lp := 60000 + l.port
	d := netip.MustParseAddr(dst)
	ip := ip4(laptop, d, layers.IPProtocolUDP)
	u := &layers.UDP{SrcPort: layers.UDPPort(lp), DstPort: 443}
	u.SetNetworkLayerForChecksum(ip)
	dcid := []byte{byte(l.port), 1, 2, 3, 4, 5, 6, 7}
	l.write(sec, l.frame(laptop, d, ip, u, gopacket.Payload(decode.SealQUICInitial(dcid, sni))), a, app{}, pktap.DirOut)
	ip2 := ip4(d, laptop, layers.IPProtocolUDP)
	u2 := &layers.UDP{SrcPort: 443, DstPort: layers.UDPPort(lp)}
	u2.SetNetworkLayerForChecksum(ip2)
	l.write(sec+0.05, l.frame(d, laptop, ip2, u2, gopacket.Payload(append([]byte{0xc0}, make([]byte, 400)...))), a, app{}, pktap.DirIn)
	l.truth[eval.Key("udp", netip.AddrPortFrom(laptop, lp), netip.AddrPortFrom(d, 443))] = eval.TruthEntry{App: a.comm, Name: sni, Note: note}
}

// Build writes the lab capture to out and returns its ground truth.
func Build(out io.Writer) (eval.Truth, error) {
	w, err := pktap.NewNgWriter(out)
	if err != nil {
		return nil, err
	}
	l := &lab{w: w, truth: eval.Truth{}}
	read := conn{sni: "", hello: true, syn: true, answered: true}
	with := func(name string) conn { c := read; c.sni = name; return c }

	// S0 baseline: look a name up, connect, announce the same name. The case
	// every design handles, and most traffic on most machines.
	base := []struct {
		a    app
		name string
		ip   string
	}{
		{safari, "www.apple.com", "23.45.67.10"}, {safari, "github.com", "140.82.112.3"},
		{slack, "app.slack.com", "54.192.10.20"}, {slack, "edgeapi.slack.com", "34.226.1.2"},
		{discord, "gateway.discord.gg", "162.159.135.232"}, {cursor, "api2.cursor.sh", "54.169.137.160"},
		{firefox, "www.wikipedia.org", "185.15.59.224"}, {spotify, "apresolve.spotify.com", "35.186.224.25"},
		{zoom, "zoom.us", "170.114.52.2"}, {figma, "www.figma.com", "13.32.99.10"},
	}
	for i, b := range base {
		s := float64(i) * 0.5
		l.lookup(s, b.a, b.name, b.ip)
		l.tcp(s+0.1, b.a, b.ip, with(b.name), b.name, "S0 baseline")
	}

	// S1 CDN fan-in. One Cloudflare edge answers for unrelated sites. Notion
	// resolves notion.so, then Brave resolves an ad domain to the same edge a
	// moment before Notion connects. Correlation names Notion's connection after
	// Brave's lookup: the wrong organisation, and another app's DNS.
	const edge = "104.18.32.7"
	l.lookup(10, notion, "www.notion.so", edge)
	l.lookup(10.5, brave, "ads.adnetwork.example", edge)
	l.tcp(11, notion, edge, with("www.notion.so"), "www.notion.so", "S1 fan-in: another app's lookup came last")
	l.lookup(12, discord, "cdn.discordapp.com", edge)
	l.tcp(12.5, brave, edge, with("ads.adnetwork.example"), "ads.adnetwork.example", "S1 fan-in: name was an earlier answer (alias)")
	l.tcp(13, notion, edge, with("msgstore.www.notion.so"), "msgstore.www.notion.so", "S1 fan-in: same site, different host")

	// S2 names that never touch system DNS: a DoH client, a cached answer from
	// before capture, a hardcoded endpoint. Correlation shows a bare address;
	// the handshake still says exactly where each one went.
	l.tcp(20, firefox, "1.1.1.1", with("mozilla.cloudflare-dns.com"), "mozilla.cloudflare-dns.com", "S2 DoH resolver itself")
	l.tcp(20.5, firefox, "151.101.65.140", with("incoming.telemetry.mozilla.org"), "incoming.telemetry.mozilla.org", "S2 resolved over DoH")
	l.tcp(21, cursor, "54.169.137.161", with("api3.cursor.sh"), "api3.cursor.sh", "S2 answer cached before capture")
	l.tcp(21.5, updater, "198.51.100.23", with("metrics.telemetry-vendor.example"), "metrics.telemetry-vendor.example", "S2 hardcoded address; blocked name evades hosts")

	// S3 flows that announce nothing on the edge: one already open when
	// capture began, one whose ClientHello carries no SNI (as under ECH). The
	// old address cache lends them a name some other flow announced, and labels
	// it as read. Read-first falls back to correlation and labels it a guess.
	l.tcp(25, spotify, edge, conn{hello: false, syn: false, answered: true}, "spclient.wg.spotify.com", "S3 predates capture, borrows a peer name")
	l.tcp(25.5, zoom, edge, conn{hello: true, syn: true, answered: true}, "zoomgov.example", "S3 no SNI on the wire, borrows a peer name")

	// S4 stale correlation: an address answered for one name earlier is now
	// reached for another, with no fresh lookup in between. One answer had
	// long expired by its TTL; the other was still valid.
	l.lookupTTL(30, 5, safari, "old-campaign.example", "34.120.5.5")
	l.tcp(40, figma, "34.120.5.5", with("api.figma.com"), "api.figma.com", "S4 answer expired by TTL")
	l.lookup(41, safari, "landing.example", "34.120.5.6")
	l.tcp(42, figma, "34.120.5.6", with("static.figma.com"), "static.figma.com", "S4 address reused for another site")

	// S5 QUIC. A Google edge serves both YouTube and Play; Brave resolved one,
	// then speaks QUIC to both. Readable only by decrypting the Initial.
	l.lookup(50, brave, "www.youtube.com", "142.250.183.14")
	l.quic(50.2, brave, "142.250.183.14", "www.youtube.com", "S5 QUIC, agrees")
	l.quic(50.6, brave, "142.250.183.14", "play.google.com", "S5 QUIC, same edge, different org")

	// S7 Encrypted Client Hello. Brave resolved the real site; the handshake
	// only shows Cloudflare's public outer name. A header reader reports the
	// front as the destination; the true name is only in Brave's own lookup.
	l.lookup(70, brave, "www.ech-site.example", "104.16.123.96")
	l.tcp(70.2, brave, "104.16.123.96", conn{sni: "cloudflare-ech.com", ech: true, alpn: "h2", hello: true, syn: true, answered: true},
		"www.ech-site.example", "S7 ECH: SNI is the outer front name")

	// S8 coalescing. Brave resolves two Google static hosts to one edge, then
	// opens one h2 connection announcing the second. The browser may send
	// requests for both over it; correlation shows the first.
	l.lookup(80, brave, "www.gstatic.example", "142.250.70.3")
	l.lookup(80.5, brave, "fonts.gstatic.example", "142.250.70.3")
	l.tcp(81, brave, "142.250.70.3", conn{sni: "www.gstatic.example", alpn: "h2", hello: true, syn: true, answered: true},
		"www.gstatic.example", "S8 h2 connection that may be coalesced")

	// S9 GREASE ECH. Chromium browsers send an ECH extension (0xfe0d) on
	// connections that are not using ECH; the SNI is the real destination, not
	// a front. Unlike S7 it must grade like the S0 baseline: agree.
	l.lookup(90, brave, "search.brave.example", "34.111.20.20")
	l.tcp(90.2, brave, "34.111.20.20", conn{sni: "search.brave.example", ech: true, alpn: "h2", hello: true, syn: true, answered: true},
		"search.brave.example", "S9 GREASE ECH: real SNI, graded normally")

	// S6 genuinely direct: no lookup, no SNI. There is no name to get right.
	l.tcp(60, backupd, "203.0.113.50", conn{hello: true, syn: true, answered: true, port: 8443}, "", "S6 direct to IP, nothing announced")

	return l.truth, l.err
}
