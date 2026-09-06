// Package decode turns a captured frame into an Observation: one 5-tuple
// sighting with whatever names we could pull out of it for free.
//
// Two enrichments happen here rather than later because they need the packet
// bytes, which we do not keep around:
//
//   - DNS responses, which tell us that 104.18.32.7 is notion.so.
//   - The TLS SNI in a ClientHello, which tells us the same thing for
//     connections whose lookup we never saw. That matters more than it
//     sounds: Chrome and Firefox default to DNS-over-HTTPS, so their
//     lookups never cross the wire in a form we can read, and without SNI
//     every browser connection is an anonymous Cloudflare address.
package decode

import (
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"ohmyosi/internal/pktap"
)

type Proto string

const (
	TCP   Proto = "tcp"
	UDP   Proto = "udp"
	ICMP  Proto = "icmp"
	Other Proto = "other"
)

// DNSRecord is one name-to-address fact learned from a response.
type DNSRecord struct {
	Name string
	IP   netip.Addr
	TTL  uint32
}

// Obs is a single packet, normalized.
type Obs struct {
	Ts    time.Time
	PID   int32
	Comm  string
	EPID  int32
	EComm string
	Iface string
	Dir   pktap.Direction

	Proto        Proto
	Src, Dst     netip.Addr
	SPort, DPort uint16

	WireLen    int // bytes on the wire
	PayloadLen int // transport payload only

	SYN, FIN, RST bool

	SNI string      // non-empty when this packet was a ClientHello we could read
	DNS []DNSRecord // non-empty when this packet was a DNS response we could read
	// Questions are the names asked for in a DNS message. A resolver's own
	// flows are meaningless without them - "mDNSResponder to 1.1.1.1" says
	// nothing, while the list of names it is resolving says everything.
	Questions []string
}

// Decoder is stateful only in its reusable layer structs; use one per goroutine.
//
// gopacket's DecodingLayerParser fixes its entry layer at construction, but a
// pktap capture mixes Ethernet (en0), loopback/AF headers (lo0, utun) and bare
// IP in one stream. So we keep one parser per entry point, all sharing the same
// layer structs, and pick by DLT.
type Decoder struct {
	parsers map[gopacket.LayerType]*gopacket.DecodingLayerParser

	eth     layers.Ethernet
	lo      layers.Loopback
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	icmp4   layers.ICMPv4
	icmp6   layers.ICMPv6
	dns     layers.DNS
	payload gopacket.Payload
	decoded []gopacket.LayerType
}

func New() *Decoder {
	d := &Decoder{decoded: make([]gopacket.LayerType, 0, 8)}
	// Reusing these structs instead of allocating per packet is the difference
	// between idle and an audible fan at a few thousand packets a second.
	shared := []gopacket.DecodingLayer{
		&d.eth, &d.lo, &d.ip4, &d.ip6, &d.tcp, &d.udp, &d.icmp4, &d.icmp6, &d.dns, &d.payload,
	}
	d.parsers = make(map[gopacket.LayerType]*gopacket.DecodingLayerParser, 4)
	for _, entry := range []gopacket.LayerType{
		layers.LayerTypeEthernet,
		layers.LayerTypeLoopback,
		layers.LayerTypeIPv4,
		layers.LayerTypeIPv6,
	} {
		p := gopacket.NewDecodingLayerParser(entry, shared...)
		p.IgnoreUnsupported = true
		p.IgnorePanic = true
		d.parsers[entry] = p
	}
	return d
}

// firstLayer maps a DLT to the layer the frame actually starts with.
func firstLayer(dlt uint32, data []byte) gopacket.LayerType {
	switch dlt {
	case 1: // DLT_EN10MB
		return layers.LayerTypeEthernet
	case 0, 108: // DLT_NULL, DLT_LOOP - 4-byte address family header (lo0, utun)
		return layers.LayerTypeLoopback
	case 12, 14, 101: // DLT_RAW variants - bare IP
		if len(data) > 0 && data[0]>>4 == 6 {
			return layers.LayerTypeIPv6
		}
		return layers.LayerTypeIPv4
	default:
		return layers.LayerTypeEthernet
	}
}

// Decode returns nil for frames we do not care about (ARP, non-IP, malformed).
func (d *Decoder) Decode(p *pktap.Packet) *Obs {
	if p == nil || len(p.Data) == 0 {
		return nil
	}
	parser, ok := d.parsers[firstLayer(p.DLT, p.Data)]
	if !ok {
		return nil
	}
	d.decoded = d.decoded[:0]
	// Errors are expected and mostly mean "truncated by snaplen". Whatever
	// layers did decode are still in d.decoded and still useful.
	_ = parser.DecodeLayers(p.Data, &d.decoded)
	if len(d.decoded) == 0 {
		return nil
	}

	o := &Obs{
		Ts: p.Ts, PID: p.PID, Comm: p.Comm, EPID: p.EPID, EComm: p.EComm,
		Iface: p.Ifname, Dir: p.Dir, WireLen: p.WireLen, Proto: Other,
	}
	var haveIP bool
	for _, lt := range d.decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			o.Src, _ = netip.AddrFromSlice(d.ip4.SrcIP)
			o.Dst, _ = netip.AddrFromSlice(d.ip4.DstIP)
			o.Src, o.Dst = o.Src.Unmap(), o.Dst.Unmap()
			haveIP = true
		case layers.LayerTypeIPv6:
			o.Src, _ = netip.AddrFromSlice(d.ip6.SrcIP)
			o.Dst, _ = netip.AddrFromSlice(d.ip6.DstIP)
			haveIP = true
		case layers.LayerTypeTCP:
			o.Proto = TCP
			o.SPort, o.DPort = uint16(d.tcp.SrcPort), uint16(d.tcp.DstPort)
			o.SYN, o.FIN, o.RST = d.tcp.SYN, d.tcp.FIN, d.tcp.RST
			o.PayloadLen = len(d.tcp.Payload)
			o.SNI = parseSNI(d.tcp.Payload)
		case layers.LayerTypeUDP:
			o.Proto = UDP
			o.SPort, o.DPort = uint16(d.udp.SrcPort), uint16(d.udp.DstPort)
			o.PayloadLen = len(d.udp.Payload)
			// QUIC Initials carry a readable ClientHello. This is where most
			// browser traffic to Google and Cloudflare lives, and without it
			// every one of those flows is a bare address.
			o.SNI = QUICSNI(d.udp.Payload)
		case layers.LayerTypeDNS:
			o.DNS = collectDNS(&d.dns)
			for _, q := range d.dns.Questions {
				if len(q.Name) > 0 {
					o.Questions = append(o.Questions, string(q.Name))
				}
			}
		case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
			o.Proto = ICMP
		}
	}
	if !haveIP {
		return nil
	}
	if o.WireLen == 0 {
		o.WireLen = len(p.Data)
	}
	return o
}

// collectDNS pulls A and AAAA answers out of a response and attributes each to
// the name the application actually asked for, following the CNAME chain by
// simply using the question. "cdn.foo.akamai.net" is technically correct and
// completely useless in a UI; "notion.so" is what the user recognizes.
func collectDNS(d *layers.DNS) []DNSRecord {
	if !d.QR || len(d.Answers) == 0 {
		return nil
	}
	question := ""
	if len(d.Questions) > 0 {
		question = string(d.Questions[0].Name)
	}
	var out []DNSRecord
	for _, a := range d.Answers {
		if a.Type != layers.DNSTypeA && a.Type != layers.DNSTypeAAAA {
			continue
		}
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		name := question
		if name == "" {
			name = string(a.Name)
		}
		out = append(out, DNSRecord{Name: name, IP: ip.Unmap(), TTL: a.TTL})
	}
	return out
}
