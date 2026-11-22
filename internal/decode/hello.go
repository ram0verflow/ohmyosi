package decode

import "net/netip"

// Reassembling ClientHellos that do not fit in one packet.
//
// Post-quantum key shares (X25519MLKEM768, on by default in Chrome and Safari
// 26) make a ClientHello about 1.9 KB: more than one TCP segment and more than
// one QUIC Initial. Chrome also shuffles its extensions, and in QUIC splits and
// reorders its CRYPTO frames, so whether server_name lands in the first packet
// is a coin toss. Reading only the first packet made the readable flows a
// random fraction of a browser's connections and pushed the rest to "neither".
//
// So the decoder keeps, per client 4-tuple, the packets of a hello that began
// but has not finished, and reads it once it is whole. Bounded: helloMaxPkts
// packets and helloMaxBytes per connection, helloMaxConns connections pending.
// Past those limits a hello is dropped and simply goes unread.

const (
	helloMaxPkts  = 8
	helloMaxBytes = 32 << 10
	helloMaxConns = 4096
)

type helloKey struct {
	proto        Proto
	src, dst     netip.Addr
	sport, dport uint16
}

type pendingHello struct {
	pkts int
	// TCP: the TLS record so far, its full length, and the next sequence number.
	rec  []byte
	need int
	next uint32
	// QUIC: CRYPTO frame data by stream offset.
	crypto map[uint64][]byte
}

func (d *Decoder) park(k helloKey, p *pendingHello) {
	if len(d.pending) >= helloMaxConns {
		clear(d.pending) // never complete is the usual reason; start over
	}
	d.pending[k] = p
}

// helloRecordLen is the full length of the TLS record a ClientHello starts in
// b (record header included), or 0 if b does not start one.
func helloRecordLen(b []byte) int {
	if len(b) < 6 || b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x01 {
		return 0
	}
	return 5 + (int(b[3])<<8 | int(b[4]))
}

func tlsHello(rec []byte) (sni, ja4 string, ech bool) {
	ja4 = JA4(rec)
	return parseSNI(rec), ja4, ja4 != "" && HelloECH(rec)
}

// tcpHello reads a ClientHello from one client segment, buffering it across
// segments when the record is longer than the segment. wireLen is the
// segment's payload length on the wire; payload may be shorter when snaplen
// cut the packet. In-order only: a retransmitted segment is ignored.
//
// When the hello cannot be completed - a segment truncated by snaplen, or a
// gap - what was captured is read as far as it goes, which is all a
// first-segment reader ever had.
func (d *Decoder) tcpHello(k helloKey, seq uint32, payload []byte, wireLen int) (sni, ja4 string, ech bool) {
	if wireLen < len(payload) {
		wireLen = len(payload)
	}
	if p, ok := d.pending[k]; ok && p.rec != nil {
		if len(payload) == 0 {
			return "", "", false
		}
		p.pkts++
		switch ahead := int32(seq - p.next); {
		case ahead < 0: // retransmission of something already buffered
			if p.pkts >= helloMaxPkts {
				delete(d.pending, k)
				return tlsHello(p.rec)
			}
			return "", "", false
		case ahead > 0: // a segment is missing
			delete(d.pending, k)
			return tlsHello(p.rec)
		}
		p.rec = append(p.rec, payload...)
		p.next += uint32(wireLen)
		switch {
		case len(p.rec) >= p.need:
			delete(d.pending, k)
			return tlsHello(p.rec[:p.need])
		case wireLen > len(payload), p.pkts >= helloMaxPkts:
			delete(d.pending, k)
			return tlsHello(p.rec)
		}
		return "", "", false
	}
	if need := helloRecordLen(payload); need > len(payload) && need <= helloMaxBytes && wireLen == len(payload) {
		d.park(k, &pendingHello{
			pkts: 1, need: need, next: seq + uint32(len(payload)),
			rec: append(make([]byte, 0, need), payload...),
		})
		return "", "", false
	}
	return tlsHello(payload)
}

// quicHello reads a ClientHello from a client Initial, collecting CRYPTO
// frames across Initials until the handshake message is complete.
func (d *Decoder) quicHello(k helloKey, payload []byte) (sni, ja4 string, ech bool) {
	plain := quicDecryptInitial(payload)
	if plain == nil {
		return "", "", false
	}
	frames := cryptoFrames(plain)
	if len(frames) == 0 {
		return "", "", false // ACK-only Initial, or one we could not walk
	}
	p, parked := d.pending[k]
	if !parked || p.crypto == nil {
		p, parked = &pendingHello{crypto: map[uint64][]byte{}}, false
	}
	p.pkts++
	for _, f := range frames {
		if _, dup := p.crypto[f.off]; !dup {
			p.crypto[f.off] = f.data // plain is freshly allocated per packet
		}
	}
	if hs := assembleCrypto(p.crypto); hs != nil {
		if parked {
			delete(d.pending, k)
		}
		return parseSNIHandshake(hs), ja4FromHandshake(hs, 'q'), helloHasExt(hs, extECH)
	}
	switch {
	case p.pkts >= helloMaxPkts:
		delete(d.pending, k)
	case !parked:
		d.park(k, p)
	}
	return "", "", false
}

type cryptoFrame struct {
	off  uint64
	data []byte
}

// cryptoFrames returns every CRYPTO frame in a decrypted client Initial,
// stepping over PADDING, PING and ACK. It stops at any other frame type, since
// past an unknown frame the boundaries are guesswork.
func cryptoFrames(b []byte) []cryptoFrame {
	var out []cryptoFrame
	for len(b) > 0 {
		t := b[0]
		b = b[1:]
		switch t {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK, ACK with ECN counts
			n := 4 // largest acked, delay, range count, first range
			for i := 0; i < n; i++ {
				v, w := varint(b)
				if w == 0 {
					return out
				}
				b = b[w:]
				if i == 2 {
					if v > 64 {
						return out
					}
					n += 2 * int(v) // gap and length per extra range
				}
			}
			if t == 0x03 {
				for i := 0; i < 3; i++ {
					_, w := varint(b)
					if w == 0 {
						return out
					}
					b = b[w:]
				}
			}
		case 0x06: // CRYPTO
			off, w := varint(b)
			if w == 0 {
				return out
			}
			b = b[w:]
			length, w := varint(b)
			if w == 0 || length > uint64(len(b)-w) {
				return out
			}
			b = b[w:]
			out = append(out, cryptoFrame{off: off, data: b[:length]})
			b = b[length:]
		default:
			return out
		}
	}
	return out
}

// assembleCrypto joins CRYPTO data from offset zero and returns the first
// handshake message once all of it is present, or nil.
func assembleCrypto(m map[uint64][]byte) []byte {
	var out []byte
	for {
		pos := uint64(len(out))
		grew := false
		for off, c := range m {
			if off <= pos && pos < off+uint64(len(c)) {
				out = append(out, c[pos-off:]...)
				grew = true
				break
			}
		}
		if !grew || len(out) > helloMaxBytes {
			break
		}
	}
	if len(out) < 4 || out[0] != 0x01 {
		return nil
	}
	n := 4 + (int(out[1])<<16 | int(out[2])<<8 | int(out[3]))
	if len(out) < n {
		return nil
	}
	return out[:n]
}
