package decode

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// Builders for the two handshakes ohmyosi reads names from. They exist for the
// lab (cmd/acn-lab) and for tests: an experiment with known ground truth needs
// real wire bytes, and building them here, next to the parsers, keeps both
// sides honest about the format.

// ClientHello returns a TLS record carrying a minimal, structurally valid
// ClientHello with the given SNI ("" for none) and a TLS 1.3 cipher.
func ClientHello(sni string) []byte { return ClientHelloOpts(sni, "", false) }

// ClientHelloOpts adds an ALPN protocol ("h2", "http/1.1"; "" for none) and,
// with ech, an encrypted_client_hello extension - in which case sni plays the
// part of the public outer name.
func ClientHelloOpts(sni, alpn string, ech bool) []byte {
	hs := clientHelloHandshakeOpts(sni, alpn, ech)
	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func clientHelloHandshake(sni string) []byte { return clientHelloHandshakeOpts(sni, "", false) }

func clientHelloHandshakeOpts(sni, alpn string, ech bool) []byte {
	var ext []byte
	if alpn != "" {
		p := append([]byte{byte(len(alpn))}, alpn...)
		l := binary.BigEndian.AppendUint16(nil, uint16(len(p)))
		l = append(l, p...)
		ext = append(ext, 0x00, 0x10)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(l)))
		ext = append(ext, l...)
	}
	if ech {
		// Outer ECH payload; contents are opaque ciphertext to an observer.
		ext = append(ext, 0xfe, 0x0d, 0x00, 0x20)
		ext = append(ext, make([]byte, 32)...)
	}
	if sni != "" {
		name := []byte(sni)
		sn := []byte{0x00}
		sn = binary.BigEndian.AppendUint16(sn, uint16(len(name)))
		sn = append(sn, name...)
		list := binary.BigEndian.AppendUint16(nil, uint16(len(sn)))
		list = append(list, sn...)
		ext = append(ext, 0x00, 0x00)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(list)))
		ext = append(ext, list...)
	}
	// supported_versions: TLS 1.3, so JA4 reports t13.
	ext = append(ext, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

// SealQUICInitial builds a QUIC v1 client Initial packet, padded to 1200 bytes,
// whose CRYPTO frame carries a ClientHello for sni - protected exactly as
// RFC 9001 §5 prescribes, so QUICInfo has to do the real work to read it.
func SealQUICInitial(dcid []byte, sni string) []byte {
	ch := clientHelloHandshake(sni)
	frames := []byte{0x06, 0x00} // CRYPTO, offset 0
	frames = appendVarint(frames, uint64(len(ch)))
	frames = append(frames, ch...)
	return sealInitial(dcid, 2, frames)
}

// sealInitial protects the given frames as QUIC v1 client Initial number pn,
// padded to 1200 bytes.
func sealInitial(dcid []byte, pn byte, frames []byte) []byte {
	initialSecret := hkdfExtract(initialSaltV1, dcid)
	client := hkdfExpandLabel(initialSecret, "client in", 32)
	key := hkdfExpandLabel(client, "quic key", 16)
	iv := hkdfExpandLabel(client, "quic iv", 12)
	hp := hkdfExpandLabel(client, "quic hp", 16)

	const pnLen = 4
	const target = 1200
	// header: first byte, version, dcid, scid(0), token(0), length(2-byte varint), pn
	hdrLen := 1 + 4 + 1 + len(dcid) + 1 + 1 + 2 + pnLen
	pad := target - hdrLen - len(frames) - 16
	if pad > 0 {
		frames = append(frames, make([]byte, pad)...)
	}
	payloadLen := pnLen + len(frames) + 16

	hdr := []byte{0xc0 | (pnLen - 1)}
	hdr = binary.BigEndian.AppendUint32(hdr, quicV1)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00)                                       // scid len
	hdr = append(hdr, 0x00)                                       // token len
	hdr = append(hdr, 0x40|byte(payloadLen>>8), byte(payloadLen)) // 2-byte varint
	pnOffset := len(hdr)
	hdr = append(hdr, 0, 0, 0, pn)

	blk, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(blk)
	nonce := make([]byte, 12)
	copy(nonce, iv)
	nonce[11] ^= pn
	ct := aead.Seal(nil, nonce, frames, hdr)
	pkt := append(append([]byte{}, hdr...), ct...)

	hpb, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	hpb.Encrypt(mask, pkt[pnOffset+4:pnOffset+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, 0x40|byte(v>>8), byte(v))
	default:
		return append(b, 0x80|byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}
