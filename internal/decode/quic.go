package decode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// QUIC Initial packets carry a TLS ClientHello, and it is recoverable.
//
// I previously wrote this off as encrypted, which is technically true and
// practically wrong. The Initial packet's protection keys are derived from the
// Destination Connection ID using constants published in RFC 9001 - the point
// is to protect against middlebox ossification, not eavesdropping. Anyone
// holding the packet can decrypt it. Since Chrome and Brave speak QUIC to
// almost everything Google and Cloudflare serve, and every one of those flows
// currently shows as a bare address, this is the single largest naming gap.
//
// So: undo header protection, derive the initial secrets, decrypt with
// AES-128-GCM, walk the CRYPTO frames, and read the SNI out of the ClientHello.
//
// Limits worth knowing: only the client's first flight is readable this way,
// only QUIC v1 and v2 are handled, and a ClientHello split across several
// Initial packets is only recovered if the first one carries the extension.

var (
	// RFC 9001 §5.2 - QUIC v1.
	initialSaltV1 = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
	}
	// RFC 9369 §3.3.1 - QUIC v2 uses a different salt and labels.
	initialSaltV2 = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
	}
)

const (
	quicV1 = 0x00000001
	quicV2 = 0x6b3343cf
)

// QUICSNI returns the server name from a QUIC Initial packet, or "".
func QUICSNI(p []byte) string {
	// Long header with the fixed bit set. The packet-type bits cannot be read
	// yet, because v2 renumbered them.
	if len(p) < 7 || p[0]&0xc0 != 0xc0 {
		return ""
	}
	version := binary.BigEndian.Uint32(p[1:5])
	var salt []byte
	keyLabel, ivLabel, hpLabel := "quic key", "quic iv", "quic hp"
	// RFC 9369 §3.2 shuffled the long-header packet types specifically to break
	// middleboxes that assumed v1 numbering. Initial is 0b00 in v1 and 0b01 in
	// v2, so the type check has to come after the version.
	var initialType byte
	switch version {
	case quicV1:
		salt, initialType = initialSaltV1, 0x00
	case quicV2:
		salt, initialType = initialSaltV2, 0x10
		keyLabel, ivLabel, hpLabel = "quicv2 key", "quicv2 iv", "quicv2 hp"
	default:
		return "" // draft or unknown version
	}
	if p[0]&0x30 != initialType {
		return "" // Handshake, 0-RTT or Retry: no readable ClientHello here
	}

	off := 5
	dcidLen := int(p[off])
	off++
	if dcidLen > 20 || off+dcidLen > len(p) {
		return ""
	}
	dcid := p[off : off+dcidLen]
	off += dcidLen
	if off >= len(p) {
		return ""
	}
	scidLen := int(p[off])
	off++
	if scidLen > 20 || off+scidLen > len(p) {
		return ""
	}
	off += scidLen

	tokenLen, n := varint(p[off:])
	if n == 0 || off+n+int(tokenLen) > len(p) {
		return ""
	}
	off += n + int(tokenLen)

	payloadLen, n := varint(p[off:])
	if n == 0 {
		return ""
	}
	off += n
	pnOffset := off
	if pnOffset+int(payloadLen) > len(p) || payloadLen < 20 {
		return ""
	}

	// Initial secrets, both directions derived from the client's DCID.
	initialSecret := hkdfExtract(salt, dcid)
	client := hkdfExpandLabel(initialSecret, "client in", 32)
	key := hkdfExpandLabel(client, keyLabel, 16)
	iv := hkdfExpandLabel(client, ivLabel, 12)
	hp := hkdfExpandLabel(client, hpLabel, 16)

	// Header protection: the sample starts four bytes past the packet number,
	// because the packet number length is itself protected and unknown yet.
	sampleOff := pnOffset + 4
	if sampleOff+16 > len(p) {
		return ""
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		return ""
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, p[sampleOff:sampleOff+16])

	hdr := make([]byte, pnOffset+4)
	copy(hdr, p[:pnOffset+4])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	hdr = hdr[:pnOffset+pnLen]
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOffset+i])
	}

	// Nonce is the IV xored with the right-aligned packet number.
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}

	ciphertext := p[pnOffset+pnLen : pnOffset+int(payloadLen)]
	aeadBlock, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	aead, err := cipher.NewGCM(aeadBlock)
	if err != nil {
		return ""
	}
	plain, err := aead.Open(nil, nonce, ciphertext, hdr)
	if err != nil {
		return "" // not an Initial we can read: retry packet, wrong version, truncated
	}
	return sniFromFrames(plain)
}

// sniFromFrames walks QUIC frames looking for CRYPTO data at offset zero, which
// is where the ClientHello starts.
func sniFromFrames(b []byte) string {
	for len(b) > 0 {
		switch b[0] {
		case 0x00: // PADDING - the client pads Initials to 1200 bytes
			b = b[1:]
		case 0x01: // PING
			b = b[1:]
		case 0x06: // CRYPTO
			b = b[1:]
			off, n := varint(b)
			if n == 0 {
				return ""
			}
			b = b[n:]
			length, n := varint(b)
			if n == 0 {
				return ""
			}
			b = b[n:]
			if int(length) > len(b) {
				return ""
			}
			if off == 0 {
				// CRYPTO data is the bare handshake message: no TLS record
				// header, so hand it to the handshake-level parser.
				if s := parseSNIHandshake(b[:length]); s != "" {
					return s
				}
			}
			b = b[length:]
		default:
			// Any other frame type in a client Initial means we have lost the
			// thread; walking further would be guessing.
			return ""
		}
	}
	return ""
}

// varint decodes a QUIC variable-length integer, returning the value and how
// many bytes it used (0 on failure).
func varint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}

func hkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// hkdfExpandLabel is the TLS 1.3 construction QUIC borrows: the label is
// prefixed with "tls13 " and the context is empty.
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(length>>8), byte(length), byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)

	var out, prev []byte
	for i := byte(1); len(out) < length; i++ {
		h := hmac.New(sha256.New, secret)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{i})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}
