package decode

// parseSNI extracts the server_name from a TLS ClientHello.
//
// Scope and limits, because both matter for how much you trust the output:
//
//   - Only the first TCP segment of a connection is examined. A ClientHello
//     split across segments is missed. Rare in practice; reassembly is a much
//     bigger machine than it is worth here.
//   - Encrypted Client Hello encrypts this field. As ECH rolls out in Chrome
//     and Firefox this returns "" more and more often, and the fallback is
//     reverse DNS plus ASN.
//   - QUIC is handled separately in quic.go, which decrypts the Initial packet
//     and calls parseSNIHandshake with the ClientHello it finds inside.
//
// Every read is bounds-checked against the enclosing length. Hostile input is
// the norm here: this parser sees whatever the network sends.
func parseSNI(b []byte) string {
	// TLS record header: content type (0x16 handshake), version, length.
	if len(b) < 5 || b[0] != 0x16 {
		return ""
	}
	body := b[5:]
	if n := int(b[3])<<8 | int(b[4]); n < len(body) {
		body = body[:n]
	}
	return parseSNIHandshake(body)
}

// parseSNIHandshake reads a bare TLS handshake message - no record layer.
// QUIC carries the ClientHello this way, inside CRYPTO frames, so both
// transports share everything below here.
func parseSNIHandshake(body []byte) string {
	// Handshake header: type (0x01 client_hello), 24-bit length.
	if len(body) < 4 || body[0] != 0x01 {
		return ""
	}
	ch := body[4:]
	if n := int(body[1])<<16 | int(body[2])<<8 | int(body[3]); n < len(ch) {
		ch = ch[:n]
	}
	// client_version(2) + random(32)
	p := 34
	if len(ch) < p+1 {
		return ""
	}
	p += 1 + int(ch[p]) // legacy_session_id
	if len(ch) < p+2 {
		return ""
	}
	p += 2 + (int(ch[p])<<8 | int(ch[p+1])) // cipher_suites
	if len(ch) < p+1 {
		return ""
	}
	p += 1 + int(ch[p]) // legacy_compression_methods
	if len(ch) < p+2 {
		return ""
	}
	end := p + 2 + (int(ch[p])<<8 | int(ch[p+1]))
	p += 2
	if end > len(ch) {
		end = len(ch)
	}
	for p+4 <= end {
		etype := int(ch[p])<<8 | int(ch[p+1])
		elen := int(ch[p+2])<<8 | int(ch[p+3])
		p += 4
		if p+elen > end {
			return ""
		}
		if etype != 0x0000 { // server_name
			p += elen
			continue
		}
		ext := ch[p : p+elen]
		if len(ext) < 2 {
			return ""
		}
		q := 2 // server_name_list length
		for q+3 <= len(ext) {
			nameType := ext[q]
			nameLen := int(ext[q+1])<<8 | int(ext[q+2])
			q += 3
			if q+nameLen > len(ext) {
				return ""
			}
			if nameType == 0 { // host_name
				return string(ext[q : q+nameLen])
			}
			q += nameLen
		}
		return ""
	}
	return ""
}
