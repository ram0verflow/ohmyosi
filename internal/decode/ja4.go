package decode

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// JA4 is the TLS client fingerprint (FoxIO's JA4, github.com/FoxIO-LLC/ja4).
//
// It fingerprints the *software making the call* - Chrome vs a Go binary vs a
// particular malware kit - from the shape of its ClientHello: the ordered
// cipher list, the extensions it offers, the TLS version, ALPN and signature
// algorithms. Two properties make it worth the parsing:
//
//   - It identifies the client stack even when the destination does not. As
//     Encrypted Client Hello removes the SNI, JA4 is one of the few things left
//     that says anything about who is talking, so it is the answer to this
//     tool's own stated ECH problem.
//   - It is stable per stack and version, so the same browser produces the same
//     fingerprint every time, and something homemade stands out against the
//     handful of fingerprints every real browser and OS component produces.
//
// This is presentation, not classification: ohmyosi ships no fingerprint
// database and makes no claim from a JA4 alone. It is a fact about the flow, put
// next to the others so a person can recognise the odd one out.
//
// The format is a_b_c:
//
//	a = transport, TLS version, SNI present, cipher count, extension count, ALPN
//	b = first 12 hex of sha256 over the sorted cipher list
//	c = first 12 hex of sha256 over the sorted extension list plus signature algs
func JA4(payload []byte) string {
	// TLS record header: content type 0x16 (handshake), version, 16-bit length.
	if len(payload) < 5 || payload[0] != 0x16 {
		return ""
	}
	body := payload[5:]
	if n := int(payload[3])<<8 | int(payload[4]); n < len(body) {
		body = body[:n]
	}
	return ja4FromHandshake(body, 't')
}

// ja4FromHandshake reads a bare ClientHello - no record layer - the same shape
// QUIC carries inside its CRYPTO frames, so TCP and QUIC share everything here.
// The transport byte is 't' for TCP and 'q' for QUIC.
//
// Every read is bounds-checked against the enclosing length. This parser sees
// whatever the network sends, so a truncated or hostile ClientHello must return
// "" rather than panic.
func ja4FromHandshake(body []byte, transport byte) string {
	if len(body) < 4 || body[0] != 0x01 { // handshake type 0x01 = client_hello
		return ""
	}
	ch := body[4:]
	if n := int(body[1])<<16 | int(body[2])<<8 | int(body[3]); n < len(ch) {
		ch = ch[:n]
	}
	// client_version(2) + random(32)
	if len(ch) < 34 {
		return ""
	}
	legacyVer := int(ch[0])<<8 | int(ch[1])
	p := 34
	if len(ch) < p+1 {
		return ""
	}
	p += 1 + int(ch[p]) // legacy_session_id
	if len(ch) < p+2 {
		return ""
	}
	csLen := int(ch[p])<<8 | int(ch[p+1])
	p += 2
	if csLen < 0 || len(ch) < p+csLen {
		return ""
	}
	var ciphers []uint16
	for i := 0; i+1 < csLen; i += 2 {
		v := uint16(ch[p+i])<<8 | uint16(ch[p+i+1])
		if !isGREASE(v) {
			ciphers = append(ciphers, v)
		}
	}
	p += csLen
	if len(ch) < p+1 {
		return ""
	}
	p += 1 + int(ch[p]) // legacy_compression_methods
	if len(ch) < p+2 {
		// A ClientHello with no extensions block is legal, if antique.
		return assembleJA4(transport, legacyVer, ciphers, nil, false, "", nil)
	}
	extTotal := int(ch[p])<<8 | int(ch[p+1])
	p += 2
	end := p + extTotal
	if end > len(ch) {
		end = len(ch)
	}

	var (
		extTypes  []uint16
		sigAlgs   []uint16
		alpnFirst string
		svVersion int
		haveSNI   bool
	)
	for p+4 <= end {
		etype := uint16(ch[p])<<8 | uint16(ch[p+1])
		elen := int(ch[p+2])<<8 | int(ch[p+3])
		p += 4
		if p+elen > end {
			break
		}
		ext := ch[p : p+elen]
		p += elen
		if isGREASE(etype) {
			continue
		}
		// Extension count in the a-part includes SNI and ALPN; only the c-part
		// hash drops them. So every non-GREASE type is recorded here.
		extTypes = append(extTypes, etype)
		switch etype {
		case 0x0000: // server_name
			haveSNI = true
		case 0x0010: // application_layer_protocol_negotiation
			alpnFirst = firstALPN(ext)
		case 0x000d: // signature_algorithms
			sigAlgs = parseSigAlgs(ext)
		case 0x002b: // supported_versions
			svVersion = highestSupportedVersion(ext)
		}
	}
	ver := legacyVer
	if svVersion != 0 {
		ver = svVersion
	}
	return assembleJA4(transport, ver, ciphers, extTypes, haveSNI, alpnFirst, sigAlgs)
}

func assembleJA4(transport byte, ver int, ciphers, extTypes []uint16, haveSNI bool, alpn string, sigAlgs []uint16) string {
	sni := byte('i')
	if haveSNI {
		sni = 'd'
	}
	if alpn == "" {
		alpn = "00"
	}
	a := fmt.Sprintf("%c%s%c%02d%02d%s",
		transport, ja4Version(ver), sni, cap99(len(ciphers)), cap99(len(extTypes)), alpn)

	b := hash12(strings.Join(hexList(sortU16(ciphers)), ","))

	// The c-part hashes the sorted extension list with SNI and ALPN removed,
	// then the signature algorithms in the order the client presented them.
	cExts := make([]uint16, 0, len(extTypes))
	for _, e := range extTypes {
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		cExts = append(cExts, e)
	}
	cRaw := strings.Join(hexList(sortU16(cExts)), ",")
	if len(sigAlgs) > 0 {
		cRaw += "_" + strings.Join(hexList(sigAlgs), ",")
	}
	c := hash12(cRaw)

	return a + "_" + b + "_" + c
}

// hash12 is the first 12 hex characters of sha256, or twelve zeros for an empty
// section, matching the reference implementation.
func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func hexList(vs []uint16) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = fmt.Sprintf("%04x", v)
	}
	return out
}

func sortU16(vs []uint16) []uint16 {
	out := append([]uint16(nil), vs...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func cap99(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

// isGREASE reports the reserved values (RFC 8701) browsers scatter through their
// hellos to keep the ecosystem tolerant of unknowns. They are noise for
// fingerprinting and are excluded everywhere.
func isGREASE(v uint16) bool {
	return byte(v>>8) == byte(v&0xff) && v&0x0f == 0x0a
}

func ja4Version(v int) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0xfefc:
		return "d3"
	case 0xfefd:
		return "d2"
	case 0xfeff:
		return "d1"
	default:
		return "00"
	}
}

// highestSupportedVersion picks the newest non-GREASE version a client offers.
// ext is the supported_versions body: a 1-byte list length then 2-byte versions.
func highestSupportedVersion(ext []byte) int {
	if len(ext) < 1 {
		return 0
	}
	n := int(ext[0])
	if 1+n > len(ext) {
		n = len(ext) - 1
	}
	best := 0
	for i := 1; i+1 <= n; i += 2 {
		if 1+i+1 > len(ext) {
			break
		}
		v := int(ext[i])<<8 | int(ext[i+1])
		if isGREASE(uint16(v)) {
			continue
		}
		if v > best {
			best = v
		}
	}
	return best
}

// parseSigAlgs reads the signature_algorithms body: a 2-byte list length then
// 2-byte algorithm identifiers, kept in order (JA4 does not sort these).
func parseSigAlgs(ext []byte) []uint16 {
	if len(ext) < 2 {
		return nil
	}
	n := int(ext[0])<<8 | int(ext[1])
	if 2+n > len(ext) {
		n = len(ext) - 2
	}
	var out []uint16
	for i := 2; i+1 < 2+n && i+1 < len(ext); i += 2 {
		v := uint16(ext[i])<<8 | uint16(ext[i+1])
		if isGREASE(v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

// firstALPN returns the first and last byte of the first ALPN protocol - "h2"
// stays "h2", "http/1.1" becomes "h1" - the two characters JA4 uses to stand in
// for the negotiated protocol. ext is the ALPN body: a 2-byte list length, then
// length-prefixed protocol strings.
func firstALPN(ext []byte) string {
	if len(ext) < 3 {
		return ""
	}
	l := int(ext[2])
	if l == 0 || 3+l > len(ext) {
		return ""
	}
	proto := ext[3 : 3+l]
	return string([]byte{proto[0], proto[len(proto)-1]})
}
