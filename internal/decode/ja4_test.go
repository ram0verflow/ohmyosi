package decode

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// The parser walks attacker-controlled bytes, so the tests exercise both a
// well-formed ClientHello and every way one can be truncated. A panic here
// takes the daemon down (snaplen cuts hellos off mid-structure), so garbage
// must return "" rather than crash.

func u16(v int) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, uint16(v)); return b }

func ext(etype int, body []byte) []byte {
	return append(append(u16(etype), u16(len(body))...), body...)
}

// buildHello assembles a TLS record around a ClientHello with the given pieces.
func buildHello() []byte {
	// Ciphers: one GREASE value (must be dropped) plus three real suites.
	ciphers := append(append(append(u16(0x0a0a), u16(0x1301)...), u16(0x1302)...), u16(0xc02b)...)

	sni := append(append([]byte{0x00}, u16(len("a.com"))...), []byte("a.com")...)
	sniBody := append(u16(len(sni)), sni...)

	supportedVersions := []byte{0x02, 0x03, 0x04} // list length 2, then TLS 1.3

	alpnProto := append([]byte{byte(len("h2"))}, []byte("h2")...)
	alpnBody := append(u16(len(alpnProto)), alpnProto...)

	sigAlgs := append(u16(4), append(u16(0x0403), u16(0x0804)...)...)

	exts := ext(0x0a0a, nil) // GREASE extension, dropped
	exts = append(exts, ext(0x0000, sniBody)...)
	exts = append(exts, ext(0x002b, supportedVersions)...)
	exts = append(exts, ext(0x0010, alpnBody)...)
	exts = append(exts, ext(0x000d, sigAlgs)...)

	var ch []byte
	ch = append(ch, u16(0x0303)...)       // legacy_version
	ch = append(ch, make([]byte, 32)...)  // random
	ch = append(ch, 0x00)                 // session id length 0
	ch = append(ch, u16(len(ciphers))...) // cipher suites length
	ch = append(ch, ciphers...)
	ch = append(ch, 0x01, 0x00)        // compression: length 1, method null
	ch = append(ch, u16(len(exts))...) // extensions length
	ch = append(ch, exts...)

	hs := []byte{0x01, byte(len(ch) >> 16), byte(len(ch) >> 8), byte(len(ch))}
	hs = append(hs, ch...)

	rec := []byte{0x16, 0x03, 0x01}
	rec = append(rec, u16(len(hs))...)
	rec = append(rec, hs...)
	return rec
}

func hash12of(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func TestJA4(t *testing.T) {
	got := JA4(buildHello())

	// a-part: tcp, TLS 1.3 (from supported_versions), SNI present, 3 ciphers,
	// 4 extensions (GREASE excluded), ALPN h2.
	wantA := "t13d0304h2"
	// b-part: sorted non-GREASE ciphers.
	wantB := hash12of("1301,1302,c02b")
	// c-part: extensions minus SNI (0000) and ALPN (0010), sorted, then the
	// signature algorithms in order.
	wantC := hash12of("000d,002b_0403,0804")
	want := wantA + "_" + wantB + "_" + wantC

	if got != want {
		t.Fatalf("JA4 mismatch\n got %q\nwant %q", got, want)
	}
	if a, _, _ := strings.Cut(got, "_"); a != wantA {
		t.Errorf("a-part = %q, want %q", a, wantA)
	}
}

func TestJA4Truncation(t *testing.T) {
	full := buildHello()
	// Every prefix of a valid hello must parse to "" or a fingerprint, never
	// panic. snaplen produces exactly these partial reads.
	for i := 0; i < len(full); i++ {
		_ = JA4(full[:i])
	}
	for _, junk := range [][]byte{
		nil, {}, {0x16}, {0x16, 0x03, 0x01, 0xff, 0xff},
		{0x17, 0x03, 0x03, 0x00, 0x05}, // not a handshake record
		make([]byte, 4096),             // all zeros
	} {
		if s := JA4(junk); s != "" {
			t.Errorf("JA4(% x) = %q, want empty", junk, s)
		}
	}
}

func TestJA4NotClientHello(t *testing.T) {
	// A ServerHello (handshake type 0x02) is not a client fingerprint.
	rec := []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}
	if s := JA4(rec); s != "" {
		t.Errorf("JA4 of ServerHello = %q, want empty", s)
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = false, want true", v)
		}
	}
	for _, v := range []uint16{0x1301, 0x0000, 0xc02b, 0x0a0b, 0x0b0a} {
		if isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = true, want false", v)
		}
	}
}
