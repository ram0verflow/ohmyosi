package decode

import (
	"encoding/binary"
	"testing"
)

// clientHello builds a minimal but structurally valid ClientHello carrying the
// given SNI, optionally preceded by other extensions so we exercise the skip
// path (real clients put GREASE and ALPN before server_name all the time).
func clientHello(sni string, pad int) []byte {
	var ext []byte
	for i := 0; i < pad; i++ {
		ext = append(ext, 0x00, 0x17, 0x00, 0x02, 0xaa, 0xbb) // extended_master_secret-ish filler
	}
	if sni != "" {
		name := []byte(sni)
		var sn []byte
		sn = append(sn, 0x00)                                  // name_type host_name
		sn = binary.BigEndian.AppendUint16(sn, uint16(len(name)))
		sn = append(sn, name...)
		var list []byte
		list = binary.BigEndian.AppendUint16(list, uint16(len(sn)))
		list = append(list, sn...)
		ext = append(ext, 0x00, 0x00)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(list)))
		ext = append(ext, list...)
	}

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id len
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00) // compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func TestParseSNI(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want string
	}{
		{"simple", clientHello("example.com", 0), "example.com"},
		{"after other extensions", clientHello("notion.so", 5), "notion.so"},
		{"no sni extension", clientHello("", 3), ""},
		{"not a handshake record", []byte{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5}, ""},
		{"empty", nil, ""},
		{"header only", []byte{0x16, 0x03, 0x01, 0x00, 0x00}, ""},
	} {
		if got := parseSNI(tc.in); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

// TestParseSNITruncation is the one that matters in production: snaplen cuts
// packets off mid-structure, and a parser that indexes past the end takes the
// whole daemon down.
func TestParseSNITruncation(t *testing.T) {
	full := clientHello("example.com", 4)
	for i := 0; i < len(full); i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %d-byte prefix: %v", i, r)
				}
			}()
			parseSNI(full[:i])
		}()
	}
	if got := parseSNI(full); got != "example.com" {
		t.Fatalf("full parse regressed: %q", got)
	}
}

// Fuzz-ish: random bytes must never panic.
func TestParseSNIGarbage(t *testing.T) {
	b := make([]byte, 300)
	for seed := 0; seed < 2000; seed++ {
		x := uint32(seed*2654435761 + 1)
		for i := range b {
			x ^= x << 13
			x ^= x >> 17
			x ^= x << 5
			b[i] = byte(x)
		}
		b[0] = 0x16 // force it down the parse path
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on garbage seed %d: %v", seed, r)
				}
			}()
			parseSNI(b)
		}()
	}
}
