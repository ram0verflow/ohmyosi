package decode

import "testing"

func TestClassifyECH(t *testing.T) {
	for _, c := range []struct {
		sni            string
		ext            bool
		outer, offered bool
	}{
		{"cloudflare-ech.com", true, true, false},   // real ECH: SNI is the front
		{"Cloudflare-ECH.com.", true, true, false},  // case and trailing dot
		{"www.google.com", true, false, true},       // GREASE: real SNI
		{"www.google.com", false, false, false},     // no extension
		{"cloudflare-ech.com", false, false, false}, // visiting the front itself
	} {
		outer, offered := classifyECH(c.sni, c.ext)
		if outer != c.outer || offered != c.offered {
			t.Errorf("%q ext=%v: outer %v offered %v", c.sni, c.ext, outer, offered)
		}
	}
}
