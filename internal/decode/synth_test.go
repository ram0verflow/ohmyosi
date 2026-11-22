package decode

import "testing"

// The builders must produce what the parsers read - otherwise lab results
// would be measuring the builder, not the network.
func TestSynthRoundTrip(t *testing.T) {
	if got := parseSNI(ClientHello("api.notion.so")); got != "api.notion.so" {
		t.Fatalf("tls: %q", got)
	}
	if got := parseSNI(ClientHello("")); got != "" {
		t.Fatalf("tls without sni: %q", got)
	}
	pkt := SealQUICInitial([]byte{1, 2, 3, 4, 5, 6, 7, 8}, "www.google.com")
	if len(pkt) < 1200 {
		t.Fatalf("initial not padded: %d", len(pkt))
	}
	sni, ja4 := QUICInfo(pkt)
	if sni != "www.google.com" || ja4 == "" || ja4[0] != 'q' {
		t.Fatalf("quic: %q %q", sni, ja4)
	}
}

func TestHelloFlags(t *testing.T) {
	ch := ClientHelloOpts("cloudflare-ech.com", "h2", true)
	if !HelloECH(ch) || parseSNI(ch) != "cloudflare-ech.com" {
		t.Fatal("ech not detected")
	}
	if HelloECH(ClientHello("example.com")) {
		t.Fatal("false ech")
	}
	if a := ALPNOf(JA4(ch)); a != "h2" {
		t.Fatalf("alpn %q from %q", a, JA4(ch))
	}
	if a := ALPNOf(JA4(ClientHello("x.example"))); a != "" {
		t.Fatalf("alpn %q", a)
	}
}
