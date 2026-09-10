package enrich

import (
	"net/netip"
	"testing"
)

func TestCymruQueryV4(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	if got := cymruQuery(ip); got != "8.8.8.8.origin.asn.cymru.com" {
		t.Fatalf("got %q", got)
	}
}

func TestCymruQueryPrivate(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.1")
	if got := cymruQuery(ip); got == "" {
		t.Fatal("expected query for routable private?")
	}
	// private still gets a query string; isResolvable filters at lookup time
}

// IPv6 uses reversed nibbles, which is easy to get subtly wrong and produces a
// query that simply never resolves rather than an error.
func TestCymruQueryV6(t *testing.T) {
	ip := netip.MustParseAddr("2606:4700::1")
	got := cymruQuery(ip)
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.6.0.6.2.origin6.asn.cymru.com"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestSplitPipe(t *testing.T) {
	got := splitPipe("13335 | 104.16.0.0/12 | US | arin | 2010-07-14")
	if len(got) != 5 || got[0] != "13335" || got[2] != "US" {
		t.Fatalf("got %#v", got)
	}
}
