package enrich

import (
	"net/netip"
	"testing"
)

func TestLearnDNSStoresOnlyDNSAddressEvidence(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	n := NewNames(false)
	n.LearnDNS(ip, "service.example.")

	host, src := n.Lookup(ip)
	if host != "service.example" || src != SrcDNS {
		t.Fatalf("lookup=%q/%q, want service.example/dns", host, src)
	}
}
