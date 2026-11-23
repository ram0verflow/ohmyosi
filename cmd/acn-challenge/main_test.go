package main

import (
	"net/netip"
	"testing"
)

func ans(ttl uint32, ips ...string) dohAnswer {
	a := dohAnswer{TTL: ttl}
	for _, s := range ips {
		a.IPs = append(a.IPs, netip.MustParseAddr(s))
	}
	return a
}

func TestSharedPairs(t *testing.T) {
	addrs := map[string]dohAnswer{
		"notion.so":      ans(300, "104.18.1.1", "104.18.1.2"),
		"discord.com":    ans(60, "104.18.1.1"),
		"www.notion.so":  ans(300, "104.18.1.2"), // same site as notion.so: never paired with it
		"github.com":     ans(60, "140.82.112.3"),
		"cdn.github.com": ans(60, "140.82.112.3"), // same registrable domain only
	}
	ps := sharedPairs(addrs)
	if len(ps) != 1 {
		t.Fatalf("pairs %+v", ps)
	}
	p := ps[0]
	if p.ip.String() != "104.18.1.1" || p.real != "discord.com" || p.decoy != "notion.so" || p.ttl != 300 {
		t.Fatalf("pair %+v", p)
	}
	s := singleNames(addrs)
	if len(s) != 0 {
		t.Fatalf("singles %v", s)
	}
	if s := singleNames(map[string]dohAnswer{"a.com": ans(1, "1.1.1.1"), "b.com": ans(1, "2.2.2.2"), "c.com": ans(1, "2.2.2.2")}); len(s) != 1 || s[0] != "a.com" {
		t.Fatalf("singles %v", s)
	}
}

func TestDialable(t *testing.T) {
	for s, want := range map[string]bool{
		"104.18.1.1": true, "59.111.160.244": true,
		"0.0.0.1": false, "0.0.0.0": false, "127.0.0.1": false, "10.0.0.1": false,
		"192.168.1.1": false, "100.64.0.1": false, "198.18.0.5": false, "169.254.1.1": false,
		"224.0.0.1": false, "255.255.255.255": false, "2606:4700::1": false,
	} {
		if got := dialable(netip.MustParseAddr(s)); got != want {
			t.Errorf("dialable(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestPartition(t *testing.T) {
	ps := make([]pair, 10)
	for i := range ps {
		ps[i].real = string(rune('a' + i))
	}
	seen := map[string]int{}
	for k := 0; k < 7; k++ {
		for _, p := range partition(ps, k, 7) {
			seen[p.real]++
		}
	}
	for _, p := range ps {
		if seen[p.real] != 1 {
			t.Fatalf("pair %s used %d times across scenarios", p.real, seen[p.real])
		}
	}
	if got := partition(ps[:3], 5, 7); len(got) != 3 {
		t.Fatalf("too few pairs should be shared: %d", len(got))
	}
}
