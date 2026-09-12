package api

import (
	"net/netip"
	"testing"

	"ohmyosi/internal/flow"
	"ohmyosi/internal/rules"
	"ohmyosi/internal/score"
)

func viewForName(t *testing.T, src string, host string, port uint16, preExisting bool) FlowView {
	t.Helper()
	f := flow.Flow{
		Key: flow.Key{
			Remote: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), port),
		},
		PreExisting: preExisting,
	}
	return View(f, Endpoint{IP: "203.0.113.9", Port: port, Host: host, HostSrc: src}, score.Result{}, false, rules.Decision{}, false)
}

func TestViewClassifiesNameEvidenceScope(t *testing.T) {
	for _, tt := range []struct {
		src, want string
	}{
		{"sni", "flow"}, {"http", "flow"},
		{"dns", "address"}, {"rdns", "address"},
	} {
		got := viewForName(t, tt.src, "example.test", 443, false).Remote
		if got.NameScope != tt.want || got.NameGap != "" {
			t.Errorf("%s: scope=%q gap=%q, want scope=%q and no gap", tt.src, got.NameScope, got.NameGap, tt.want)
		}
	}
}

func TestViewExplainsMissingNameWithoutGuessing(t *testing.T) {
	for _, tt := range []struct {
		name        string
		port        uint16
		preExisting bool
		want        string
	}{
		{"pre-existing", 443, true, "pre_existing"},
		{"tls-or-quic", 443, false, "handshake_name_unavailable"},
		{"other", 22, false, "no_name_observed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := viewForName(t, "", "", tt.port, tt.preExisting).Remote
			if got.NameScope != "none" || got.NameGap != tt.want {
				t.Fatalf("scope=%q gap=%q, want none/%s", got.NameScope, got.NameGap, tt.want)
			}
		})
	}
}

func TestViewDoesNotCallAmbiguousDNSDirectIP(t *testing.T) {
	f := flow.Flow{Key: flow.Key{Remote: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), 443)}}
	remote := Endpoint{IP: "203.0.113.9", Port: 443, NameGap: "dns_ambiguous", NameCandidates: []string{"a.example", "b.example"}}
	got := View(f, remote, score.Result{}, false, rules.Decision{}, false)
	if got.Remote.NameScope != "address" || got.DirectIP {
		t.Fatalf("scope=%q direct_ip=%v, ambiguous DNS is address evidence, not direct IP", got.Remote.NameScope, got.DirectIP)
	}
}
