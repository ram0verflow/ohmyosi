package api

import (
	"net/netip"
	"testing"
	"time"

	"ohmyosi/internal/enrich"
)

func TestInvestigateKeepsFlowEvidenceAheadOfAddressFallback(t *testing.T) {
	ip := netip.MustParseAddr("104.18.32.7")
	names := enrich.NewNames(false)
	names.LearnDNS(ip, "dns-fallback.example", time.Minute)
	ctx := InvestigateCtx{Names: names}

	tests := []struct {
		name, sni, httpHost, wantHost, wantSource string
	}{
		{"TLS flow", "alpha.example", "", "alpha.example", "sni"},
		{"cleartext HTTP flow", "", "beta.example", "beta.example", "http"},
		{"unnamed flow", "", "", "dns-fallback.example", "dns"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Investigate(ip, 443, tt.sni, tt.httpHost, ctx)
			if got.Host != tt.wantHost || got.HostSrc != tt.wantSource {
				t.Fatalf("host=%q source=%q, want %q/%q", got.Host, got.HostSrc, tt.wantHost, tt.wantSource)
			}
		})
	}
}

func TestInvestigateAbstainsOnAmbiguousDNS(t *testing.T) {
	ip := netip.MustParseAddr("104.18.32.7")
	names := enrich.NewNames(false)
	names.LearnDNS(ip, "alpha.example", time.Minute)
	names.LearnDNS(ip, "beta.example", time.Minute)

	got := Investigate(ip, 443, "", "", InvestigateCtx{Names: names})
	if got.Host != "" || got.NameGap != "dns_ambiguous" {
		t.Fatalf("host=%q gap=%q, want abstention for ambiguous DNS", got.Host, got.NameGap)
	}
	if len(got.NameCandidates) != 2 {
		t.Fatalf("candidates=%v, want both DNS names", got.NameCandidates)
	}
}

func TestSharedIPFlowsKeepDistinctHandshakeNames(t *testing.T) {
	ip := netip.MustParseAddr("104.18.32.7")
	ctx := InvestigateCtx{Names: enrich.NewNames(false)}

	alpha := Investigate(ip, 443, "alpha.example", "", ctx)
	beta := Investigate(ip, 443, "beta.example", "", ctx)
	unnamed := Investigate(ip, 443, "", "", ctx)

	if alpha.Host != "alpha.example" || beta.Host != "beta.example" {
		t.Fatalf("shared-IP flow names crossed: alpha=%q beta=%q", alpha.Host, beta.Host)
	}
	if unnamed.Host != "" || unnamed.HostSrc != "" {
		t.Fatalf("unnamed flow borrowed handshake evidence: host=%q source=%q", unnamed.Host, unnamed.HostSrc)
	}
}
