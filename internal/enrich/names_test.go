package enrich

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestLearnDNSStoresOnlyDNSAddressEvidence(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	n := NewNames(false)
	n.LearnDNS(ip, "service.example.", time.Minute)

	host, src := n.Lookup(ip)
	if host != "service.example" || src != SrcDNS {
		t.Fatalf("lookup=%q/%q, want service.example/dns", host, src)
	}
}

func TestDNSAmbiguityAbstainsAndPreservesCandidates(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	n := NewNames(false)
	n.LearnDNS(ip, "beta.example", time.Minute)
	n.LearnDNS(ip, "alpha.example", time.Minute)

	got := n.LookupResult(ip)
	if !got.Ambiguous || got.Name != "" || got.Source != SrcDNS {
		t.Fatalf("lookup=%+v, want explicit DNS ambiguity with no selected name", got)
	}
	if len(got.Candidates) != 2 || got.Candidates[0] != "alpha.example" || got.Candidates[1] != "beta.example" {
		t.Fatalf("candidates=%v, want stable sorted names", got.Candidates)
	}
}

func TestRepeatedDNSNameIsNotAmbiguous(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	n := NewNames(false)
	n.LearnDNS(ip, "same.example", time.Minute)
	n.LearnDNS(ip, "same.example", 2*time.Minute)
	if got := n.LookupResult(ip); got.Name != "same.example" || got.Ambiguous {
		t.Fatalf("repeated answer became ambiguous: %+v", got)
	}
}

func TestDNSCandidatesRespectTTL(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	n := NewNames(false)
	now := time.Unix(100, 0)
	n.now = func() time.Time { return now }
	n.LearnDNS(ip, "old.example", 2*time.Second)
	now = now.Add(3 * time.Second)
	n.LearnDNS(ip, "fresh.example", time.Minute)

	got := n.LookupResult(ip)
	if got.Name != "fresh.example" || got.Ambiguous {
		t.Fatalf("lookup=%+v, expired name should not remain a candidate", got)
	}
}

func TestZeroTTLWithdrawsDNSCandidate(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	n := NewNames(false)
	n.LearnDNS(ip, "gone.example", time.Minute)
	n.LearnDNS(ip, "gone.example", 0)
	if got := n.LookupResult(ip); got.Name != "" || got.Ambiguous {
		t.Fatalf("zero-TTL goodbye left a candidate: %+v", got)
	}
}

func TestConcurrentDNSLearningAndLookup(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	n := NewNames(false)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if worker%2 == 0 {
					n.LearnDNS(ip, "alpha.example", time.Minute)
				} else {
					n.LearnDNS(ip, "beta.example", time.Minute)
				}
				_ = n.LookupResult(ip)
			}
		}(worker)
	}
	wg.Wait()
}
