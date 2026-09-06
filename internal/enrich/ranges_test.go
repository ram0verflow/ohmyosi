package enrich

import (
	"net/netip"
	"testing"
	"time"
)

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

// Longest prefix must win. AWS publishes a broad AMAZON block and narrow
// per-service blocks inside it; if the broad one matched first, every S3
// address would report "Amazon" with no region and the detail would be lost.
func TestLookupPrefersMostSpecific(t *testing.T) {
	r := NewRanges()
	r.Set([]Prefix{
		{P: mustPrefix("52.0.0.0/8"), Org: "Amazon", Src: "aws"},
		{P: mustPrefix("52.219.0.0/16"), Org: "Amazon", Detail: "S3 ap-southeast-1", Src: "aws"},
		{P: mustPrefix("104.16.0.0/13"), Org: "Cloudflare", Src: "cloudflare-v4"},
	}, time.Now())

	got, ok := r.Lookup(netip.MustParseAddr("52.219.4.9"))
	if !ok || got.Detail != "S3 ap-southeast-1" {
		t.Errorf("specific block should win: %+v ok=%v", got, ok)
	}
	if got, ok := r.Lookup(netip.MustParseAddr("52.4.4.4")); !ok || got.Org != "Amazon" || got.Detail != "" {
		t.Errorf("broad block: %+v ok=%v", got, ok)
	}
	if got, ok := r.Lookup(netip.MustParseAddr("104.18.18.125")); !ok || got.Org != "Cloudflare" {
		t.Errorf("cloudflare: %+v ok=%v", got, ok)
	}
	if _, ok := r.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("unlisted address should not match")
	}
}

// v4 and v6 live in separate lists; a v6 address must never match a v4 block.
func TestLookupSeparatesFamilies(t *testing.T) {
	r := NewRanges()
	r.Set([]Prefix{
		{P: mustPrefix("104.16.0.0/13"), Org: "Cloudflare"},
		{P: mustPrefix("2606:4700::/32"), Org: "Cloudflare", Src: "cloudflare-v6"},
	}, time.Now())

	if got, ok := r.Lookup(netip.MustParseAddr("2606:4700:4408::ac40:9bd1")); !ok || got.Org != "Cloudflare" {
		t.Errorf("v6 lookup: %+v ok=%v", got, ok)
	}
	if _, ok := r.Lookup(netip.MustParseAddr("2001:db8::1")); ok {
		t.Error("unlisted v6 should not match")
	}
}

// An IPv4-mapped v6 address must resolve against the v4 table. gopacket hands
// these back for some link types, and without unmapping they silently miss.
func TestLookupUnmapsV4(t *testing.T) {
	r := NewRanges()
	r.Set([]Prefix{{P: mustPrefix("17.0.0.0/8"), Org: "Apple"}}, time.Now())
	if got, ok := r.Lookup(netip.MustParseAddr("::ffff:17.248.154.135")); !ok || got.Org != "Apple" {
		t.Errorf("mapped v4: %+v ok=%v", got, ok)
	}
}

func TestParseAWS(t *testing.T) {
	body := []byte(`{"prefixes":[
	  {"ip_prefix":"52.0.0.0/8","region":"us-east-1","service":"AMAZON"},
	  {"ip_prefix":"52.219.0.0/16","region":"ap-southeast-1","service":"S3"}],
	 "ipv6_prefixes":[{"ipv6_prefix":"2600:1f00::/24","region":"us-west-2","service":"EC2"}]}`)
	ps, err := parseAWS(body)
	if err != nil || len(ps) != 3 {
		t.Fatalf("got %d prefixes, err %v", len(ps), err)
	}
	// The generic AMAZON tag carries no service detail; a real service does.
	if ps[0].Detail != "us-east-1" {
		t.Errorf("generic entry detail: %q", ps[0].Detail)
	}
	if ps[1].Detail != "S3 ap-southeast-1" {
		t.Errorf("service entry detail: %q", ps[1].Detail)
	}
	if ps[2].Org != "Amazon" || !ps[2].P.Addr().Is6() {
		t.Errorf("v6 entry: %+v", ps[2])
	}
}

func TestParseGoogleAndFastly(t *testing.T) {
	g, err := parseGoogle([]byte(`{"prefixes":[{"ipv4Prefix":"8.8.4.0/24"},{"ipv6Prefix":"2001:4860::/32"}]}`))
	if err != nil || len(g) != 2 || g[0].Org != "Google" {
		t.Fatalf("google: %d %v", len(g), err)
	}
	f, err := parseFastly([]byte(`{"addresses":["151.101.0.0/16"],"ipv6_addresses":["2a04:4e42::/32"]}`))
	if err != nil || len(f) != 2 || f[1].Org != "Fastly" {
		t.Fatalf("fastly: %d %v", len(f), err)
	}
}

// GitHub's meta endpoint mixes CIDR lists with values that are not lists at
// all, and its keys change over time - so it is decoded generically and the
// non-list values must be skipped rather than blowing up the whole parse.
func TestParseGitHubSkipsNonLists(t *testing.T) {
	body := []byte(`{"verifiable_password_authentication":true,
	  "ssh_key_fingerprints":{"SHA256_RSA":"abc"},
	  "web":["140.82.112.0/20"],"api":["143.55.64.0/20","2a0a:a440::/29"]}`)
	ps, err := parseGitHub(body)
	if err != nil {
		t.Fatalf("err %v", err)
	}
	if len(ps) != 3 {
		t.Fatalf("got %d prefixes, want 3", len(ps))
	}
	for _, p := range ps {
		if p.Org != "GitHub" || p.Detail == "" {
			t.Errorf("entry missing org or role: %+v", p)
		}
	}
}

// A source that returns something unparseable must error rather than quietly
// contributing zero prefixes: silently losing a whole provider is exactly the
// kind of gap this tool exists to not have.
func TestParsersErrorOnEmpty(t *testing.T) {
	if _, err := parseAWS([]byte(`{"prefixes":[]}`)); err == nil {
		t.Error("aws: want error on empty")
	}
	if _, err := parseFastly([]byte(`{}`)); err == nil {
		t.Error("fastly: want error on empty")
	}
	if _, err := plainCIDR("X", "x")([]byte("not a cidr\n")); err == nil {
		t.Error("plain: want error on empty")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ranges.json"
	when := time.Now().Truncate(time.Second)

	r := NewRanges()
	r.Set([]Prefix{
		{P: mustPrefix("104.16.0.0/13"), Org: "Cloudflare", Src: "cloudflare-v4"},
		{P: mustPrefix("2606:4700::/32"), Org: "Cloudflare", Src: "cloudflare-v6"},
	}, when)
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}

	r2 := NewRanges()
	if err := r2.Load(path); err != nil {
		t.Fatal(err)
	}
	if r2.Len() != 2 {
		t.Fatalf("len after load: %d", r2.Len())
	}
	if !r2.Updated().Equal(when) {
		t.Errorf("updated: %v want %v", r2.Updated(), when)
	}
	if got, ok := r2.Lookup(netip.MustParseAddr("104.18.18.125")); !ok || got.Src != "cloudflare-v4" {
		t.Errorf("lookup after load: %+v", got)
	}
}
