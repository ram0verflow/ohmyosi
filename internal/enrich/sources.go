package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Published address-space lists, straight from the operators.
//
// These are the open datasets: every provider here publishes its own ranges
// because other people need to route and firewall around them. No account, no
// API key, no licence to agree to. That is worth more than it sounds - a tool
// whose whole claim is transparency should not depend on a dataset you must
// register to obtain.
//
// This covers the operators that dominate a laptop's traffic. Everything else
// falls through to reverse DNS, and to an ASN database if one is configured.
//
// Fetched once by `ohmyosi -update-ranges`, written to disk, then used offline.

// ListSource is one published allocation list.
type ListSource struct {
	Name  string
	URL   string
	Parse func(body []byte) ([]Prefix, error)
}

// Result records what one source produced, so an update reports exactly what it
// got and from where rather than silently returning fewer prefixes.
type Result struct {
	Source string
	Count  int
	Err    error
}

func Sources() []ListSource {
	return []ListSource{
		{"cloudflare-v4", "https://www.cloudflare.com/ips-v4", plainCIDR("Cloudflare", "cloudflare-v4")},
		{"cloudflare-v6", "https://www.cloudflare.com/ips-v6", plainCIDR("Cloudflare", "cloudflare-v6")},
		{"aws", "https://ip-ranges.amazonaws.com/ip-ranges.json", parseAWS},
		{"google", "https://www.gstatic.com/ipranges/goog.json", parseGoogle},
		{"google-cloud", "https://www.gstatic.com/ipranges/cloud.json", parseGoogleCloud},
		{"fastly", "https://api.fastly.com/public-ip-list", parseFastly},
		{"github", "https://api.github.com/meta", parseGitHub},
	}
}

// Builtin covers allocations that are stable, well known, and not published as
// a machine-readable list by their owner. Kept deliberately short: every entry
// here is a claim we are making ourselves rather than quoting, so it needs to
// be one that is not in dispute.
func Builtin() []Prefix {
	must := func(s string) netip.Prefix { p, _ := netip.ParsePrefix(s); return p }
	return []Prefix{
		// Apple holds one of the original class-A allocations outright.
		{P: must("17.0.0.0/8"), Org: "Apple", Src: "builtin"},
		{P: must("2620:149::/32"), Org: "Apple", Src: "builtin"},
	}
}

// Update fetches every source concurrently and returns the combined prefixes
// plus a per-source report. A failing source is reported, never silently
// dropped: fewer names is a result the operator should be told about.
func Update(ctx context.Context) ([]Prefix, []Result) {
	client := &http.Client{Timeout: 30 * time.Second}
	srcs := Sources()

	type out struct {
		ps  []Prefix
		res Result
	}
	ch := make(chan out, len(srcs))
	for _, s := range srcs {
		go func(s ListSource) {
			ps, err := fetch(ctx, client, s)
			ch <- out{ps, Result{Source: s.Name, Count: len(ps), Err: err}}
		}(s)
	}

	all := Builtin()
	results := []Result{{Source: "builtin", Count: len(all)}}
	for range srcs {
		o := <-ch
		all = append(all, o.ps...)
		results = append(results, o.res)
	}
	return all, results
}

func fetch(ctx context.Context, c *http.Client, s ListSource) ([]Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ohmyosi/0.1 (+https://github.com/eulerbutcooler/ohmyosi)")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", s.URL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	return s.Parse(body)
}

func plainCIDR(org, src string) func([]byte) ([]Prefix, error) {
	return func(body []byte) ([]Prefix, error) {
		var out []Prefix
		for _, line := range strings.Fields(string(body)) {
			if p, err := netip.ParsePrefix(line); err == nil {
				out = append(out, Prefix{P: p, Org: org, Src: src})
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%s: no prefixes parsed", src)
		}
		return out, nil
	}
}

func parseAWS(body []byte) ([]Prefix, error) {
	var f struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPPrefix string `json:"ipv6_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, err
	}
	var out []Prefix
	// AWS publishes overlapping entries: a broad one tagged AMAZON and narrow
	// ones tagged S3, EC2, CLOUDFRONT. Longest-prefix lookup picks the specific
	// one, which is why "Amazon S3 ap-southeast-1" is reachable at all.
	add := func(cidr, region, service string) {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return
		}
		detail := region
		if service != "" && service != "AMAZON" {
			detail = service + " " + region
		}
		out = append(out, Prefix{P: p, Org: "Amazon", Detail: strings.TrimSpace(detail), Src: "aws"})
	}
	for _, p := range f.Prefixes {
		add(p.IPPrefix, p.Region, p.Service)
	}
	for _, p := range f.IPv6Prefixes {
		add(p.IPPrefix, p.Region, p.Service)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("aws: no prefixes parsed")
	}
	return out, nil
}

type googFile struct {
	Prefixes []struct {
		V4      string `json:"ipv4Prefix"`
		V6      string `json:"ipv6Prefix"`
		Service string `json:"service"`
		Scope   string `json:"scope"`
	} `json:"prefixes"`
}

func parseGoog(body []byte, org, src string) ([]Prefix, error) {
	var f googFile
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, err
	}
	var out []Prefix
	for _, e := range f.Prefixes {
		for _, c := range []string{e.V4, e.V6} {
			if c == "" {
				continue
			}
			if p, err := netip.ParsePrefix(c); err == nil {
				detail := strings.TrimSpace(e.Service + " " + e.Scope)
				out = append(out, Prefix{P: p, Org: org, Detail: detail, Src: src})
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no prefixes parsed", src)
	}
	return out, nil
}

func parseGoogle(body []byte) ([]Prefix, error) { return parseGoog(body, "Google", "google") }

func parseGoogleCloud(body []byte) ([]Prefix, error) {
	return parseGoog(body, "Google Cloud", "google-cloud")
}

func parseFastly(body []byte) ([]Prefix, error) {
	var f struct {
		Addresses []string `json:"addresses"`
		V6        []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, err
	}
	var out []Prefix
	for _, c := range append(append([]string{}, f.Addresses...), f.V6...) {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, Prefix{P: p, Org: "Fastly", Src: "fastly"})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("fastly: no prefixes parsed")
	}
	return out, nil
}

func parseGitHub(body []byte) ([]Prefix, error) {
	// The meta endpoint is a map of role -> CIDR list, and the roles change
	// over time, so decode generically and keep the role as detail.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	var out []Prefix
	for role, v := range raw {
		var list []string
		if json.Unmarshal(v, &list) != nil {
			continue // not a CIDR list (ssh keys, verifiable_password_authentication)
		}
		for _, c := range list {
			if p, err := netip.ParsePrefix(c); err == nil {
				out = append(out, Prefix{P: p, Org: "GitHub", Detail: role, Src: "github"})
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("github: no prefixes parsed")
	}
	return out, nil
}
