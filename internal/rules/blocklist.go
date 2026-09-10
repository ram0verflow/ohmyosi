package rules

import (
	"bufio"
	"io"
	"strings"
)

// ParseHostsBlocklist reads a hosts-format blocklist - the format the big
// curated lists ship in (StevenBlack's ads/adult/malware lists, and countless
// others) - and returns the domains to block.
//
// Lines look like "0.0.0.0 ads.example" or "127.0.0.1 tracker.test", or
// sometimes a bare "ads.example". Comments (#) and the housekeeping entries a
// hosts file always carries (localhost, broadcasthost) are dropped, as is
// anything that does not look like a domain, so a malformed list degrades to
// fewer rules rather than garbage ones.
func ParseHostsBlocklist(r io.Reader) []string {
	skip := map[string]bool{
		"localhost": true, "localhost.localdomain": true,
		"broadcasthost": true, "local": true, "ip6-localhost": true,
		"ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
		"ip6-allnodes": true, "ip6-allrouters": true, "0.0.0.0": true,
	}
	seen := make(map[string]bool)
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// "0.0.0.0 domain" / "127.0.0.1 domain", or a bare "domain".
		cand := fields[0]
		if len(fields) >= 2 {
			cand = fields[1]
		}
		cand = strings.ToLower(strings.TrimSuffix(cand, "."))
		if !looksLikeDomain(cand) || skip[cand] || seen[cand] {
			continue
		}
		seen[cand] = true
		out = append(out, cand)
	}
	return out
}

// looksLikeDomain is a cheap sanity check, not a validator: a dotted name with
// no spaces or slashes and at least one letter, which is enough to reject IPs,
// URLs and header junk that turn up in these files.
func looksLikeDomain(s string) bool {
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	if strings.ContainsAny(s, " \t/:@") {
		return false
	}
	hasLetter := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			hasLetter = true
		case r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return hasLetter
}

// BlocklistRules turns a set of domains into enabled domain block rules, tagged
// with the source so they can be told apart from hand-written rules later.
func BlocklistRules(domains []string, source string) []Rule {
	note := "blocklist"
	if source != "" {
		note = "blocklist: " + source
	}
	out := make([]Rule, 0, len(domains))
	for _, d := range domains {
		out = append(out, Rule{Scope: ScopeDomain, Match: d, Action: Block, Enabled: true, Note: note})
	}
	return out
}
