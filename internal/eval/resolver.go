package eval

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// The method reads DNS answers off the wire. macOS 14+ follows Discovery of
// Designated Resolvers (RFC 9462): when the configured resolver advertises an
// encrypted endpoint, mDNSResponder switches to DoH/DoT by itself and no answer
// reaches the capture. The public resolvers below all advertise one. Capture
// scripts record the resolver in each manifest (tools/resolver.sh); reports
// print it and warn when a run's DNS was probably invisible.

// DDRPublicResolvers are public resolvers that advertise DDR.
var DDRPublicResolvers = []string{
	"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844", // Google
	"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001", // Cloudflare
	"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9", // Quad9
}

func isDDRPublic(ns string) bool {
	if i := strings.IndexByte(ns, '%'); i >= 0 {
		ns = ns[:i]
	}
	a, err := netip.ParseAddr(ns)
	if err != nil {
		return false
	}
	for _, p := range DDRPublicResolvers {
		if netip.MustParseAddr(p) == a {
			return true
		}
	}
	return false
}

func mstr(m map[string]any, k string) string {
	if v, ok := m[k]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

// ResolverLine describes a run's system resolver from its manifest.
func ResolverLine(m map[string]any) string {
	ns := mstr(m, "resolver")
	if ns == "" {
		return "not recorded"
	}
	return fmt.Sprintf("%s (ddr %s, encrypted %s)", ns, orUnknown(mstr(m, "resolver_ddr")), orUnknown(mstr(m, "resolver_encrypted")))
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// ResolverWarning returns a warning when a run's system DNS was probably
// encrypted, so its DNS answers were not visible on the wire; "" otherwise.
func ResolverWarning(m map[string]any) string {
	var public []string
	for _, ns := range strings.Fields(mstr(m, "resolver")) {
		if isDDRPublic(ns) {
			public = append(public, ns)
		}
	}
	enc := mstr(m, "resolver_encrypted")
	switch {
	case len(public) > 0:
		return fmt.Sprintf("WARNING: system resolver %s is a DDR-upgraded public resolver: macOS encrypts DNS to it, "+
			"so DNS answers are not visible on the wire and correlation results for this run are not comparable",
			strings.Join(public, " "))
	case enc == "yes" || enc == "likely":
		return fmt.Sprintf("WARNING: system DNS was %s encrypted (resolver %s): DNS answers are not visible on the wire "+
			"and correlation results for this run are not comparable", map[string]string{"yes": "observed", "likely": "probably"}[enc], mstr(m, "resolver"))
	}
	return ""
}

// printResolvers writes the report header: each distinct system resolver with
// its run count, then one warning per affected resolver.
func printResolvers(w io.Writer, runs []RunSummary) {
	count := map[string]int{}
	warn := map[string]string{}
	for _, r := range runs {
		l := ResolverLine(r.Manifest)
		count[l]++
		if s := ResolverWarning(r.Manifest); s != "" {
			warn[l] = s
		}
	}
	lines := make([]string, 0, len(count))
	for l := range count {
		lines = append(lines, l)
	}
	sort.Strings(lines)
	fmt.Fprintln(w, "SYSTEM RESOLVER (from each run's manifest)")
	for _, l := range lines {
		fmt.Fprintf(w, "  %-70s %3d run(s)\n", l, count[l])
	}
	for _, l := range lines {
		if s := warn[l]; s != "" {
			fmt.Fprintf(w, "  %s (%d run(s))\n", s, count[l])
		}
	}
	fmt.Fprintln(w)
}
