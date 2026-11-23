package eval

import (
	"net/netip"
	"time"

	"ohmyosi/internal/enrich"
	"ohmyosi/internal/naming"
)

// Little Snitch on macOS, as its documentation describes it
// (https://help.obdev.at/littlesnitch6/adv-server-names and the FAQ at
// https://www.obdev.at/support/littlesnitch):
//
//  1. A name handed down by Apple's Network Extension framework, when the app
//     connected by name. NOT observable in packets: we cannot see it, so every
//     flow it would have named is graded by the later steps. Our Little Snitch
//     numbers are therefore an upper bound on its error.
//  2. DNS sniffing - "If the process can know only one name for the address,
//     we are done, we have the name." The handshake is not consulted.
//  3. Otherwise read the server name the process sends (TLS SNI). By default
//     "Little Snitch uses the server name that a process sends only if it
//     matches a DNS lookup it has seen" (setting "Verify server names asserted
//     by process", on by default).
//  4. Otherwise, if the names the process knows for the address share a
//     domain, the domain; otherwise the address alone ("the hostname could
//     not be determined").

// LS steps, recorded per flow so a report can say which step named it.
const (
	LSStepDNS     = 2 // unique name this process resolved to the address
	LSStepSNI     = 3 // server name from the handshake, accepted
	LSStepDomain  = 4 // common domain of several resolved names
	LSStepAddress = 5 // nothing usable: the address is shown
)

// lsResult is what the modelled Little Snitch would display.
type lsResult struct {
	Step int
	Name string
	// Rejected: the handshake carried a name but step 3 refused it because no
	// DNS lookup had mapped that name to this address.
	Rejected bool
}

// littleSnitch models steps 2-4. sni is the name in this flow's own handshake
// as Little Snitch would read it (the ECH outer name included); verify is the
// default "Verify server names asserted by process" setting.
func littleSnitch(l *naming.Ledger, ip netip.Addr, at time.Time, app int32, sni string, verify bool) lsResult {
	known := l.NamesFor(ip, at, app)
	if len(known) == 1 {
		return lsResult{Step: LSStepDNS, Name: known[0]}
	}
	if sni != "" {
		if !verify || l.Resolved(ip, sni, at) {
			return lsResult{Step: LSStepSNI, Name: sni}
		}
	}
	res := lsResult{Step: LSStepAddress, Rejected: sni != ""}
	if len(known) > 1 {
		d := enrich.Registrable(known[0])
		same := d != ""
		for _, n := range known[1:] {
			if enrich.Registrable(n) != d {
				same = false
				break
			}
		}
		if same {
			res.Step, res.Name = LSStepDomain, d
		}
	}
	return res
}

// shownLS renders a Little Snitch result as a strategy output. A domain-level
// name is claimed as "domain", not as a read host name.
func shownLS(r lsResult) Shown {
	switch r.Step {
	case LSStepDomain:
		return Shown{Name: r.Name, Claim: "domain"}
	case LSStepAddress:
		return Shown{}
	}
	return Shown{Name: r.Name, Claim: "read"}
}
