package api

import (
	"fmt"
	"net/netip"

	"ohmyosi/internal/enrich"
)

// InvestigateCtx bundles every source that can say something about an address.
type InvestigateCtx struct {
	Names  *enrich.Names
	Ranges *enrich.Ranges
	Owners *enrich.Owners
	Icons  *enrich.Favicons
	ASN    *enrich.ASN
}

// Investigate assembles everything known about the far end, and records how
// each fact was learned.
//
// The trail is the point. Any of these facts on its own can mislead - a
// reverse-DNS name belongs to the hoster, an allocation says who owns the
// hardware and not who you are talking to - and a UI that merges them into one
// confident label is lying by simplification. Showing the steps lets a person
// see which layer a name came from and discount it accordingly.
func Investigate(ip netip.Addr, port uint16, sni, httpHost string, c InvestigateCtx) Endpoint {
	e := Endpoint{IP: ip.String(), Port: port, AgeDays: -1}
	var trail []string

	// 1. What the client asked for. The only source that speaks to intent.
	switch {
	case sni != "":
		e.Host, e.HostSrc = sni, string(enrich.SrcSNI)
		trail = append(trail, fmt.Sprintf("resolved to %s (sni)", sni))
	case httpHost != "":
		e.Host, e.HostSrc = httpHost, string(enrich.SrcHTTP)
		trail = append(trail, fmt.Sprintf("resolved to %s (http host)", httpHost))
	default:
		if c.Names != nil {
			result := c.Names.LookupResult(ip)
			if result.Name != "" {
				e.Host, e.HostSrc = result.Name, string(result.Source)
				trail = append(trail, fmt.Sprintf("resolved to %s (%s)", result.Name, result.Source))
			} else if result.Ambiguous {
				e.NameGap = "dns_ambiguous"
				e.NameCandidates = result.Candidates
				trail = append(trail, fmt.Sprintf("DNS observed %d names for this shared address; no tenant selected", len(result.Candidates)))
			}
		}
	}
	if e.Host == "" && e.NameGap == "" {
		trail = append(trail, "no name observed on the wire - address only")
	}

	// 2. Whose address space this is, from lists the operators publish
	//    themselves. Offline, and authoritative about hosting, not identity.
	if c.Ranges != nil {
		if p, ok := c.Ranges.Lookup(ip); ok {
			e.Org, e.OrgDetail, e.OrgSrc = p.Org, p.Detail, p.Src
			if p.Detail != "" {
				trail = append(trail, fmt.Sprintf("address is in %s, published by %s as %s", p.P, p.Org, p.Detail))
			} else {
				trail = append(trail, fmt.Sprintf("address is in %s, published by %s", p.P, p.Org))
			}
		}
	}

	// 3. The autonomous system, for everything the published lists miss.
	if c.ASN != nil {
		if info, ok := c.ASN.Lookup(ip); ok {
			e.ASN, e.ASNOrg, e.Country = info.Number, info.Org, info.Country
			if info.Org != "" {
				trail = append(trail, fmt.Sprintf("AS%d %s (cymru-dns)", info.Number, info.Org))
			} else {
				trail = append(trail, fmt.Sprintf("AS%d (cymru-dns)", info.Number))
			}
			if e.Org == "" && info.Org != "" {
				e.Org, e.OrgSrc = info.Org, "asn"
			}
		}
	}

	// 4. Who registered the name, and when. Only for names the machine itself
	//    stated - looking up who owns ec2-...compute.amazonaws.com would just
	//    report Amazon a second time and tell you nothing about the tenant.
	stated := e.HostSrc == string(enrich.SrcSNI) || e.HostSrc == string(enrich.SrcDNS) ||
		e.HostSrc == string(enrich.SrcHTTP)
	if e.Host != "" && stated {
		e.Domain = enrich.Registrable(e.Host)
		if c.Owners != nil {
			if o := c.Owners.Lookup(e.Domain); o != nil {
				e.Owner, e.Registrar, e.AgeDays = o.Registrant, o.Registrar, o.AgeDays()
				switch {
				case o.Err != "":
					trail = append(trail, fmt.Sprintf("registry lookup for %s failed: %s", e.Domain, o.Err))
				case o.AgeDays() >= 0:
					trail = append(trail, fmt.Sprintf("%s registered %s, %d days ago",
						e.Domain, o.Created.Format("2006-01-02"), o.AgeDays()))
				}
			}
		}
		if c.Icons != nil {
			e.Favicon = c.Icons.Lookup(e.Domain)
		}
	}

	e.Trail = trail
	return e
}
