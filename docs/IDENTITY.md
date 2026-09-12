# Knowing who the other end is

The goal is that every destination reads as an organization a person
recognizes, not an address. Getting there needs one idea kept straight:

**Whois and ASN data answer "whose machine is this", not "who am I talking
to".** For most modern traffic those are different companies. A connection to
`notion.so` terminates on Cloudflare hardware: whois says Cloudflare, and whois
is correct and useless. The name the client asked for is the identity; the ASN
is where it happens to be hosted. Show both, labelled, and never let the second
overwrite the first.

## Landlord is not tenant

Address ownership answers "whose hardware", and anyone can rent hardware. An
attacker's box and a real company's backend both report "Amazon ap-southeast-1",
so `org` can never be the identity field. What distinguishes them is the domain:
who registered it, and when. Registration age in particular is not something a
rented instance can fake.

So ownership is looked up against the **name**, not the address - and only for
names the machine actually stated, since a reverse-DNS name belongs to the
hoster and would just report the hoster again.

## The stack, in priority order

| Rank | Source | Answers | Cost |
|---|---|---|---|
| 1 | TLS SNI / HTTP Host | who this exact flow asked for | free, already parsed |
| 2 | Sniffed DNS response | who the app looked up | free, already parsed |
| 3 | Reverse DNS (PTR) | usually the hoster | one network round trip |
| 4 | ASN → organization | who owns the address space | offline database |
| 5 | Domain RDAP | who registered the name, and when | one network round trip |

All five are implemented. Ranks 1-2 and the allocation table are offline; rank 5
is behind `-rdap`.

SNI and HTTP Host are scoped to the connection that carried them. They are
never copied into the address cache: a CDN address can serve unrelated tenants,
so lending one flow's handshake name to another would turn strong evidence into
a confident false label. DNS and PTR remain explicitly lower-confidence,
address-level fallbacks. DNS entries retain their TTL and the cache preserves
all unexpired candidates. If more than one name is plausible for an address,
the product exposes the candidate set and abstains instead of letting the last
answer overwrite the others.

## Offline first

Any lookup that leaves the machine is a connection ohmyosi makes about traffic
you are watching, and it appears in its own graph. That is tolerable but it
should be a choice, so: resolve offline where possible, make network lookups
opt-in, cache them hard, and tag them `self` so they can be filtered.

**ASN database.** Ship or download one `.mmdb` and read it with
`github.com/oschwald/maxminddb-golang`. Two free options:

- **MaxMind GeoLite2 ASN** — free account required, permissive licence,
  updated weekly.
- **IPinfo Lite** — free, CC-BY, country + ASN, no account for the Lite tier.

This is the single highest-value addition. It turns every unnamed IPv6 address
in the current output into "Google", "Cloudflare", "Akamai" — which is most of
what is unlabelled right now.

**Public Suffix List** (`golang.org/x/net/publicsuffix`, already an indirect
dependency) to fold `agentn.global.api5.cursor.sh` and `api2.cursor.sh` into one
`cursor.sh` group. Without this the canvas shows six nodes for one service.

## Network lookups, when allowed

**RDAP, not whois.** RDAP is the modern replacement: structured JSON over
HTTPS, no per-registry text formats to parse, no rate-limit games.
`https://rdap.org/ip/1.1.1.1` redirects to the right registry. You get network
name, registrant organisation, country, allocation date and abuse contact.
Parsing classic whois output means writing five different scrapers.

**Team Cymru** for IP→ASN without a database file: a DNS TXT query to
`origin.asn.cymru.com`. Free, no key, but it is a network lookup per address
and it tells the operator what you are looking up.

**PeeringDB** for ASN → organisation detail and network type (is this a CDN, an
eyeball network, an enterprise). Free JSON API, good for a one-off enrichment
of the ASN table rather than per-connection.

## Shape of the result

```go
type Destination struct {
    Name    string // "notion.so"        - who you asked for
    NameSrc string // sni | dns | rdns
    Org     string // "Cloudflare, Inc." - who hosts it
    ASN     uint32 // 13335
    Country string // "US"
    Group   string // "cursor.sh" - registrable domain, for clustering
}
```

`Name` and `Org` are separate fields because they answer different questions.
The UI should lead with `Name` and show `Org` as the quieter second line. When
`Name` is empty — QUIC, ECH, a connection older than the daemon — `Org` is the
fallback, and it should look like a fallback.

## Clustering is the point

At 114 flows the table is already dense and a canvas would be unreadable.
Grouping by registrable domain and by organisation is what makes it legible:
forty Amazon endpoints become one node that expands. So this work is not
decoration on top of the visualisation, it is a prerequisite for it.

## On malware

ohmyosi does not detect malware and should not claim to. What it can honestly
do is make the unusual visible and let a person judge:

- **First sighting.** Keep a small on-disk history of process/destination pairs.
  A pair never seen before gets highlighted. This catches the interesting cases
  - a terminal process phoning somewhere new - without any threat intelligence
  and without any false-positive claims.
- **Unexpected shapes.** A background daemon with a long-lived outbound
  connection, or a process whose only destination has no name at all.

Both are presentation, not classification. The tool says "this is new"; the
person decides what it means.
