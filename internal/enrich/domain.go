package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Who owns the NAME, as opposed to who owns the wire.
//
// The allocation table in ranges.go says an address belongs to Amazon. That is
// true of Cursor's backend and equally true of anything anyone rents for forty
// dollars a month, so on its own it is not identity - it is landlord.
//
// Identity lives with the domain. Three things about it are worth knowing and
// all three are free:
//
//   - the registrable domain, so api2.cursor.sh and agentn.global.api5.cursor.sh
//     are visibly one thing;
//   - the registrant, from RDAP - often privacy-redacted, which is itself
//     information;
//   - when it was registered. This is the signal that actually separates a
//     company's backend from a rented box: a domain first registered nine years
//     ago and one registered last Tuesday are very different propositions, and
//     no amount of AWS makes them look alike.

// Registrable reduces a hostname to the unit someone actually registers:
// agentn.global.api5.cursor.sh -> cursor.sh, foo.bar.co.uk -> bar.co.uk.
// Uses the Public Suffix List, because guessing "last two labels" gets every
// multi-part TLD wrong.
func Registrable(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || strings.ContainsAny(host, ":/") {
		return ""
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return d
}

// Owner is what RDAP says about a domain.
type Owner struct {
	Domain     string    `json:"domain"`
	Registrar  string    `json:"registrar,omitempty"`
	Registrant string    `json:"registrant,omitempty"`
	Created    time.Time `json:"created,omitempty"`
	Fetched    time.Time `json:"fetched"`
	// Err records a lookup that failed, so it is visible as a failure rather
	// than indistinguishable from a domain nobody has looked up yet.
	Err string `json:"err,omitempty"`
}

// Age in days, or -1 when the registration date is unknown.
func (o *Owner) AgeDays() int {
	if o == nil || o.Created.IsZero() {
		return -1
	}
	return int(time.Since(o.Created).Hours() / 24)
}

// Owners resolves and caches domain ownership.
//
// This is the one component that talks to the network on purpose, so it is off
// unless asked for, cached to disk across runs, and rate-limited. Looking up a
// domain tells the RDAP operator you are interested in it.
type Owners struct {
	mu      sync.RWMutex
	m       map[string]*Owner
	pending map[string]bool
	queue   chan string
	path    string
	client  *http.Client

	Enabled bool
	TTL     time.Duration
}

func NewOwners(cachePath string, enabled bool) *Owners {
	return &Owners{
		m:       make(map[string]*Owner, 256),
		pending: make(map[string]bool, 32),
		queue:   make(chan string, 128),
		path:    cachePath,
		client:  &http.Client{Timeout: 15 * time.Second},
		Enabled: enabled,
		TTL:     14 * 24 * time.Hour,
	}
}

// Load reads the on-disk cache. Registration dates do not change, so a cache
// that survives restarts means most lookups never happen twice.
func (o *Owners) Load() error {
	b, err := os.ReadFile(o.path)
	if err != nil {
		return err
	}
	var list []*Owner
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, e := range list {
		o.m[e.Domain] = e
	}
	return nil
}

func (o *Owners) Save() error {
	o.mu.RLock()
	list := make([]*Owner, 0, len(o.m))
	for _, e := range o.m {
		list = append(list, e)
	}
	o.mu.RUnlock()
	if len(list) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(o.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(list, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(o.path, b, 0o644)
}

// Run starts the lookup workers. One at a time and spaced out: RDAP is a free
// service run by registries, and hammering it is both rude and a good way to
// get blocked.
func (o *Owners) Run(ctx context.Context) {
	if !o.Enabled {
		return
	}
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				o.Save()
				return
			case d := <-o.queue:
				<-tick.C
				owner := o.fetch(ctx, d)
				o.mu.Lock()
				o.m[d] = owner
				delete(o.pending, d)
				o.mu.Unlock()
			}
		}
	}()
}

// Lookup returns what is known, queueing a fetch on first sight. Returns nil
// until an answer exists; callers render the domain alone in the meantime.
func (o *Owners) Lookup(domain string) *Owner {
	if domain == "" {
		return nil
	}
	o.mu.RLock()
	e, ok := o.m[domain]
	pending := o.pending[domain]
	o.mu.RUnlock()

	if ok && (e.Err == "" || time.Since(e.Fetched) < o.TTL) {
		return e
	}
	if !o.Enabled || pending {
		return e
	}
	o.mu.Lock()
	o.pending[domain] = true
	o.mu.Unlock()
	select {
	case o.queue <- domain:
	default:
		o.mu.Lock()
		delete(o.pending, domain)
		o.mu.Unlock()
	}
	return e
}

// fetch asks RDAP. RDAP replaced whois precisely so that this could be one
// request returning structured JSON, instead of five registry-specific text
// formats each needing its own scraper.
func (o *Owners) fetch(ctx context.Context, domain string) *Owner {
	out := &Owner{Domain: domain, Fetched: time.Now()}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://rdap.org/domain/"+domain, nil)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "ohmyosi/0.1")
	resp, err := o.client.Do(req)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		out.Err = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return out
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		out.Err = err.Error()
		return out
	}
	parseRDAP(body, out)
	return out
}

type rdapDomain struct {
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []rdapEntity `json:"entities"`
}

type rdapEntity struct {
	Roles       []string        `json:"roles"`
	VCardArray  json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity `json:"entities"`
	Handle     string       `json:"handle"`
}

func parseRDAP(body []byte, out *Owner) {
	var d rdapDomain
	if err := json.Unmarshal(body, &d); err != nil {
		out.Err = "unparseable rdap: " + err.Error()
		return
	}
	for _, e := range d.Events {
		if strings.EqualFold(e.Action, "registration") {
			for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
				if t, err := time.Parse(layout, e.Date); err == nil {
					out.Created = t
					break
				}
			}
		}
	}
	for _, e := range d.Entities {
		name := vcardName(e.VCardArray)
		if name == "" {
			name = e.Handle
		}
		for _, r := range e.Roles {
			switch strings.ToLower(r) {
			case "registrar":
				if out.Registrar == "" {
					out.Registrar = name
				}
			case "registrant":
				if out.Registrant == "" {
					out.Registrant = name
				}
			}
		}
	}
}

// vcardName digs the organisation or full name out of jCard, whose shape is
// ["vcard", [["version",{},"text","4.0"], ["fn",{},"text","Example Inc"], ...]].
// Organisation wins: "Anysphere, Inc." beats a contact's personal name.
func vcardName(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var card []json.RawMessage
	if json.Unmarshal(raw, &card) != nil || len(card) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if json.Unmarshal(card[1], &props) != nil {
		return ""
	}
	var fn, org string
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var key string
		if json.Unmarshal(p[0], &key) != nil {
			continue
		}
		var val string
		if json.Unmarshal(p[3], &val) != nil {
			// "org" is sometimes an array of organisational units.
			var parts []string
			if json.Unmarshal(p[3], &parts) == nil && len(parts) > 0 {
				val = parts[0]
			}
		}
		switch strings.ToLower(key) {
		case "fn":
			fn = val
		case "org":
			org = val
		}
	}
	if org != "" {
		return org
	}
	return fn
}
