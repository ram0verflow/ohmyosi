package enrich

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Ranges maps an address to the organisation that owns the block containing it.
//
// This is the answer to "who is 2607:6bc0::10", which is most of what is
// unnamed in a live capture. Keep firmly in mind what it does and does not say:
// it identifies **who owns the address space**, not who you are talking to.
// Traffic to notion.so lands on Cloudflare hardware, and an org of "Cloudflare"
// is correct and useless on its own. The SNI is the identity; this is the
// infrastructure underneath it. Both get shown, never one instead of the other.
type Ranges struct {
	mu sync.RWMutex
	// Sorted by prefix length, descending, so the first match is the most
	// specific one. AWS publishes overlapping blocks and the narrow one carries
	// the useful detail.
	v4, v6  []Prefix
	updated time.Time
}

// Prefix is one published allocation.
type Prefix struct {
	P netip.Prefix `json:"p"`
	// Org is the operator's name, e.g. "Cloudflare", "Amazon", "Google".
	Org string `json:"org"`
	// Detail is whatever the source volunteered beyond the org - AWS names the
	// service and region, which turns "Amazon" into "Amazon S3 ap-southeast-1".
	Detail string `json:"detail,omitempty"`
	// Src records which published list this came from, because a claim about
	// who owns an address should say where it came from.
	Src string `json:"src,omitempty"`
}

type rangesFile struct {
	Updated  time.Time `json:"updated"`
	Prefixes []Prefix  `json:"prefixes"`
}

func NewRanges() *Ranges { return &Ranges{} }

// Load reads a ranges file written by Save. A missing file is not an error:
// ohmyosi works without one, just with more unnamed addresses.
func (r *Ranges) Load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f rangesFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	r.Set(f.Prefixes, f.Updated)
	return nil
}

func (r *Ranges) Set(ps []Prefix, updated time.Time) {
	var v4, v6 []Prefix
	for _, p := range ps {
		if !p.P.IsValid() {
			continue
		}
		if p.P.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	// Longest prefix first: the first match during lookup is then the most
	// specific, with no further comparison needed.
	sort.SliceStable(v4, func(i, j int) bool { return v4[i].P.Bits() > v4[j].P.Bits() })
	sort.SliceStable(v6, func(i, j int) bool { return v6[i].P.Bits() > v6[j].P.Bits() })

	r.mu.Lock()
	r.v4, r.v6, r.updated = v4, v6, updated
	r.mu.Unlock()
}

func (r *Ranges) Save(path string) error {
	r.mu.RLock()
	f := rangesFile{Updated: r.updated}
	f.Prefixes = append(append(f.Prefixes, r.v4...), r.v6...)
	r.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Lookup returns the most specific published block containing ip.
func (r *Ranges) Lookup(ip netip.Addr) (Prefix, bool) {
	ip = ip.Unmap()
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := r.v6
	if ip.Is4() {
		list = r.v4
	}
	for _, p := range list {
		if p.P.Contains(ip) {
			return p, true
		}
	}
	return Prefix{}, false
}

func (r *Ranges) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.v4) + len(r.v6)
}

func (r *Ranges) Updated() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.updated
}
