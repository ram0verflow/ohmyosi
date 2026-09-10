// Package rules is the decision layer: given what ohmyosi already knows about a
// flow - which app opened it, where it is going - it says allow or block.
//
// The point ohmyosi can make that a packet filter cannot is per-application
// control without a kernel extension or an Apple entitlement. pf knows addresses
// and ports; it does not know that this connection belongs to Spotify and that
// one to a shell in /tmp. ohmyosi does, from pktap. So the process-awareness
// lives here, and the enforcement layer (internal/enforce) turns a decision
// about an app into a rule about the one 5-tuple that app just opened.
//
// Precedence is allow-over-block: an explicit allow always wins, so a broad
// block ("this app talks to nothing") can be carved out by a narrow allow
// ("...except its update server"). With no matching rule the verdict is Allow -
// this is a monitor first, and silence must never mean deny.
package rules

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Action string

const (
	Allow Action = "allow"
	Block Action = "block"
)

type Scope string

const (
	// ScopeApp matches on the application or process name. This is the one a
	// packet filter cannot express on its own.
	ScopeApp Scope = "app"
	// ScopeDomain matches a registrable domain or any host under it, so
	// "doubleclick.net" also blocks "ad.g.doubleclick.net".
	ScopeDomain Scope = "domain"
	// ScopeDest matches a destination IP, optionally with :port.
	ScopeDest Scope = "dest"
	// ScopePort matches a remote port regardless of host.
	ScopePort Scope = "port"
)

// Rule is one decision a person has asked ohmyosi to make.
type Rule struct {
	ID      string `json:"id"`
	Scope   Scope  `json:"scope"`
	Match   string `json:"match"`
	Action  Action `json:"action"`
	Note    string `json:"note,omitempty"`
	Enabled bool   `json:"enabled"`
	Created int64  `json:"created"`
}

// Target is everything a rule can match against, assembled from a flow.
type Target struct {
	App    string // the application bundle name, when known
	Comm   string // the process name from the kernel
	Domain string // registrable domain of the destination
	Host   string // full hostname the client asked for
	IP     string
	Port   uint16
}

// Decision is the outcome for a flow, with the rule that produced it.
type Decision struct {
	Action Action
	Rule   *Rule // nil when no rule matched (the default-allow case)
}

// Blocked reports a decision that denies the flow.
func (d Decision) Blocked() bool { return d.Action == Block && d.Rule != nil }

// matches reports whether a rule applies to a target.
func (r Rule) matches(t Target) bool {
	if !r.Enabled {
		return false
	}
	m := strings.TrimSpace(strings.ToLower(r.Match))
	if m == "" {
		return false
	}
	switch r.Scope {
	case ScopeApp:
		return containsFold(t.App, m) || containsFold(t.Comm, m)
	case ScopeDomain:
		return domainMatch(strings.ToLower(t.Domain), m) || domainMatch(strings.ToLower(t.Host), m)
	case ScopeDest:
		return destMatch(m, t.IP, t.Port)
	case ScopePort:
		return strconv.Itoa(int(t.Port)) == m
	}
	return false
}

// destMatch matches a "dest" pattern against an IP and port. The pattern is
// either a bare address (v4 or v6, brackets optional) or address:port. IPv6 is
// the reason this is not a simple split on ':': the address is full of them, so
// a bare v6 address must be recognised as an address, not a host:port.
func destMatch(pattern, ip string, port uint16) bool {
	if bare := strings.Trim(pattern, "[]"); netipValid(bare) {
		return bare == ip
	}
	if host, ps, err := net.SplitHostPort(pattern); err == nil {
		return strings.Trim(host, "[]") == ip && strconv.Itoa(int(port)) == ps
	}
	return false
}

func netipValid(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func containsFold(s, sub string) bool {
	return s != "" && strings.Contains(strings.ToLower(s), sub)
}

// domainMatch is true when name equals the pattern or is a subdomain of it, so
// a rule on "doubleclick.net" covers "ad.doubleclick.net" but not
// "notdoubleclick.net".
func domainMatch(name, pattern string) bool {
	if name == "" {
		return false
	}
	return name == pattern || strings.HasSuffix(name, "."+pattern)
}

// Set is the live, persisted collection of rules.
type Set struct {
	path string
	mu   sync.RWMutex
	list []Rule
	ver  int // bumped on every change, so enforcement can skip unchanged syncs
}

// Version reports a counter that changes whenever the rules do.
func (s *Set) Version() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ver
}

func New(path string) *Set { return &Set{path: path} }

// Load reads rules from disk. A missing file is not an error.
func (s *Set) Load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var list []Rule
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	s.mu.Lock()
	s.list = list
	s.mu.Unlock()
	return nil
}

// Decide returns the verdict for a target. Allow wins over block; with nothing
// matching, the flow is allowed and the rule is nil.
func (s *Set) Decide(t Target) Decision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var blockRule *Rule
	for i := range s.list {
		if !s.list[i].matches(t) {
			continue
		}
		if s.list[i].Action == Allow {
			r := s.list[i]
			return Decision{Action: Allow, Rule: &r}
		}
		if blockRule == nil {
			r := s.list[i]
			blockRule = &r
		}
	}
	if blockRule != nil {
		return Decision{Action: Block, Rule: blockRule}
	}
	return Decision{Action: Allow}
}

// List returns a copy of the current rules.
func (s *Set) List() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Rule(nil), s.list...)
}

// BlockedDomains returns the domains under enabled block rules, for the hosts
// backend, which can act on names before a connection is ever made.
func (s *Set) BlockedDomains() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, r := range s.list {
		if r.Enabled && r.Action == Block && r.Scope == ScopeDomain {
			out = append(out, strings.ToLower(strings.TrimSpace(r.Match)))
		}
	}
	return out
}

// Add inserts a rule, assigns it an ID and timestamp, and saves.
func (s *Set) Add(r Rule) (Rule, error) {
	s.mu.Lock()
	if r.ID == "" {
		r.ID = strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	if r.Created == 0 {
		r.Created = time.Now().Unix()
	}
	s.list = append(s.list, r)
	s.ver++
	s.mu.Unlock()
	return r, s.save()
}

// Remove deletes a rule by ID and saves. Reports whether anything was removed.
func (s *Set) Remove(id string) (bool, error) {
	s.mu.Lock()
	kept := s.list[:0]
	removed := false
	for _, r := range s.list {
		if r.ID == id {
			removed = true
			continue
		}
		kept = append(kept, r)
	}
	s.list = append([]Rule(nil), kept...)
	if removed {
		s.ver++
	}
	s.mu.Unlock()
	if !removed {
		return false, nil
	}
	return true, s.save()
}

// RemoveByNote deletes every rule tagged with a given note, for removing a
// whole imported category ("adult", "ads") in one go rather than thousands of
// individual deletes. Returns how many were removed.
func (s *Set) RemoveByNote(note string) (int, error) {
	note = strings.TrimSpace(note)
	if note == "" {
		return 0, nil
	}
	s.mu.Lock()
	kept := s.list[:0]
	removed := 0
	for _, r := range s.list {
		if r.Note == note {
			removed++
			continue
		}
		kept = append(kept, r)
	}
	s.list = append([]Rule(nil), kept...)
	if removed > 0 {
		s.ver++
	}
	s.mu.Unlock()
	if removed == 0 {
		return 0, nil
	}
	return removed, s.save()
}

// AddMany appends rules without per-rule saves, for bulk blocklist imports.
func (s *Set) AddMany(rs []Rule) error {
	now := time.Now()
	s.mu.Lock()
	for i := range rs {
		if rs[i].ID == "" {
			rs[i].ID = strconv.FormatInt(now.UnixNano()+int64(i), 36)
		}
		if rs[i].Created == 0 {
			rs[i].Created = now.Unix()
		}
		s.list = append(s.list, rs[i])
	}
	s.ver++
	s.mu.Unlock()
	return s.save()
}

func (s *Set) save() error {
	s.mu.RLock()
	b, err := json.MarshalIndent(s.list, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
