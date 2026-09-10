// Package history remembers which process/destination pairs this machine has
// been seen talking to before, so a pair never seen until now can be marked as
// new.
//
// This is the honest half of "on malware" in docs/IDENTITY.md: the tool keeps
// no threat feed and makes no claim about what a new pair means. It only
// answers "have I seen this before", and lets a person judge. A terminal
// phoning somewhere it never has is exactly the case this catches, with no
// signatures and no false-positive claims.
//
// The store is a plain JSON file - no database, no cgo, in keeping with the
// rest of the tool - written atomically so a crash mid-write cannot corrupt it.
package history

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// max caps the file so a long-lived machine cannot grow it without bound. Pairs
// are bounded by apps times destinations, which is small in practice; the cap
// is a backstop, and when hit the oldest entries are dropped.
const max = 100_000

// Store maps a pair key to when it was first seen, in unix seconds.
type Store struct {
	path string

	mu sync.Mutex
	// known is the set loaded from disk at startup: what was true before this
	// session. FirstContact is judged against this snapshot, so a genuinely new
	// pair reads as new for the whole session and as known from the next run.
	known map[string]int64
	// seen is known plus everything observed this session, and what gets saved.
	seen  map[string]int64
	dirty bool
}

// New returns a store backed by path. Call Load before use.
func New(path string) *Store {
	return &Store{path: path, known: map[string]int64{}, seen: map[string]int64{}}
}

// Load reads the file if present. A missing file is not an error: it just means
// nothing is known yet, and everything will read as first contact until saved.
func (s *Store) Load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	m := map[string]int64{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.known = m
	s.seen = make(map[string]int64, len(m)+64)
	for k, v := range m {
		s.seen[k] = v
	}
	return nil
}

// FirstContact reports whether key predates this session, and records it as
// seen. It returns true only for a pair that was not in the file at startup, so
// on a fresh install nothing is flagged until there is a history to be new
// against - which is the honest behaviour.
func (s *Store) FirstContact(key string) bool {
	if key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, wasKnown := s.known[key]
	if _, ok := s.seen[key]; !ok {
		s.seen[key] = time.Now().Unix()
		s.dirty = true
	}
	return !wasKnown
}

// Run saves periodically and once more on shutdown, so a new pair survives a
// restart without a save on every tick.
func (s *Store) Run(ctx context.Context, every time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = s.Save()
				return
			case <-t.C:
				_ = s.Save()
			}
		}
	}()
}

// Save writes the current set atomically. A no-op when nothing changed.
func (s *Store) Save() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	// Trim to the cap by dropping the oldest first sightings.
	if len(s.seen) > max {
		s.trimLocked()
	}
	b, err := json.Marshal(s.seen)
	s.dirty = false
	s.mu.Unlock()
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

// Len reports how many pairs are remembered.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// trimLocked drops the oldest entries down to the cap. Caller holds the lock.
func (s *Store) trimLocked() {
	type kv struct {
		k string
		t int64
	}
	all := make([]kv, 0, len(s.seen))
	for k, v := range s.seen {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t < all[j].t })
	for _, e := range all[:len(all)-max] {
		delete(s.seen, e.k)
	}
}
