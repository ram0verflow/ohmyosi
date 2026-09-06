package enrich

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Favicons for destinations.
//
// Worth being explicit about the trade, because it is the one place where the
// tool's own behaviour cuts against its purpose: fetching a site's icon means
// connecting to that site. A monitor that quietly phones every host it observes
// is a monitor you have to reason about, and on a machine you are auditing that
// is a real cost. So this is off unless asked for, cached on disk forever,
// fetched once per domain, and it shows up in ohmyosi's own graph flagged as
// self-traffic like everything else it does.
//
// Icons are stored and served as fetched. Converting .ico to PNG would need an
// ICO decoder that is not in the standard library, and browsers render .ico in
// an <img> perfectly well, so there is nothing to gain.
type Favicons struct {
	mu      sync.RWMutex
	have    map[string]string // domain -> file name in the cache
	pending map[string]bool
	queue   chan string
	dir     string
	client  *http.Client

	Enabled bool
}

func NewFavicons(dir string, enabled bool) (*Favicons, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f := &Favicons{
		have:    make(map[string]string, 128),
		pending: make(map[string]bool, 32),
		queue:   make(chan string, 128),
		dir:     dir,
		Enabled: enabled,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Redirects are normal here (apex to www, http to https), but a
			// long chain is a sign we are being led somewhere.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 4 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
	f.loadCache()
	return f, nil
}

func (f *Favicons) Dir() string { return f.dir }

// loadCache adopts whatever previous runs already fetched.
func (f *Favicons) loadCache() {
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if name := e.Name(); !e.IsDir() {
			f.have[strings.TrimSuffix(name, filepath.Ext(name))] = name
		}
	}
}

func (f *Favicons) Run(ctx context.Context) {
	if !f.Enabled {
		return
	}
	go func() {
		// One at a time, spaced out. There is no hurry, and a burst of requests
		// to fifty domains at once is both rude and conspicuous.
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case d := <-f.queue:
				<-tick.C
				name := f.fetch(ctx, d)
				f.mu.Lock()
				if name != "" {
					f.have[key(d)] = name
				} else {
					// Remember the failure so we do not retry every tick;
					// a zero-byte marker file is enough.
					os.WriteFile(filepath.Join(f.dir, key(d)+".none"), nil, 0o644)
					f.have[key(d)] = key(d) + ".none"
				}
				delete(f.pending, d)
				f.mu.Unlock()
			}
		}
	}()
}

// Lookup returns the cached file name for a domain, queueing a fetch on first
// sight. An empty return means "nothing yet", which the UI renders as no icon.
func (f *Favicons) Lookup(domain string) string {
	if domain == "" {
		return ""
	}
	k := key(domain)
	f.mu.RLock()
	name, ok := f.have[k]
	pending := f.pending[domain]
	f.mu.RUnlock()

	if ok {
		if strings.HasSuffix(name, ".none") {
			return ""
		}
		return name
	}
	if !f.Enabled || pending {
		return ""
	}
	f.mu.Lock()
	f.pending[domain] = true
	f.mu.Unlock()
	select {
	case f.queue <- domain:
	default:
		f.mu.Lock()
		delete(f.pending, domain)
		f.mu.Unlock()
	}
	return ""
}

func key(domain string) string {
	sum := sha1.Sum([]byte(domain))
	return hex.EncodeToString(sum[:])[:16]
}

func (f *Favicons) fetch(ctx context.Context, domain string) string {
	for _, u := range []string{
		"https://" + domain + "/favicon.ico",
		"https://www." + domain + "/favicon.ico",
	} {
		if name := f.try(ctx, domain, u); name != "" {
			return name
		}
	}
	return ""
}

func (f *Favicons) try(ctx context.Context, domain, url string) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "ohmyosi/0.1")
	resp, err := f.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	ct := resp.Header.Get("Content-Type")
	ext := extFor(ct)
	if ext == "" {
		return "" // an HTML error page dressed as a 200, most likely
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil || len(body) == 0 {
		return ""
	}
	name := key(domain) + ext
	if os.WriteFile(filepath.Join(f.dir, name), body, 0o644) != nil {
		return ""
	}
	return name
}

func extFor(contentType string) string {
	switch {
	case strings.Contains(contentType, "png"):
		return ".png"
	case strings.Contains(contentType, "svg"):
		return ".svg"
	case strings.Contains(contentType, "jpeg"), strings.Contains(contentType, "jpg"):
		return ".jpg"
	case strings.Contains(contentType, "gif"):
		return ".gif"
	case strings.Contains(contentType, "icon"), strings.Contains(contentType, "ico"):
		return ".ico"
	}
	return ""
}
