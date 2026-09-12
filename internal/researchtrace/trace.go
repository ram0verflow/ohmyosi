// Package researchtrace records the raw identity evidence needed to evaluate
// ohmyosi without treating the product's own label as ground truth.
package researchtrace

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ohmyosi/internal/decode"
	"ohmyosi/internal/flow"
)

type Event struct {
	Type string `json:"type"`
	At   int64  `json:"at"`

	IP   string `json:"ip,omitempty"`
	Name string `json:"name,omitempty"`
	TTL  uint32 `json:"ttl,omitempty"`

	FlowID      string `json:"flow_id,omitempty"`
	Proto       string `json:"proto,omitempty"`
	LocalIP     string `json:"local_ip,omitempty"`
	LocalPort   uint16 `json:"local_port,omitempty"`
	RemoteIP    string `json:"remote_ip,omitempty"`
	RemotePort  uint16 `json:"remote_port,omitempty"`
	SNI         string `json:"sni,omitempty"`
	HTTPHost    string `json:"http_host,omitempty"`
	PreExisting bool   `json:"pre_existing,omitempty"`
	WireLen     int    `json:"wire_len,omitempty"`
	CaptureLen  int    `json:"capture_len,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

type flowSignature struct {
	sni, httpHost string
	preExisting   bool
	truncated     bool
}

type Recorder struct {
	mu   sync.Mutex
	f    *os.File
	w    *bufio.Writer
	enc  *json.Encoder
	seen map[string]flowSignature
	n    int
}

func NewRecorder(path, version, hostname, iface string) (*Recorder, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	r := &Recorder{f: f, w: bufio.NewWriterSize(f, 1<<16), seen: make(map[string]flowSignature)}
	r.enc = json.NewEncoder(r.w)
	if err := r.enc.Encode(map[string]any{
		"type": "research-trace", "version": version, "hostname": hostname,
		"iface": iface, "started": time.Now().Format(time.RFC3339),
	}); err != nil {
		f.Close()
		return nil, err
	}
	return r, nil
}

func (r *Recorder) DNS(record decode.DNSRecord, at time.Time) {
	if r == nil {
		return
	}
	r.write(Event{Type: "dns", At: at.Unix(), IP: record.IP.String(), Name: record.Name, TTL: record.TTL})
}

// Flow writes the first sighting and any later change to identity evidence.
// The exporter collapses these updates to the strongest final observation.
func (r *Recorder) Flow(f flow.Flow) {
	if r == nil {
		return
	}
	sig := flowSignature{sni: f.SNI, httpHost: f.HTTPHost, preExisting: f.PreExisting, truncated: f.Truncated}
	r.mu.Lock()
	defer r.mu.Unlock()
	if prior, ok := r.seen[f.ID]; ok && prior == sig {
		return
	}
	r.seen[f.ID] = sig
	r.encode(Event{
		Type: "flow", At: f.LastSeen.Unix(), FlowID: f.ID, Proto: string(f.Proto),
		LocalIP: f.Local.Addr().String(), LocalPort: f.Local.Port(),
		RemoteIP: f.Remote.Addr().String(), RemotePort: f.Remote.Port(),
		SNI: f.SNI, HTTPHost: f.HTTPHost, PreExisting: f.PreExisting,
		WireLen: f.LastWireLen, CaptureLen: f.LastCaptureLen, Truncated: f.Truncated,
	})
}

func (r *Recorder) write(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.encode(e)
}

func (r *Recorder) encode(e Event) {
	if r.enc.Encode(e) == nil {
		r.n++
	}
	// Evidence is most valuable after a crash, so flush every event.
	r.w.Flush()
}

func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.w.Flush(); err != nil {
		r.f.Close()
		return err
	}
	return r.f.Close()
}

func (r *Recorder) Summary() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return fmt.Sprintf("%d evidence events", r.n)
}
