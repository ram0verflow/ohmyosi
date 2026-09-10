package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Recording a session, and playing one back.
//
// There is already a way to replay raw packets (`-read` on a pcapng), and it is
// the wrong thing to keep. A pcapng preserves bytes and throws away everything
// the daemon worked out about them: which process, which name, from which
// source, what the trail was, what it scored and why. Replaying one re-derives
// all of that from scratch and can easily reach different conclusions, because
// the allocation table, the RDAP cache and the DNS the machine had at the time
// are all gone.
//
// So a recording here is the envelope stream itself - the daemon's own
// conclusions, in order, with their timestamps. What you play back is exactly
// what you saw, which is the only thing that makes a recording worth keeping as
// evidence rather than as a curiosity.
//
// The format is NDJSON: one envelope per line. Greppable, diffable, and
// readable by anything, which matters more than compactness for a file whose
// whole purpose is to be examined later.
type Recorder struct {
	mu   sync.Mutex
	f    *os.File
	w    *bufio.Writer
	enc  *json.Encoder
	n    int
	path string
}

// NewRecorder opens path for writing. The header line records when and by what,
// so a file found later can explain itself.
func NewRecorder(path, version, hostname, iface string) (*Recorder, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	r := &Recorder{f: f, w: bufio.NewWriterSize(f, 1<<16), path: path}
	r.enc = json.NewEncoder(r.w)
	head := map[string]any{
		"type": "recording", "version": version, "hostname": hostname,
		"iface": iface, "started": time.Now().Format(time.RFC3339),
	}
	if err := r.enc.Encode(head); err != nil {
		f.Close()
		return nil, err
	}
	return r, nil
}

// Write appends one envelope.
func (r *Recorder) Write(e Envelope) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.enc.Encode(e) == nil {
		r.n++
	}
	// Flushed every tick rather than at close: a recording is most wanted
	// exactly when the thing recording it did not exit cleanly.
	r.w.Flush()
}

func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.w.Flush()
	return r.f.Close()
}

func (r *Recorder) Summary() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return fmt.Sprintf("%d ticks to %s", r.n, r.path)
}

// Play reads a recording back, calling emit for each envelope.
//
// Timing is reproduced from the envelopes' own timestamps, capped so a long
// idle gap does not make playback stall for minutes. Passing speed > 1 runs it
// faster; 0 emits everything immediately, which is what a script wants.
func Play(path string, speed float64, emit func(Envelope)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	var prev float64
	first := true
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Envelope
		if json.Unmarshal(line, &e) != nil {
			continue // the header line, or a truncated final write
		}
		if e.Type != "hello" && e.Type != "tick" {
			continue
		}
		if speed > 0 && !first && e.T > prev {
			d := time.Duration((e.T - prev) / speed * float64(time.Second))
			if d > 2*time.Second {
				d = 2 * time.Second
			}
			time.Sleep(d)
		}
		prev, first = e.T, false
		emit(e)
	}
	return sc.Err()
}
