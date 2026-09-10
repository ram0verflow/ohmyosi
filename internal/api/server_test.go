package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"ohmyosi/internal/rules"
)

func testServer(t *testing.T) *Server {
	rs := rules.New(filepath.Join(t.TempDir(), "rules.json"))
	if err := rs.Load(); err != nil {
		t.Fatal(err)
	}
	s := NewServer(func() Envelope { return Envelope{Type: "hello"} }, t.TempDir(), "")
	s.Rules = rs
	return s
}

func TestRulesAPICRUD(t *testing.T) {
	s := testServer(t)
	h := s.Handler()

	// Empty to start.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	if rec.Code != 200 {
		t.Fatalf("GET status %d", rec.Code)
	}
	var list []rules.Rule
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Fatalf("expected no rules, got %d", len(list))
	}

	// Add one. Enabled should default true even though the body omitted it.
	body := `{"scope":"app","match":"Spotify","action":"block"}`
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("POST status %d: %s", rec.Code, rec.Body)
	}
	var added rules.Rule
	json.Unmarshal(rec.Body.Bytes(), &added)
	if added.ID == "" || !added.Enabled {
		t.Fatalf("added rule not initialised: %+v", added)
	}

	// It now decides.
	if !s.Rules.Decide(rules.Target{App: "Spotify"}).Blocked() {
		t.Error("rule added over the API did not take effect")
	}

	// Delete it.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/rules?id="+added.ID, nil))
	if rec.Code != 200 {
		t.Fatalf("DELETE status %d", rec.Code)
	}
	var res map[string]bool
	json.Unmarshal(rec.Body.Bytes(), &res)
	if !res["removed"] {
		t.Error("delete did not report removal")
	}
	if len(s.Rules.List()) != 0 {
		t.Error("rule still present after delete")
	}
}

func TestActionEndpoints(t *testing.T) {
	var enforcing bool
	var imported, spoofed, hostnamed string
	s := NewServer(func() Envelope { return Envelope{} }, t.TempDir(), "")
	s.IsRoot = true
	s.Enforcing = func() bool { return enforcing }
	s.Enforce = func(on bool) error { enforcing = on; return nil }
	s.ImportBlock = func(src string) (int, error) { imported = src; return 7, nil }
	s.SpoofMAC = func(iface string) (string, error) { spoofed = iface; return "02:11:22:33:44:55", nil }
	s.SetHostname = func(name string) error { hostnamed = name; return nil }
	s.Interfaces = func() []string { return []string{"en0"} }
	h := s.Handler()

	call := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		var r *http.Request
		if body == "" {
			r = httptest.NewRequest(method, path, nil)
		} else {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
		}
		h.ServeHTTP(rec, r)
		return rec
	}

	// status reflects root + enforcement + interfaces
	rec := call(http.MethodGet, "/api/status", "")
	var st map[string]any
	json.Unmarshal(rec.Body.Bytes(), &st)
	if st["root"] != true || st["enforcing"] != false {
		t.Fatalf("status = %v", st)
	}

	// enforce flips state
	rec = call(http.MethodPost, "/api/enforce", `{"on":true}`)
	if !enforcing {
		t.Errorf("enforce did not turn on: %s", rec.Body)
	}

	// blocklist, spoof, hostname reach their hooks
	call(http.MethodPost, "/api/blocklist", `{"src":"adult"}`)
	if imported != "adult" {
		t.Errorf("blocklist src = %q", imported)
	}
	rec = call(http.MethodPost, "/api/spoof-mac", `{"iface":"en1"}`)
	if spoofed != "en1" || !strings.Contains(rec.Body.String(), "02:11:22:33:44:55") {
		t.Errorf("spoof = %q body %s", spoofed, rec.Body)
	}
	call(http.MethodPost, "/api/hostname", `{"name":"lab"}`)
	if hostnamed != "lab" {
		t.Errorf("hostname = %q", hostnamed)
	}
}

func TestActionEndpointsAbsentWithoutHooks(t *testing.T) {
	s := NewServer(func() Envelope { return Envelope{} }, t.TempDir(), "")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/enforce", strings.NewReader(`{"on":true}`)))
	if rec.Code != http.StatusNotFound {
		t.Errorf("enforce should be 404 without a hook, got %d", rec.Code)
	}
}

func TestRulesEndpointAbsentWithoutRules(t *testing.T) {
	// A daemon with no ruleset is observe-only; the endpoint must not exist.
	s := NewServer(func() Envelope { return Envelope{} }, t.TempDir(), "")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 without a ruleset, got %d", rec.Code)
	}
}
