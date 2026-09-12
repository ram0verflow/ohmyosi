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
	s.ControlToken = "test-control-secret"
	return s
}

func authorized(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "127.0.0.1:7777"
	r.Header.Set("Authorization", "Bearer test-control-secret")
	return r
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
	h.ServeHTTP(rec, authorized(http.MethodPost, "/api/rules", body))
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
	h.ServeHTTP(rec, authorized(http.MethodDelete, "/api/rules?id="+added.ID, ""))
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
	s.ControlToken = "test-control-secret"
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
		r.Host = "127.0.0.1:7777"
		r.Header.Set("Authorization", "Bearer test-control-secret")
		h.ServeHTTP(rec, r)
		return rec
	}

	// status reflects root + enforcement + interfaces
	rec := call(http.MethodGet, "/api/status", "")
	var st map[string]any
	json.Unmarshal(rec.Body.Bytes(), &st)
	if st["root"] != true || st["enforcing"] != false || st["control_authorized"] != true {
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

func TestMutationsRequireTokenAndLocalOrigin(t *testing.T) {
	s := testServer(t)
	called := 0
	s.Enforce = func(bool) error { called++; return nil }
	s.ImportBlock = func(string) (int, error) { called++; return 1, nil }
	s.SpoofMAC = func(string) (string, error) { called++; return "", nil }
	s.SetHostname = func(string) error { called++; return nil }
	h := s.Handler()
	tests := []struct{ method, path, body string }{
		{"POST", "/api/rules", `{"scope":"app","match":"test"}`},
		{"DELETE", "/api/rules?id=none", ""},
		{"POST", "/api/enforce", `{"on":true}`},
		{"POST", "/api/blocklist", `{"src":"adult"}`},
		{"POST", "/api/spoof-mac", `{"iface":"en0"}`},
		{"POST", "/api/hostname", `{"name":"lab"}`},
	}
	for _, tt := range tests {
		for _, bad := range []string{"", "Bearer wrong"} {
			r := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			r.Host = "127.0.0.1:7777"
			r.Header.Set("Authorization", bad)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s with %q: got %d", tt.method, tt.path, bad, w.Code)
			}
		}
	}
	if called != 0 || len(s.Rules.List()) != 0 {
		t.Fatalf("unauthorized mutation: hooks=%d rules=%d", called, len(s.Rules.List()))
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Host = "attacker.example:7777" },
		func(r *http.Request) { r.Header.Set("Origin", "http://attacker.example") },
	} {
		r := authorized("POST", "/api/enforce", `{"on":true}`)
		change(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || called != 0 {
			t.Fatalf("origin/host bypass: status=%d calls=%d", w.Code, called)
		}
	}
	for _, method := range []string{"GET", "OPTIONS", "DELETE"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, authorized(method, "/api/enforce", ""))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/enforce: got %d", method, w.Code)
		}
	}
	s.ControlToken = ""
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorized("POST", "/api/enforce", `{"on":true}`))
	if w.Code != http.StatusForbidden || called != 0 {
		t.Fatalf("empty token must disable controls: status=%d calls=%d", w.Code, called)
	}
}

func TestReadOnlyResponsesDoNotAllowCrossOrigin(t *testing.T) {
	s := testServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/snapshot", nil))
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("snapshot leaked cross-origin access")
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
