package decode

import "testing"

func TestParseHTTPHost(t *testing.T) {
	raw := "GET /api HTTP/1.1\r\nHost: api.cursor.sh\r\nUser-Agent: test\r\n\r\n"
	if got := parseHTTPHost([]byte(raw)); got != "api.cursor.sh" {
		t.Fatalf("got %q", got)
	}
}

func TestParseHTTPHostRejectsTLS(t *testing.T) {
	raw := "\x16\x03\x01\x00\x05"
	if got := parseHTTPHost([]byte(raw)); got != "" {
		t.Fatalf("got %q", got)
	}
}
