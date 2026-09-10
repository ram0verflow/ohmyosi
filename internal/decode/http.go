package decode

import "strings"

// parseHTTPHost pulls the Host header out of a plaintext HTTP request.
//
// Cleartext HTTP is rarer every year, but where it survives the Host header
// states the destination exactly as precisely as a TLS SNI does - it is the
// client saying out loud where it means to go. Worth reading for the same
// reason.
//
// Only a payload that begins with a recognised method is examined, and only up
// to the end of the headers, so this cannot be tricked into lifting a hostname
// out of arbitrary binary data that happens to contain "Host:".
func parseHTTPHost(b []byte) string {
	if len(b) < 16 || len(b) > 1<<16 {
		return ""
	}
	if !startsWithMethod(b) {
		return ""
	}

	// Headers end at the first blank line; never read past it into a body.
	limit := len(b)
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			limit = i
			break
		}
	}

	lines := strings.Split(string(b[:limit]), "\r\n")
	for _, line := range lines {
		if len(line) <= 5 || !strings.EqualFold(line[:5], "host:") {
			continue
		}
		host := strings.TrimSpace(line[5:])
		if host == "" {
			return ""
		}
		// Strip a trailing :port, but not the colons inside a bracketed IPv6.
		if !strings.HasSuffix(host, "]") {
			if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
				host = host[:i]
			}
		}
		return strings.ToLower(host)
	}
	return ""
}

var httpMethods = []string{
	"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
}

func startsWithMethod(b []byte) bool {
	for _, m := range httpMethods {
		if len(b) >= len(m) && string(b[:len(m)]) == m {
			return true
		}
	}
	return false
}
