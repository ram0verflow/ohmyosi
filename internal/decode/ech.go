package decode

import "strings"

// Telling real Encrypted Client Hello from GREASE.
//
// A ClientHello carrying the encrypted_client_hello extension (0xfe0d) is not
// evidence that its SNI is a front. Chrome, Brave and Firefox send a GREASE
// ECH extension (RFC 9849 §6.2) on connections that are not using ECH at all,
// and then the SNI is the real destination. GREASE is built to look exactly
// like the real thing on the wire, so the only usable signal is the outer
// name: with real ECH it is the provider's public name, which is the same
// for every site behind that provider.
//
// So: ECH extension + SNI in ECHFronts -> the SNI is a front (ech-outer, not
// a valid reference). ECH extension + any other SNI -> "ECH offered", graded
// normally. A real-ECH front missing from this list would be graded as if its
// SNI were the destination; the list is printed with every report so that
// assumption is visible. Add a provider's public_name here when one is seen.

// ECHFronts lists the public outer names of deployed ECH providers.
var ECHFronts = []string{
	"cloudflare-ech.com", // Cloudflare, every ECH-enabled zone
}

// IsECHFront reports whether sni is a known ECH public name.
func IsECHFront(sni string) bool {
	sni = strings.TrimSuffix(strings.ToLower(sni), ".")
	for _, f := range ECHFronts {
		if sni == f {
			return true
		}
	}
	return false
}

// classifyECH splits "the hello carried 0xfe0d" into a front (outer) and an
// ordinary hello that merely offered ECH (offered, usually GREASE).
func classifyECH(sni string, ext bool) (outer, offered bool) {
	if !ext {
		return false, false
	}
	if IsECHFront(sni) {
		return true, false
	}
	return false, true
}
