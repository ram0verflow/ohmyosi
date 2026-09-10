package score

import (
	"fmt"
	"testing"
)

// This is the detection benchmark: a table of realistic connection shapes, both
// malicious and ordinary, run through the scorer to check it separates them.
//
// It is deliberately shape-based. The scorer has no threat feed and no
// signatures, so what it can be held to is exactly this: does the collection of
// properties a beacon, an exfil channel or a fresh-domain callback exhibits add
// up to "worth a look", while a browser talking to Google does not. The numbers
// printed here are the honest measure of that, precision and recall included.

type scenario struct {
	name      string
	malicious bool // ground truth: is this something a person should see?
	in        Input
}

// rank orders bands so ">=" comparisons read naturally.
func rank(b string) int {
	switch b {
	case "loud":
		return 3
	case "unusual":
		return 2
	case "notable":
		return 1
	default:
		return 0
	}
}

func scenarios() []scenario {
	return []scenario{
		// --- shapes a person should be shown ---
		{"beacon: unsigned /tmp binary, direct-IP, odd port, regular cadence", true, Input{
			DirectIP: true, HasName: false, HasOrg: false, RemotePort: 4444,
			ExecPath: "/tmp/.update", Signing: "unsigned",
			BeaconRegularity: 0.96, BeaconSamples: 9, FirstContact: true,
			DomainAgeDays: -1, BytesUp: 4096, BytesDown: 512,
		}},
		{"C2 over 443: no DNS, ad-hoc signed, steady cadence", true, Input{
			DirectIP: true, HasName: false, HasOrg: true, RemotePort: 443,
			ExecPath: "/Users/x/Downloads/helper", Signing: "adhoc",
			BeaconRegularity: 0.90, BeaconSamples: 6, FirstContact: true,
			DomainAgeDays: -1, BytesUp: 2048, BytesDown: 1024,
		}},
		{"exfil: large one-sided upload to an unnamed host", true, Input{
			DirectIP: true, HasName: false, HasOrg: false, RemotePort: 8443,
			ExecPath: "/usr/local/bin/sync", Signing: "unknown",
			DomainAgeDays: -1, BytesUp: 200 << 20, BytesDown: 64 << 10,
		}},
		{"malware callback: unsigned download to a days-old domain, first contact", true, Input{
			DirectIP: false, HasName: true, HasOrg: true, RemotePort: 443,
			ExecPath: "/Users/x/Downloads/Installer", Signing: "unsigned",
			DomainAgeDays: 3, FirstContact: true, BytesUp: 8 << 10, BytesDown: 40 << 10,
		}},

		// --- ordinary traffic that must stay quiet ---
		{"browser to Google", false, Input{
			HasName: true, HasOrg: true, RemotePort: 443, Proto: "tcp",
			ExecPath: "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
			Signing:  "developer-id", DomainAgeDays: -1, BytesUp: 60 << 10, BytesDown: 4 << 20,
		}},
		{"iCloud backup: big upload, but to a named Apple service", false, Input{
			HasName: true, HasOrg: true, RemotePort: 443,
			ExecPath: "/System/Library/PrivateFrameworks/CloudKit", Signing: "apple",
			DomainAgeDays: -1, BytesUp: 500 << 20, BytesDown: 2 << 20,
		}},
		{"Slack websocket, long-lived and named", false, Input{
			HasName: true, HasOrg: true, RemotePort: 443,
			ExecPath: "/Applications/Slack.app/Contents/MacOS/Slack", Signing: "developer-id",
			DomainAgeDays: -1, BytesUp: 20 << 10, BytesDown: 30 << 10,
		}},
		{"homebrew fetching a release from a named host", false, Input{
			HasName: true, HasOrg: true, RemotePort: 443,
			ExecPath: "/opt/homebrew/bin/brew", Signing: "developer-id",
			DomainAgeDays: -1, BytesUp: 4 << 10, BytesDown: 80 << 20,
		}},
		{"NTP time sync", false, Input{
			HasName: true, HasOrg: true, RemotePort: 123, Proto: "udp",
			ExecPath: "/usr/libexec/timed", Signing: "apple", DomainAgeDays: -1,
		}},
		{"signed app to an unnamed address (push / QUIC / ECH)", false, Input{
			DirectIP: true, HasName: false, HasOrg: false, RemotePort: 443,
			ExecPath: "/Applications/Notes.app/Contents/MacOS/Notes",
			Signing:  "apple", DomainAgeDays: -1,
		}},
		{"signed CDN client, direct IP, no SNI", false, Input{
			DirectIP: true, HasName: false, HasOrg: true, RemotePort: 443,
			ExecPath: "/Applications/Spotify.app/Contents/MacOS/Spotify",
			Signing:  "developer-id", DomainAgeDays: -1, BytesUp: 40 << 10, BytesDown: 8 << 20,
		}},
	}
}

func TestDetectionBenchmark(t *testing.T) {
	// A scenario counts as "flagged" once it reaches unusual or above: that is
	// the threshold at which the tool interrupts, so it is the honest line to
	// measure detection against.
	const flagAt = 2 // unusual

	var tp, fp, tn, fn int
	t.Log("")
	t.Logf("  %-58s %5s  %-8s %s", "scenario", "score", "band", "verdict")
	t.Logf("  %s", "----------------------------------------------------------------------------------")
	for _, s := range scenarios() {
		r := Evaluate(s.in)
		flagged := rank(r.Band) >= flagAt
		verdict := "quiet"
		switch {
		case flagged && s.malicious:
			verdict, tp = "detected", tp+1
		case flagged && !s.malicious:
			verdict, fp = "FALSE ALARM", fp+1
		case !flagged && s.malicious:
			verdict, fn = "MISSED", fn+1
		default:
			verdict, tn = "ok (quiet)", tn+1
		}
		t.Logf("  %-58s %5d  %-8s %s", trunc(s.name, 58), r.Score, r.Band, verdict)
	}

	precision := ratio(tp, tp+fp)
	recall := ratio(tp, tp+fn)
	t.Log("")
	t.Logf("  detected %d/%d malicious shapes (recall %.0f%%), %d false alarms on %d benign (precision %.0f%%)",
		tp, tp+fn, recall*100, fp, tn+fp, precision*100)
	t.Log("")

	if fn > 0 {
		t.Errorf("scorer missed %d malicious shape(s) - they scored below 'unusual'", fn)
	}
	if fp > 0 {
		t.Errorf("scorer raised %d false alarm(s) on ordinary traffic", fp)
	}
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

var _ = fmt.Sprintf
