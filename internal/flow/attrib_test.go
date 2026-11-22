package flow

import "testing"

func TestDisplayPIDUsesEffectiveForResolver(t *testing.T) {
	f := Flow{PID: 42, Comm: "mDNSResponder", EPID: 999, EComm: "Cursor"}
	if f.DisplayPID() != 999 {
		t.Fatalf("pid: %d", f.DisplayPID())
	}
	if f.DisplayComm() != "Cursor" {
		t.Fatalf("comm: %q", f.DisplayComm())
	}
}

func TestDisplayPIDKeepsDirectApp(t *testing.T) {
	f := Flow{PID: 100, Comm: "Brave Browser H", EPID: 0}
	if f.DisplayPID() != 100 {
		t.Fatal()
	}
	// A helper acting for its app keeps its own name (WebKit for Safari).
	w := Flow{PID: 1590, Comm: "com.apple.WebKi", EPID: 672, EComm: "Safari"}
	if w.DisplayPID() != 1590 || w.DisplayComm() != "com.apple.WebKi" {
		t.Fatalf("helper: %d %q", w.DisplayPID(), w.DisplayComm())
	}
}

// pktap stamps some Chrome connections "proc 0" with Chrome only as the
// effective process; they belong to Chrome, not to nobody.
func TestDisplayPIDFallsBackToEffectiveWhenNoOwner(t *testing.T) {
	f := Flow{PID: 0, EPID: 67410, EComm: "Google Chrome He"}
	if f.DisplayPID() != 67410 || f.DisplayComm() != "Google Chrome He" {
		t.Fatalf("got %d %q", f.DisplayPID(), f.DisplayComm())
	}
}
