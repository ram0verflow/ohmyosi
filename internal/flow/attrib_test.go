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
}
