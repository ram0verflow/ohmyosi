package eval

import (
	"testing"

	"ohmyosi/internal/naming"
)

// Re-keying after a relaunch: a unique name moves to its new PID; a name that
// maps to several processes now loses its asker; a process still running, or
// absent from the new capture, keeps its PID.
func TestRekey(t *testing.T) {
	prior := []naming.Answer{
		{Asker: 100, Comm: "firefox"},         // relaunched as 300
		{Asker: 110, Comm: "Google Chrome H"}, // two helpers now: ambiguous
		{Asker: 200, Comm: "Safari"},          // still running
		{Asker: 400, Comm: "backupd"},         // not in the new capture
	}
	procs := map[string]map[int32]bool{
		"firefox":         {300: true},
		"Google Chrome H": {120: true, 130: true},
		"Safari":          {200: true},
	}
	var st PriorStats
	rekey(prior, procs, &st)
	want := []int32{300, 0, 200, 400}
	for i, a := range prior {
		if a.Asker != want[i] {
			t.Errorf("%s: asker %d, want %d", a.Comm, a.Asker, want[i])
		}
	}
	if st.Remapped != 1 || st.Unknown != 1 {
		t.Errorf("stats %+v", st)
	}
}
