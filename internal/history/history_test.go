package history

import (
	"path/filepath"
	"testing"
)

func TestFirstContactAcrossSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")

	// Session one: a fresh store knows nothing, so the first sighting of a pair
	// reads as new, and stays new for the rest of the session.
	s1 := New(path)
	if err := s1.Load(); err != nil {
		t.Fatal(err)
	}
	if !s1.FirstContact("curl→evil.example") {
		t.Error("unknown pair should be first contact")
	}
	if !s1.FirstContact("curl→evil.example") {
		t.Error("pair should stay first contact within the same session")
	}
	if err := s1.Save(); err != nil {
		t.Fatal(err)
	}

	// Session two: the pair is now known from disk, so it is no longer new -
	// while a different pair still is.
	s2 := New(path)
	if err := s2.Load(); err != nil {
		t.Fatal(err)
	}
	if s2.FirstContact("curl→evil.example") {
		t.Error("known pair should not be first contact after reload")
	}
	if !s2.FirstContact("curl→new.example") {
		t.Error("a genuinely new pair should still be first contact")
	}
}

func TestEmptyKeyIsNeverFirstContact(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "h.json"))
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	if s.FirstContact("") {
		t.Error("empty key should never be reported as first contact")
	}
}

func TestMissingFileLoadsClean(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err := s.Load(); err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if s.Len() != 0 {
		t.Errorf("empty store should have length 0, got %d", s.Len())
	}
}
