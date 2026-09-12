package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlTokenIsRandomAndPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	a, path, err := newControlToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, other, err := newControlToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a == b || len(a) != 64 || path == other {
		t.Fatal("control tokens must be unique 256-bit values")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode: %o", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(data)) != a {
		t.Fatal("token file contents differ")
	}
	private, err := os.Stat(dir)
	if err != nil || private.Mode().Perm() != 0o700 {
		t.Fatalf("control directory must be private: %v, %v", private, err)
	}
}

func TestControlTokenRejectsPublicDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := newControlToken(dir); err == nil {
		t.Fatal("control token written into a publicly accessible directory")
	}
}
