package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// newControlToken writes a short-lived bearer secret in a root-only directory.
// The native app asks the operator to paste it; it is never passed in a URL or
// printed to the daemon log. A new daemon run gets a new capability.
func newControlToken(dir string) (secret, path string, err error) {
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", "", fmt.Errorf("control directory must be private to its owner: %s", dir)
	}
	var bytes [32]byte
	if _, err = rand.Read(bytes[:]); err != nil {
		return "", "", err
	}
	f, err := os.CreateTemp(dir, "control-*.token")
	if err != nil {
		return "", "", err
	}
	path = f.Name()
	secret = hex.EncodeToString(bytes[:])
	if _, err = f.WriteString(secret + "\n"); err != nil {
		f.Close()
		os.Remove(path)
		return "", "", err
	}
	if err = f.Close(); err != nil {
		os.Remove(path)
		return "", "", err
	}
	return secret, filepath.Clean(path), nil
}
