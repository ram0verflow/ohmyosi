// Package spoof changes the two identifiers a machine broadcasts about itself on
// a network: its MAC address and its hostname. Both are ordinary, documented
// root operations - ifconfig and scutil - and both are the kind of thing worth
// doing before joining an untrusted network, so the network's operator learns
// less about the device than it otherwise would.
//
// This is a deliberate, one-off action, not a background behaviour: nothing here
// runs unless the operator asks for it on the command line.
package spoof

import (
	"context"
	"crypto/rand"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// RandomMAC returns a random MAC with the locally-administered bit set and the
// multicast bit clear, which is the correct shape for a spoofed unicast address:
// locally-administered says "not a real vendor assignment", and a card will
// refuse a multicast address as its own.
func RandomMAC() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	b[0] = (b[0] | 0x02) & 0xfe // set locally-administered, clear multicast
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// SetMAC assigns mac to an interface. On Wi-Fi the card must be disassociated
// first or the change is rejected while a connection is up, so that is attempted
// and its failure ignored (it is harmless on wired interfaces).
func SetMAC(ctx context.Context, iface, mac string) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(cctx,
		"/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
		"-z").Run()
	if out, err := exec.CommandContext(cctx, "/sbin/ifconfig", iface, "ether", mac).CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig %s ether: %v: %s", iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CurrentMAC reads the interface's current hardware address, for reporting the
// before/after of a change.
func CurrentMAC(ctx context.Context, iface string) (string, error) {
	out, err := exec.CommandContext(ctx, "/sbin/ifconfig", iface).Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "ether "); ok {
			return strings.TrimSpace(after), nil
		}
	}
	return "", fmt.Errorf("no ether address on %s", iface)
}

// SetHostname sets all three names macOS keeps: the Unix hostname, the Bonjour
// LocalHostName, and the user-facing ComputerName. Setting only one leaves the
// device advertising the old name somewhere, which defeats the point.
func SetHostname(ctx context.Context, name string) error {
	local := sanitizeLocal(name)
	for _, kv := range [][2]string{{"HostName", name}, {"LocalHostName", local}, {"ComputerName", name}} {
		if out, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--set", kv[0], kv[1]).CombinedOutput(); err != nil {
			return fmt.Errorf("scutil --set %s: %v: %s", kv[0], err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// sanitizeLocal makes a Bonjour-safe LocalHostName: letters, digits and hyphens
// only, since that name becomes <name>.local on the wire.
func sanitizeLocal(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "Mac"
	}
	return out
}
