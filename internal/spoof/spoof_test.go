package spoof

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var macRE = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)

func TestRandomMAC(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		mac := RandomMAC()
		if !macRE.MatchString(mac) {
			t.Fatalf("malformed MAC: %q", mac)
		}
		first, err := strconv.ParseUint(strings.SplitN(mac, ":", 2)[0], 16, 8)
		if err != nil {
			t.Fatal(err)
		}
		if first&0x02 == 0 {
			t.Errorf("%q: locally-administered bit not set", mac)
		}
		if first&0x01 != 0 {
			t.Errorf("%q: multicast bit set - a card will reject this as its own address", mac)
		}
		seen[mac] = true
	}
	if len(seen) < 190 {
		t.Errorf("MACs not random enough: %d unique of 200", len(seen))
	}
}

func TestSanitizeLocal(t *testing.T) {
	cases := map[string]string{
		"My Laptop":     "My-Laptop",
		"café_box":      "caf-box",
		"---":           "Mac",
		"":              "Mac",
		"valid-name-99": "valid-name-99",
	}
	for in, want := range cases {
		if got := sanitizeLocal(in); got != want {
			t.Errorf("sanitizeLocal(%q) = %q, want %q", in, got, want)
		}
	}
}
