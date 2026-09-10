package enrich

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"ohmyosi/internal/decode"
	"ohmyosi/internal/flow"
)

// SeedTable populates the flow table with sockets that were already open when
// the daemon started.
//
// Without this, the first minute of a session is a lie by omission: a browser
// holding thirty established connections shows nothing until one of them
// happens to move a packet. Their handshakes are gone, so these arrive with no
// SNI and get marked pre-existing - which is the honest label for them.
func SeedTable(ctx context.Context, t *flow.Table) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// -F gives machine-readable output: one field per line, tagged by a
	// leading character. Far more reliable than parsing lsof's columns.
	cmd := exec.CommandContext(ctx, "/usr/sbin/lsof", "-i", "-n", "-P", "-FpcPn")
	out, err := cmd.Output()
	if err != nil {
		// lsof exits non-zero when some sockets are unreadable, which is normal.
		if len(out) == 0 {
			return 0, err
		}
	}

	var (
		pid   int32
		comm  string
		proto decode.Proto
		count int
	)
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) < 2 {
			continue
		}
		tag, val := line[0], line[1:]
		switch tag {
		case 'p':
			if n, err := strconv.Atoi(val); err == nil {
				pid = int32(n)
			}
		case 'c':
			comm = val
		case 'P':
			switch strings.ToUpper(val) {
			case "TCP":
				proto = decode.TCP
			case "UDP":
				proto = decode.UDP
			default:
				proto = decode.Other
			}
		case 'n':
			local, remote, ok := parseEndpoints(val)
			if !ok || pid <= 0 {
				continue
			}
			t.Seed(proto, local, remote, pid, comm, false)
			count++
		}
	}
	return count, nil
}

// parseEndpoints reads lsof's "local->remote" address field. Listening sockets
// have no remote half and are skipped: nothing is connected to them yet.
func parseEndpoints(s string) (netip.AddrPort, netip.AddrPort, bool) {
	i := strings.Index(s, "->")
	if i < 0 {
		return netip.AddrPort{}, netip.AddrPort{}, false
	}
	l, okL := parseAddrPort(s[:i])
	r, okR := parseAddrPort(s[i+2:])
	return l, r, okL && okR
}

func parseAddrPort(s string) (netip.AddrPort, bool) {
	s = strings.TrimSpace(s)
	// lsof writes IPv6 as [::1]:443 and IPv4 as 1.2.3.4:443.
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, true
	}
	// Bare IPv6 without brackets shows up occasionally.
	if i := strings.LastIndex(s, ":"); i > 0 {
		host, portStr := s[:i], s[i+1:]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return netip.AddrPort{}, false
		}
		addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(addr, uint16(port)), true
	}
	return netip.AddrPort{}, false
}

var _ = fmt.Sprintf
