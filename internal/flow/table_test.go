package flow

import (
	"net/netip"
	"testing"
	"time"

	"ohmyosi/internal/decode"
	"ohmyosi/internal/pktap"
)

// testTable pins the local address set instead of reading real interfaces, so
// these tests mean the same thing on any machine.
func testTable(local ...string) *Table {
	t := NewTable(999)
	t.local = map[netip.Addr]bool{}
	for _, s := range local {
		t.local[netip.MustParseAddr(s)] = true
	}
	t.lastLocalScan = time.Now()
	return t
}

func obs(src string, sp uint16, dst string, dp uint16, n int, dir pktap.Direction) *decode.Obs {
	return &decode.Obs{
		Ts: time.Now(), PID: 42, Comm: "curl", Proto: decode.TCP,
		Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst),
		SPort: sp, DPort: dp, WireLen: n, Dir: dir,
	}
}

// Both directions of one conversation must collapse into a single flow with
// separate up/down counters. Getting this wrong shows up as every connection
// appearing twice in the UI, which is the most obvious possible bug.
func TestOrientationCollapsesBothDirections(t *testing.T) {
	tb := testTable("192.168.1.5")
	tb.Observe(obs("192.168.1.5", 52341, "104.18.32.7", 443, 100, pktap.DirOut))
	tb.Observe(obs("104.18.32.7", 443, "192.168.1.5", 52341, 900, pktap.DirIn))

	all := tb.All()
	if len(all) != 1 {
		t.Fatalf("want 1 flow, got %d", len(all))
	}
	f := all[0]
	if f.Local.Port() != 52341 || f.Remote.Port() != 443 {
		t.Errorf("orientation wrong: local=%v remote=%v", f.Local, f.Remote)
	}
	if f.BytesUp != 100 || f.BytesDown != 900 {
		t.Errorf("counters: up=%d down=%d want 100/900", f.BytesUp, f.BytesDown)
	}
	if f.PktsUp != 1 || f.PktsDown != 1 {
		t.Errorf("packets: up=%d down=%d", f.PktsUp, f.PktsDown)
	}
}

// pktap stamps a PID on only one direction. A zero from the other side must not
// erase it, or half the flows lose their process.
func TestPIDNotClobberedByReturnTraffic(t *testing.T) {
	tb := testTable("192.168.1.5")
	tb.Observe(obs("192.168.1.5", 52341, "104.18.32.7", 443, 100, pktap.DirOut))
	back := obs("104.18.32.7", 443, "192.168.1.5", 52341, 900, pktap.DirIn)
	back.PID, back.Comm = 0, ""
	tb.Observe(back)

	if f := tb.All()[0]; f.PID != 42 || f.Comm != "curl" {
		t.Errorf("pid lost on return traffic: pid=%d comm=%q", f.PID, f.Comm)
	}
}

func TestApplicationNamesStayOnTheirOriginatingFlow(t *testing.T) {
	tb := testTable("192.168.1.5")
	sharedIP := "104.18.32.7"

	tls := obs("192.168.1.5", 51001, sharedIP, 443, 100, pktap.DirOut)
	tls.SNI = "alpha.example"
	tb.Observe(tls)

	http := obs("192.168.1.5", 51002, sharedIP, 80, 100, pktap.DirOut)
	http.HTTPHost = "beta.example"
	tb.Observe(http)

	unnamed := obs("192.168.1.5", 51003, sharedIP, 443, 100, pktap.DirOut)
	tb.Observe(unnamed)

	byPort := map[uint16]Flow{}
	for _, f := range tb.All() {
		byPort[f.Local.Port()] = f
	}
	if f := byPort[51001]; f.SNI != "alpha.example" || f.HTTPHost != "" {
		t.Fatalf("TLS evidence moved or changed: SNI=%q HTTP=%q", f.SNI, f.HTTPHost)
	}
	if f := byPort[51002]; f.SNI != "" || f.HTTPHost != "beta.example" {
		t.Fatalf("HTTP evidence moved or changed: SNI=%q HTTP=%q", f.SNI, f.HTTPHost)
	}
	if f := byPort[51003]; f.SNI != "" || f.HTTPHost != "" {
		t.Fatalf("unnamed shared-IP flow borrowed evidence: SNI=%q HTTP=%q", f.SNI, f.HTTPHost)
	}
}

func TestInboundApplicationNameDoesNotLabelRemoteClient(t *testing.T) {
	tb := testTable("192.168.1.5")
	in := obs("203.0.113.9", 51001, "192.168.1.5", 8080, 100, pktap.DirIn)
	in.HTTPHost = "local-service.example"
	in.SNI = "local-service.example"
	tb.Observe(in)

	f := tb.All()[0]
	if f.SNI != "" || f.HTTPHost != "" {
		t.Fatalf("inbound request mislabeled remote client: SNI=%q HTTP=%q", f.SNI, f.HTTPHost)
	}
}

// When neither endpoint is in the local set (VPN transit, loopback), fall back
// to the kernel's direction flag rather than guessing.
func TestOrientationFallsBackToKernelFlag(t *testing.T) {
	tb := testTable() // no local addresses at all
	tb.Observe(obs("10.8.0.2", 33333, "1.1.1.1", 53, 60, pktap.DirOut))
	f := tb.All()[0]
	if f.Local.Port() != 33333 {
		t.Errorf("want local port 33333, got %v", f.Local)
	}
	if f.BytesUp != 60 || f.BytesDown != 0 {
		t.Errorf("want 60 up, got up=%d down=%d", f.BytesUp, f.BytesDown)
	}
}

func TestSnapshotOnlyReturnsChanged(t *testing.T) {
	tb := testTable("192.168.1.5")
	tb.Observe(obs("192.168.1.5", 1234, "8.8.8.8", 443, 10, pktap.DirOut))
	if n := len(tb.Snapshot()); n != 1 {
		t.Fatalf("first snapshot: want 1, got %d", n)
	}
	if n := len(tb.Snapshot()); n != 0 {
		t.Fatalf("second snapshot with no traffic: want 0, got %d", n)
	}
	tb.Observe(obs("192.168.1.5", 1234, "8.8.8.8", 443, 10, pktap.DirOut))
	if n := len(tb.Snapshot()); n != 1 {
		t.Fatalf("after new traffic: want 1, got %d", n)
	}
}

func TestExpiry(t *testing.T) {
	tb := testTable("192.168.1.5")
	tb.IdleTimeout = 30 * time.Second
	tb.ClosedLinger = 5 * time.Second

	o := obs("192.168.1.5", 1234, "8.8.8.8", 443, 10, pktap.DirOut)
	tb.Observe(o)
	closed := obs("192.168.1.5", 5678, "8.8.4.4", 443, 10, pktap.DirOut)
	closed.FIN = true
	tb.Observe(closed)

	// 3s: inside both windows, nothing should go.
	if gone := tb.Expire(time.Now().Add(3 * time.Second)); len(gone) != 0 {
		t.Fatalf("premature expiry: %v", gone)
	}
	// 10s: past ClosedLinger (5s) but well inside IdleTimeout (30s), so only
	// the FIN'd flow retires.
	gone := tb.Expire(time.Now().Add(10 * time.Second))
	if len(gone) != 1 {
		t.Fatalf("want the closed flow expired, got %d", len(gone))
	}
	if n := len(tb.All()); n != 1 {
		t.Fatalf("want 1 flow left, got %d", n)
	}
	// 40s: the idle one goes too.
	if gone := tb.Expire(time.Now().Add(40 * time.Second)); len(gone) != 1 {
		t.Fatalf("want idle flow expired, got %d", len(gone))
	}
}

// Expiry must run on the capture clock. Replaying a file recorded an hour ago
// used to wipe every flow before it could be reported, because each LastSeen
// was already older than IdleTimeout relative to the wall clock.
func TestExpiryUsesCaptureClock(t *testing.T) {
	tb := testTable("192.168.1.5")
	tb.IdleTimeout = 30 * time.Second

	old := time.Now().Add(-2 * time.Hour)
	o := obs("192.168.1.5", 1234, "8.8.8.8", 443, 10, pktap.DirOut)
	o.Ts = old
	tb.Observe(o)

	if got := tb.Now(); !got.Equal(old) {
		t.Fatalf("capture clock: got %v want %v", got, old)
	}
	if gone := tb.Expire(tb.Now()); len(gone) != 0 {
		t.Fatalf("flow expired against its own capture clock: %v", gone)
	}
	if n := len(tb.All()); n != 1 {
		t.Fatalf("want the flow retained, got %d", n)
	}
	// Wall clock would have killed it instantly.
	if gone := tb.Expire(time.Now()); len(gone) != 1 {
		t.Fatalf("want expiry against wall clock, got %d", len(gone))
	}
}

func TestSelfTrafficMarked(t *testing.T) {
	tb := testTable("192.168.1.5")
	o := obs("192.168.1.5", 40000, "1.1.1.1", 53, 40, pktap.DirOut)
	o.PID = 999 // the daemon's own PID
	tb.Observe(o)
	if !tb.All()[0].Self {
		t.Error("ohmyosi's own reverse-DNS traffic should be marked Self")
	}
}
