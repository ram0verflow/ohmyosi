// beacon-sim is a BENIGN network-shape generator for exercising ohmyosi's
// scoring engine. It is not malware and does nothing malicious: it opens plain
// TCP connections to a destination YOU name and moves bytes in a shape you
// choose - a steady beacon, a one-sided upload - so you can watch the detector
// react to the patterns real implants produce, against a host you control.
//
// It carries no exploit, no payload and no persistence. The only thing it
// imitates is the *traffic shape*, which is all the scorer ever looks at.
//
//	# in one terminal: the daemon
//	sudo ./ohmyosi
//
//	# in another: run a lab sink you own, then beacon at it by IP so there is
//	# no DNS and the flow reads as direct-IP, the way a hardcoded C2 address does
//	nc -l 4444 &                      # or any listener on a box you own
//	go run ./cmd/beacon-sim -target 192.0.2.10:4444 -every 10s -up 64KB
//
// To also trip the code-signature signal, build it and run the copy unsigned
// from a scratch location:
//
//	go build -o /tmp/beacon-sim ./cmd/beacon-sim && /tmp/beacon-sim -target ...
//
// Point it only at hosts you are authorised to send traffic to.
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	target := flag.String("target", "", "host:port to beacon at - use an IP for the direct-IP shape (required; a host you own)")
	every := flag.Duration("every", 10*time.Second, "beacon interval - the cadence the scorer measures regularity from")
	jitter := flag.Duration("jitter", 0, "random +/- added to each interval; keep it small to stay 'regular'")
	up := flag.String("up", "16KB", "bytes to send per beat, e.g. 64KB, 5MB - large and one-sided reads as exfil")
	down := flag.String("down", "1KB", "bytes to expect back per beat")
	count := flag.Int("count", 0, "number of beats, or 0 to run until interrupted")
	yes := flag.Bool("i-own-this-target", false, "acknowledge you are authorised to send traffic to -target")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "beacon-sim: -target host:port is required (a host you control).")
		fmt.Fprintln(os.Stderr, "example: nc -l 4444 &  then  beacon-sim -target 127.0.0.1:4444 -i-own-this-target")
		os.Exit(2)
	}
	if !*yes {
		fmt.Fprintln(os.Stderr, "beacon-sim: refusing to run without -i-own-this-target.")
		fmt.Fprintln(os.Stderr, "this tool sends real traffic; only point it at a host you are authorised to reach.")
		os.Exit(2)
	}
	upN, err := parseSize(*up)
	if err != nil {
		fmt.Fprintf(os.Stderr, "beacon-sim: bad -up: %v\n", err)
		os.Exit(2)
	}
	downN, err := parseSize(*down)
	if err != nil {
		fmt.Fprintf(os.Stderr, "beacon-sim: bad -down: %v\n", err)
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	isIP := net.ParseIP(strings.Split(*target, ":")[0]) != nil ||
		strings.Count(*target, ":") > 1 // bracketless IPv6
	shape := "named host"
	if isIP {
		shape = "direct-IP (no DNS)"
	}
	logf("beaconing %s every %s, up=%s down=%s [%s]", *target, *every, human(upN), human(downN), shape)
	if !isIP {
		logf("note: -target is a hostname, so a DNS lookup happens first; use a raw IP for the direct-IP shape")
	}

	payload := make([]byte, upN)
	rand.Read(payload)
	buf := make([]byte, 32<<10)

	beat := 0
	for {
		start := time.Now()
		if err := oneBeat(ctx, *target, payload, downN, buf); err != nil {
			logf("beat %d: %v", beat+1, err)
		} else {
			logf("beat %d: sent %s, read up to %s", beat+1, human(upN), human(downN))
		}
		beat++
		if *count > 0 && beat >= *count {
			logf("done after %d beats", beat)
			return
		}
		wait := *every - time.Since(start)
		if *jitter > 0 {
			wait += time.Duration(rand.Int63n(int64(2**jitter))) - *jitter
		}
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			logf("stopped after %d beats", beat)
			return
		case <-time.After(wait):
		}
	}
}

// oneBeat opens a connection, writes the upload, reads what comes back and
// closes - one check-in. Opening a fresh connection each beat is deliberate:
// that is the pattern the beacon detector counts.
func oneBeat(ctx context.Context, target string, payload []byte, downWant int, buf []byte) error {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	read := 0
	for read < downWant {
		n, err := conn.Read(buf)
		read += n
		if err != nil {
			break // a sink that sends nothing back is fine; the upload is the point
		}
	}
	return nil
}

func parseSize(s string) (int, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	mult := 1
	switch {
	case strings.HasSuffix(s, "KB"):
		mult, s = 1<<10, strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "MB"):
		mult, s = 1<<20, strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n); err != nil {
		return 0, fmt.Errorf("not a size: %q", s)
	}
	return n * mult, nil
}

func human(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s beacon-sim: %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
}
