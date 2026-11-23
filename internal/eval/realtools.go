package eval

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Real firewalls, scored like the modelled strategies.
//
// A real tool's log says, for a remote address and port and the executable
// that connected, which name the tool displayed. Joining that to our flows
// gives a strategy "real:<tool>" whose output is what the product actually
// showed, graded against the handshake name (field data) and against ground
// truth (challenge runs).
//
// Two input formats, chosen by the CSV header:
//
//   - Little Snitch 6, `sudo littlesnitch log-traffic -b <begin> -e <end>`
//     (https://help.obdev.at/littlesnitch6/cmd-log-traffic): columns date,
//     direction, uid, ipAddress, remoteHostname, protocol, port, connectCount,
//     ..., connectingExecutable, parentAppExecutable. Rows are per interval,
//     not per connection: date is the interval start.
//   - Common: time, executable, ip, port, protocol, name - for any other tool
//     (LuLu's log converted into it).
//
// A capture's logs sit next to it as <capture>.<tool>.csv and are picked up
// automatically.

// RealPrefix marks a strategy that is a real product's own output.
const RealPrefix = "real:"

type realRow struct {
	at    time.Time
	exe   string // executable path or name
	ip    netip.Addr
	port  uint16
	proto string // "tcp" | "udp" | ""
	name  string // the name the tool displayed; "" = address only
	conns int
}

// RealLog is one tool's log, indexed by remote address and port.
type RealLog struct {
	Tool string
	rows map[netip.AddrPort][]realRow
	// Window is how far around a flow's opening a row may be timestamped
	// and still describe it: Little Snitch rows cover intervals.
	Window time.Duration
}

// timeLayouts are tried in order, in local time unless the layout has a zone.
var timeLayouts = []string{time.RFC3339Nano, "2006-01-02 15:04:05.000000-0700", "2006-01-02 15:04:05-0700",
	"2006-01-02 15:04:05.000", "2006-01-02 15:04:05"}

func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range timeLayouts {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t, true
		}
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f > 1e9 {
		if f > 1e12 { // milliseconds
			return time.UnixMilli(int64(f)), true
		}
		return time.Unix(int64(f), 0), true
	}
	return time.Time{}, false
}

// LoadReal reads a real tool's CSV log.
func LoadReal(tool string, r io.Reader) (*RealLog, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	head, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("%s log: %w", tool, err)
	}
	col := map[string]int{}
	for i, h := range head {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	get := func(rec []string, names ...string) string {
		for _, n := range names {
			if i, ok := col[strings.ToLower(n)]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
		}
		return ""
	}
	_, isLS := col["remotehostname"]
	log := &RealLog{Tool: tool, rows: map[netip.AddrPort][]realRow{}, Window: 2 * time.Minute}
	if !isLS {
		log.Window = 30 * time.Second
	}
	if _, ok := col["ipaddress"]; !ok {
		if _, ok := col["ip"]; !ok {
			return nil, fmt.Errorf("%s log: no ipAddress/ip column in header %v", tool, head)
		}
	}
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s log: %w", tool, err)
		}
		if isLS && get(rec, "direction") == "in" {
			continue // we grade outgoing connections only
		}
		ip, err := netip.ParseAddr(get(rec, "ipAddress", "ip"))
		if err != nil {
			continue
		}
		port, _ := strconv.Atoi(get(rec, "port"))
		at, ok := parseTime(get(rec, "date", "time"))
		if !ok {
			continue
		}
		row := realRow{at: at, ip: ip.Unmap(), port: uint16(port), name: strings.TrimSuffix(strings.ToLower(get(rec, "remoteHostname", "name")), ".")}
		row.exe = get(rec, "connectingExecutable", "executable")
		if p := get(rec, "parentAppExecutable"); row.exe == "" {
			row.exe = p
		}
		switch get(rec, "protocol") {
		case "6", "tcp", "TCP":
			row.proto = "tcp"
		case "17", "udp", "UDP":
			row.proto = "udp"
		}
		row.conns, _ = strconv.Atoi(get(rec, "connectCount"))
		if net := netip.AddrPortFrom(row.ip, row.port); true {
			log.rows[net] = append(log.rows[net], row)
		}
	}
	for k := range log.rows {
		rs := log.rows[k]
		sort.Slice(rs, func(i, j int) bool { return rs[i].at.Before(rs[j].at) })
	}
	return log, nil
}

// exeMatches compares the tool's executable (a path, possibly of the app
// bundle) with pktap's process name, which is truncated to 15 characters.
func exeMatches(exe, comm string) bool {
	if exe == "" || comm == "" {
		return true // nothing to contradict the match
	}
	e := strings.ToLower(filepath.Base(exe))
	c := strings.ToLower(comm)
	if len(e) > len(c) {
		e = e[:len(c)]
	}
	if strings.HasPrefix(e, c) || strings.HasPrefix(c, e) {
		return true
	}
	// An app bundle path ("/Applications/Google Chrome.app/...") against a
	// helper's name ("Google Chrome He"): same application family.
	return strings.Contains(strings.ToLower(exe), strings.ToLower(strings.Fields(comm)[0]))
}

// Shown returns what the tool displayed for a flow, and whether a log row
// matched at all. Among matching rows the one nearest the flow's opening
// wins; rows naming different hosts at the same distance count as ambiguous.
func (l *RealLog) Shown(proto string, remote netip.AddrPort, comm string, opened time.Time) (Shown, bool, bool) {
	rows := l.rows[netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())]
	var best *realRow
	var bestD time.Duration
	ambiguous := false
	for i := range rows {
		r := &rows[i]
		if r.proto != "" && proto != "" && r.proto != proto {
			continue
		}
		d := opened.Sub(r.at)
		if d < 0 {
			d = -d
		}
		if d > l.Window || !exeMatches(r.exe, comm) {
			continue
		}
		switch {
		case best == nil || d < bestD:
			best, bestD, ambiguous = r, d, false
		case d == bestD && r.name != best.name:
			ambiguous = true
		}
	}
	if best == nil {
		return Shown{}, false, false
	}
	if best.name == "" {
		return Shown{}, true, ambiguous
	}
	return Shown{Name: best.name, Claim: "read"}, true, ambiguous
}

// loadRealLogs finds <capture>.<tool>.csv files next to a capture.
func loadRealLogs(pcap string) (map[string]*RealLog, error) {
	base := strings.TrimSuffix(strings.TrimSuffix(pcap, ".pcapng"), ".pcap")
	matches, _ := filepath.Glob(base + ".*.csv")
	out := map[string]*RealLog{}
	for _, m := range matches {
		tool := strings.TrimSuffix(strings.TrimPrefix(m, base+"."), ".csv")
		if tool == "" || strings.Contains(tool, ".") || tool == "visits" {
			continue
		}
		f, err := os.Open(m)
		if err != nil {
			return nil, err
		}
		l, err := LoadReal(tool, f)
		f.Close()
		if err != nil {
			return nil, err
		}
		out[tool] = l
	}
	return out, nil
}
