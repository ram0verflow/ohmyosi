// Package pktap reads packets from macOS's pktap pseudo-interface.
//
// pktap is Apple's packet tap: it prepends a metadata header to every captured
// packet carrying the PID and name of the process that sent or received it.
// That is the one thing libpcap alone cannot give you, and it is the reason
// ohmyosi can attribute traffic without a kernel extension.
//
// We deliberately shell out to /usr/sbin/tcpdump rather than linking libpcap.
// gopacket's pcap bindings need cgo, which turns a two-second build into a
// toolchain argument. tcpdump ships with macOS, already knows how to open
// pktap, and writing a pcap stream to stdout is a stable interface.
package pktap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
)

// Header field offsets within struct pktap_header (bsd/net/pktap.h).
// Everything is host byte order; every Mac we care about is little-endian.
//
//	0   pth_length              uint32
//	4   pth_type_next           uint32
//	8   pth_dlt                 uint32   DLT of the packet that follows
//	12  pth_ifname[24]          char
//	36  pth_flags               uint32
//	40  pth_protocol_family     uint32
//	44  pth_frame_pre_length    uint32
//	48  pth_frame_post_length   uint32
//	52  pth_pid                 int32
//	56  pth_comm[17]            char     (+3 pad)
//	76  pth_svc                 uint32
//	80  pth_iftype              uint16
//	82  pth_ifunit              uint16
//	84  pth_epid                int32
//	88  pth_ecomm[17]           char     (+3 pad)
//	108 pth_flowid              uint32
//	112 pth_ipproto             uint32
//	116 pth_tstamp              timeval32
//	124 pth_uuid[16]
//	140 pth_euuid[16]
//
// We never assume the total is 156: pth_length is authoritative and Apple has
// grown this struct before. Read what we understand, skip pth_length bytes.
const (
	offLength   = 0
	offTypeNext = 4
	offDLT      = 8
	offIfname   = 12
	offFlags    = 36
	offPID      = 52
	offComm     = 56
	offSvc      = 76
	offEPID     = 84
	offEComm    = 88
	offFlowID   = 108
	offIPProto  = 112

	minHeaderLen = 56  // through pth_pid; anything shorter is unusable
	maxHeaderLen = 512 // sanity bound so a corrupt length can't allocate wildly

	typePacket = 1 // PTH_TYPE_PACKET

	flagDirIn  = 0x0001 // PTH_FLAG_DIR_IN
	flagDirOut = 0x0002 // PTH_FLAG_DIR_OUT

	// LinkTypePktap is DLT_PKTAP. gopacket has no decoder for it, which is
	// fine, because we are the decoder.
	LinkTypePktap = 258
)

// Direction as reported by the kernel. Trust it, but the flow table also
// derives direction from the local address set, because these flags are absent
// on some interface types (utun, awdl) and wrong on a few others.
type Direction uint8

const (
	DirUnknown Direction = iota
	DirIn
	DirOut
)

// Packet is one captured frame plus the process the kernel attributes it to.
type Packet struct {
	Ts   time.Time
	PID  int32  // pth_pid, the process on the socket
	Comm string // truncated to 16 chars by the kernel; enrich resolves the real name
	// EPID/EComm are the "effective" process: set when one process opened the
	// socket on another's behalf. mDNSResponder doing DNS for Safari shows up
	// here, which is the thread we pull on to fix DNS attribution later.
	EPID    int32
	EComm   string
	Ifname  string
	Dir     Direction
	FlowID  uint32 // kernel flow id; stable per socket, useful as a tiebreak
	IPProto uint32
	DLT     uint32 // link type of Data
	WireLen int    // original length on the wire, before snaplen truncation
	Data    []byte // the actual frame, valid until the next Read
}

// CaptureStats are loss counters exported by the capture format. Drop counters
// are optional in pcapng and unavailable in classic pcap, so each value has a
// separate Known bit; zero without Known would falsely claim a perfect capture.
type CaptureStats struct {
	InterfaceDrops      uint64
	OSDrops             uint64
	InterfaceDropsKnown bool
	OSDropsKnown        bool
}

// packetReader is the shared shape of pcapgo's classic and pcapng readers.
type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// Source streams packets from a running tcpdump, or from a saved capture file.
type Source struct {
	cmd  *exec.Cmd // nil in file mode
	errW *lockedBuffer
	pr   *os.File
	f    *os.File

	ready   chan struct{} // closed once rdr/initErr are set
	rdr     packetReader
	initErr error

	ng         *ngReader // pcapng: our own reader, which keeps process options
	format     string    // "pcap" or "pcapng"
	staticLink uint32    // classic pcap: one link type for the whole file

	exited  chan struct{} // closed when tcpdump exits; never closed in file mode
	waitErr error
}

// lockedBuffer collects tcpdump's stderr, which is written from cmd's own
// goroutine while we read it from ours.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.TrimSpace(l.b.String())
}

var (
	// ErrNoProcessMetadata means the capture carries no pktap header, so
	// packets cannot be attributed to a process.
	ErrNoProcessMetadata = errors.New("capture has no pktap metadata (process attribution unavailable)")

	// ErrNoPacketsYet means the capture is running and healthy but has not yet
	// produced a readable stream. Not a failure - often just an idle interface.
	ErrNoPacketsYet = errors.New("no packets captured yet")
)

// pcapng section header block type. Byte-order independent, which is why it
// works as a format sniff before we know anything else about the stream.
const pcapngMagic = 0x0a0d0d0a

// Open starts tcpdump on iface (e.g. "pktap,all", "pktap,en0") applying an
// optional BPF filter. It must run as root; pktap is privileged.
//
// Open returns as soon as tcpdump starts, and does NOT wait for the capture to
// produce data - see WaitReady.
func Open(ctx context.Context, iface, filter string, snaplen int) (*Source, error) {
	args := []string{
		"-i", iface,
		"-w", "-", // capture stream to stdout
		"-U", // flush per packet rather than every 4KB
		"-n", // no name resolution inside tcpdump; we do our own
		"-s", fmt.Sprint(snaplen),
	}
	if filter != "" {
		args = append(args, filter)
	}
	cmd := exec.CommandContext(ctx, "/usr/sbin/tcpdump", args...)
	errW := &lockedBuffer{}
	cmd.Stderr = errW

	// We make the pipe ourselves rather than using cmd.StdoutPipe(). The docs
	// for StdoutPipe say plainly that Wait closes the pipe once the process
	// exits, so "it is incorrect to call Wait before all reads have completed"
	// - and we want a Wait running concurrently, to notice tcpdump dying while
	// we sit blocked on a read. Owning the pipe removes the race.
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = pw
	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, fmt.Errorf("start tcpdump: %w", err)
	}
	pw.Close() // the child holds the only write end, so we get a clean EOF

	s := &Source{cmd: cmd, errW: errW, pr: pr, ready: make(chan struct{}), exited: make(chan struct{})}
	go func() {
		s.waitErr = cmd.Wait()
		close(s.exited)
	}()
	go s.initReader(pr)
	return s, nil
}

// OpenFile reads a saved capture instead of live traffic. Invaluable for
// debugging: capture once with tcpdump, then replay it as many times as it
// takes, with no root and no moving target.
func OpenFile(path string) (*Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	s := &Source{
		errW: &lockedBuffer{}, f: f,
		ready:  make(chan struct{}),
		exited: make(chan struct{}), // never closed: nothing can exit in file mode
	}
	go s.initReader(f)
	return s, nil
}

// initReader sniffs the capture format and builds the matching reader.
//
// Apple's tcpdump picks the format for you, and the choice is not documented
// anywhere obvious: -i pktap,en0 writes classic pcap, while -i pktap,all writes
// pcapng, because several interfaces need several interface descriptions and
// classic pcap has room for exactly one. So we handle both.
//
// This also blocks, and how long depends on the format. pcapng flushes its
// section header immediately. Classic pcap holds its 24-byte header in tcpdump's
// stdio buffer until the first packet forces a flush, so on a silent interface
// nothing arrives at all. That is why this runs in a goroutine and never on the
// startup path.
func (s *Source) initReader(r io.Reader) {
	defer close(s.ready)
	br := bufio.NewReaderSize(r, 1<<20)
	magic, err := br.Peek(4)
	if err != nil {
		s.initErr = fmt.Errorf("reading capture magic: %w", err)
		return
	}
	if binary.LittleEndian.Uint32(magic) == pcapngMagic {
		// Our own reader rather than pcapgo's, because pcapgo discards packet
		// options and that is exactly where Apple puts the PID. See pcapng.go.
		ng, err := newNgReader(br)
		if err != nil {
			s.initErr = fmt.Errorf("pcapng: %w", err)
			return
		}
		s.ng, s.format = ng, "pcapng"
		return
	}
	rd, err := pcapgo.NewReader(br)
	if err != nil {
		s.initErr = fmt.Errorf("pcap: %w", err)
		return
	}
	s.rdr, s.format, s.staticLink = rd, "pcap", uint32(rd.LinkType())
}

// WaitReady reports whether the capture stream is readable yet. It returns:
//
//	nil               stream is readable
//	ErrNoPacketsYet   healthy, nothing readable within timeout - call again
//	anything else     tcpdump died or the stream is unusable
//
// Whether packets carry process metadata is not known until the first packet
// arrives, so that is reported separately, via Packet.PID.
func (s *Source) WaitReady(ctx context.Context, timeout time.Duration) error {
	select {
	case <-s.ready:
		if s.initErr != nil {
			return s.diag("opening capture stream", s.initErr)
		}
		return nil
	case <-s.exited:
		return s.diag("tcpdump exited", s.waitErr)
	case <-time.After(timeout):
		return ErrNoPacketsYet
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Format is "pcap" or "pcapng", valid once WaitReady has returned nil.
func (s *Source) Format() string {
	select {
	case <-s.ready:
		return s.format
	default:
		return ""
	}
}

// diag builds an error saying what we were doing, what Go reported, whether
// tcpdump is still alive, and what it printed. An earlier version showed only
// tcpdump's stderr, which on a healthy capture is just "listening on ..." - so
// every failure looked identical and told you nothing.
func (s *Source) diag(doing string, cause error) error {
	alive := "tcpdump still running"
	switch {
	case s.cmd == nil:
		alive = "file mode"
	default:
		select {
		case <-s.exited:
			alive = "tcpdump exited"
			if s.waitErr != nil {
				alive += ": " + s.waitErr.Error()
			} else {
				alive += " cleanly"
			}
		default:
		}
	}
	msg := fmt.Sprintf("%s: %v (%s)", doing, cause, alive)
	if out := s.errW.String(); out != "" {
		msg += "\n  tcpdump said: " + strings.ReplaceAll(out, "\n", "\n  ")
	}
	return errors.New(msg)
}

// Stderr returns whatever tcpdump has said so far. Most of it is informational
// ("listening on pktap,all, link-type PKTAP"), so only surface it with a real
// failure.
func (s *Source) Stderr() string { return s.errW.String() }

// CaptureStats returns the latest loss counters the stream has actually
// reported. A live tcpdump often writes these only at shutdown, while some
// pcapng producers emit them periodically.
func (s *Source) CaptureStats() CaptureStats {
	if s.ng == nil {
		return CaptureStats{}
	}
	return CaptureStats{
		InterfaceDrops:      s.ng.interfaceDrops.Load(),
		OSDrops:             s.ng.osDrops.Load(),
		InterfaceDropsKnown: s.ng.interfaceDropsKnown.Load(),
		OSDropsKnown:        s.ng.osDropsKnown.Load(),
	}
}

// Read returns the next packet, blocking until the stream is readable.
//
// A Packet with PID <= 0 carries no process attribution: either the capture is
// not pktap, or this particular packet arrived on an interface that is not.
// The returned Data aliases an internal buffer and is valid only until the next
// call.
func (s *Source) Read() (*Packet, error) {
	<-s.ready
	if s.initErr != nil {
		return nil, s.diag("opening capture stream", s.initErr)
	}
	// pcapng: process metadata rides in block options, already parsed for us.
	if s.ng != nil {
		np, err := s.ng.next()
		if err != nil {
			return nil, s.readErr(err)
		}
		return &Packet{
			Ts: np.Ts, PID: np.PID, Comm: np.Comm, EPID: np.EPID, EComm: np.EComm,
			Dir: np.Dir, DLT: np.LinkType, WireLen: np.WireLen, Data: np.Data,
		}, nil
	}

	// classic pcap: DLT_PKTAP means a metadata header in front of every frame.
	raw, ci, err := s.rdr.ReadPacketData()
	if err != nil {
		return nil, s.readErr(err)
	}
	if s.staticLink != LinkTypePktap {
		return &Packet{Ts: ci.Timestamp, DLT: s.staticLink, WireLen: ci.Length, Data: raw}, nil
	}
	p, err := parse(raw)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	p.Ts = ci.Timestamp
	// A classic DLT_PKTAP record's lengths include the metadata header, while
	// Packet.Data does not. Preserve the actual frame length so truncation can
	// be measured without labelling every pktap packet as truncated.
	headerLen := len(raw) - len(p.Data)
	p.WireLen = ci.Length - headerLen
	if p.WireLen < len(p.Data) {
		p.WireLen = len(p.Data)
	}
	return p, nil
}

func (s *Source) readErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		if s.cmd != nil {
			return s.diag("stream ended", err)
		}
		return io.EOF // file mode: a clean end of capture
	}
	return err
}

// Close stops tcpdump, or closes the capture file.
func (s *Source) Close() error {
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
		<-s.exited
	}
	if s.pr != nil {
		s.pr.Close()
	}
	if s.f != nil {
		s.f.Close()
	}
	return nil
}

var errShortHeader = errors.New("pktap: truncated header")

func parse(b []byte) (*Packet, error) {
	if len(b) < minHeaderLen {
		return nil, errShortHeader
	}
	le := binary.LittleEndian
	hlen := int(le.Uint32(b[offLength:]))
	if hlen < minHeaderLen || hlen > maxHeaderLen || hlen > len(b) {
		return nil, fmt.Errorf("pktap: implausible header length %d", hlen)
	}
	if le.Uint32(b[offTypeNext:]) != typePacket {
		// PTH_TYPE_NONE or a future chained record. There is no documented
		// pktap drop-record type; capture loss comes from pcapng statistics.
		return nil, nil
	}

	p := &Packet{
		DLT:  le.Uint32(b[offDLT:]),
		PID:  int32(le.Uint32(b[offPID:])),
		Data: b[hlen:],
	}
	// Every field past pth_pid is read defensively: hlen is the contract.
	if hlen >= offIfname+24 {
		p.Ifname = cstr(b[offIfname : offIfname+24])
	}
	if hlen >= offFlags+4 {
		switch f := le.Uint32(b[offFlags:]); {
		case f&flagDirOut != 0:
			p.Dir = DirOut
		case f&flagDirIn != 0:
			p.Dir = DirIn
		}
	}
	if hlen >= offComm+17 {
		p.Comm = cstr(b[offComm : offComm+17])
	}
	if hlen >= offEPID+4 {
		p.EPID = int32(le.Uint32(b[offEPID:]))
	}
	if hlen >= offEComm+17 {
		p.EComm = cstr(b[offEComm : offEComm+17])
	}
	if hlen >= offFlowID+4 {
		p.FlowID = le.Uint32(b[offFlowID:])
	}
	if hlen >= offIPProto+4 {
		p.IPProto = le.Uint32(b[offIPProto:])
	}
	_ = offSvc
	return p, nil
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(bytes.TrimSpace(b))
}
