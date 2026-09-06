package pktap

import (
	"encoding/binary"
	"testing"
)

// synthHeader builds a pktap_header the way the kernel lays it out, so we are
// testing our offsets against the struct definition rather than against
// ourselves.
func synthHeader(hlen int, pid int32, comm string, dlt uint32, flags uint32, payload []byte) []byte {
	b := make([]byte, hlen)
	le := binary.LittleEndian
	le.PutUint32(b[offLength:], uint32(hlen))
	le.PutUint32(b[offTypeNext:], typePacket)
	le.PutUint32(b[offDLT:], dlt)
	copy(b[offIfname:], "en0\x00")
	le.PutUint32(b[offFlags:], flags)
	le.PutUint32(b[offPID:], uint32(pid))
	// Only write fields the declared header length actually has room for --
	// a short header is a real case (see TestParseHeaderRejectsGarbage).
	if hlen >= offComm+17 {
		copy(b[offComm:], comm)
	}
	if hlen >= offEPID+4 {
		le.PutUint32(b[offEPID:], uint32(pid+1))
	}
	if hlen >= offEComm+17 {
		copy(b[offEComm:], "mDNSResponder")
	}
	if hlen >= offFlowID+4 {
		le.PutUint32(b[offFlowID:], 0xdeadbeef)
	}
	return append(b, payload...)
}

func TestParseHeader(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}
	raw := synthHeader(156, 4321, "Google Chrome H", 1, flagDirOut, payload)

	p, err := parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.PID != 4321 {
		t.Errorf("pid: got %d want 4321", p.PID)
	}
	if p.Comm != "Google Chrome H" {
		t.Errorf("comm: got %q", p.Comm)
	}
	if p.EPID != 4322 || p.EComm != "mDNSResponder" {
		t.Errorf("effective proc: got %d %q", p.EPID, p.EComm)
	}
	if p.Ifname != "en0" {
		t.Errorf("ifname: got %q", p.Ifname)
	}
	if p.Dir != DirOut {
		t.Errorf("dir: got %v want DirOut", p.Dir)
	}
	if p.DLT != 1 {
		t.Errorf("dlt: got %d", p.DLT)
	}
	if p.FlowID != 0xdeadbeef {
		t.Errorf("flowid: got %x", p.FlowID)
	}
	if string(p.Data) != string(payload) {
		t.Errorf("payload: got %x want %x", p.Data, payload)
	}
}

// The kernel has grown this struct before, so pth_length is authoritative and
// a longer header must still parse with the payload starting in the right place.
func TestParseHeaderFutureLength(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	raw := synthHeader(200, 99, "kernel_task", 1, flagDirIn, payload)
	p, err := parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.PID != 99 || p.Dir != DirIn {
		t.Errorf("got pid=%d dir=%v", p.PID, p.Dir)
	}
	if string(p.Data) != string(payload) {
		t.Errorf("payload misaligned: got %x", p.Data)
	}
}

func TestParseHeaderRejectsGarbage(t *testing.T) {
	if _, err := parse([]byte{1, 2, 3}); err == nil {
		t.Error("want error on runt header")
	}
	bad := synthHeader(156, 1, "x", 1, 0, nil)
	binary.LittleEndian.PutUint32(bad[offLength:], 0xffffffff)
	if _, err := parse(bad); err == nil {
		t.Error("want error on implausible header length")
	}
	short := synthHeader(60, 7, "small", 1, flagDirOut, []byte{9})
	p, err := parse(short)
	if err != nil {
		t.Fatalf("short-but-valid header should parse: %v", err)
	}
	if p.PID != 7 {
		t.Errorf("pid from short header: got %d", p.PID)
	}
	if p.Comm != "" {
		t.Errorf("comm should be empty when header is too short to contain it, got %q", p.Comm)
	}
}
