package eval

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A Little Snitch 6 `log-traffic` export, in its documented column order.
const lsCSV = `date,direction,uid,ipAddress,remoteHostname,protocol,port,connectCount,denyCount,byteCountIn,byteCountOut,connectingExecutable,parentAppExecutable
2026-11-10 09:00:11,out,501,104.18.32.7,ads.adnetwork.example,6,443,1,0,900,500,/Applications/Notion.app/Contents/Frameworks/Notion Helper.app/Contents/MacOS/Notion Helper,/Applications/Notion.app
2026-11-10 09:00:11,in,501,104.18.32.7,,6,443,1,0,0,0,/x,
2026-11-10 09:00:20,out,501,151.101.65.140,,6,443,1,0,1,1,/Applications/Firefox.app/Contents/MacOS/firefox,
`

func TestLoadLittleSnitch(t *testing.T) {
	l, err := LoadReal("littlesnitch", strings.NewReader(lsCSV))
	if err != nil {
		t.Fatal(err)
	}
	at := func(s string) time.Time { tt, _ := parseTime(s); return tt }
	ap := netip.MustParseAddrPort
	sh, ok, _ := l.Shown("tcp", ap("104.18.32.7:443"), "Notion Helper", at("2026-11-10 09:00:12"))
	if !ok || sh.Name != "ads.adnetwork.example" || sh.Claim != "read" {
		t.Fatalf("notion: %+v %v", sh, ok)
	}
	// Same address, another process: the row is not about this flow.
	if _, ok, _ := l.Shown("tcp", ap("104.18.32.7:443"), "Slack Helper", at("2026-11-10 09:00:12")); ok {
		t.Fatal("matched a different executable")
	}
	// Logged with no name: the tool showed only the address (blank, but logged).
	sh, ok, _ = l.Shown("tcp", ap("151.101.65.140:443"), "firefox", at("2026-11-10 09:00:20"))
	if !ok || sh.Name != "" {
		t.Fatalf("firefox: %+v %v", sh, ok)
	}
	// Far outside the row's interval: no opinion.
	if _, ok, _ := l.Shown("tcp", ap("151.101.65.140:443"), "firefox", at("2026-11-10 10:00:00")); ok {
		t.Fatal("matched an unrelated time")
	}
}

func TestCommonFormat(t *testing.T) {
	l, err := LoadReal("lulu", strings.NewReader("time,executable,ip,port,protocol,name\n1795436022000,/usr/bin/curl,1.2.3.4,443,tcp,example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	sh, ok, _ := l.Shown("tcp", netip.MustParseAddrPort("1.2.3.4:443"), "curl", time.UnixMilli(1795436022500))
	if !ok || sh.Name != "example.com" {
		t.Fatalf("%+v %v", sh, ok)
	}
}
