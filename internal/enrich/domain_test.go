package enrich

import (
	"testing"
	"time"
)

// Naive "last two labels" gets multi-part TLDs wrong, which is why this uses
// the Public Suffix List: bar.co.uk is registrable, co.uk is not.
func TestRegistrable(t *testing.T) {
	for in, want := range map[string]string{
		"agentn.global.api5.cursor.sh": "cursor.sh",
		"api2.cursor.sh":               "cursor.sh",
		"cursor.sh":                    "cursor.sh",
		"foo.bar.co.uk":                "bar.co.uk",
		"a.b.c.github.io":              "c.github.io", // github.io is a public suffix
		"notion.so.":                   "notion.so",
		"API.Cursor.SH":                "cursor.sh",
		"":                             "",
		"localhost":                    "",
		"192.168.1.1":                  "",
	} {
		if got := Registrable(in); got != want {
			t.Errorf("Registrable(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRDAP(t *testing.T) {
	body := []byte(`{
	  "objectClassName":"domain","ldhName":"EXAMPLE.SH",
	  "events":[{"eventAction":"registration","eventDate":"2015-03-14T09:26:53Z"},
	            {"eventAction":"expiration","eventDate":"2030-03-14T09:26:53Z"}],
	  "entities":[
	    {"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],
	        ["fn",{},"text","Example Registrar LLC"]]]},
	    {"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],
	        ["fn",{},"text","Some Person"],["org",{},"text","Anysphere, Inc."]]]}]}`)

	var o Owner
	parseRDAP(body, &o)
	if o.Err != "" {
		t.Fatalf("unexpected error: %s", o.Err)
	}
	if o.Registrar != "Example Registrar LLC" {
		t.Errorf("registrar: %q", o.Registrar)
	}
	// Organisation beats the contact's personal name.
	if o.Registrant != "Anysphere, Inc." {
		t.Errorf("registrant: %q", o.Registrant)
	}
	if o.Created.Year() != 2015 || o.Created.Month() != time.March {
		t.Errorf("created: %v", o.Created)
	}
	// Expiration must not be mistaken for registration.
	if o.Created.Year() == 2030 {
		t.Error("picked up the expiration event")
	}
}

// jCard's "org" is sometimes an array of organisational units rather than a
// string. Registries differ, and a type mismatch must not lose the whole record.
func TestParseRDAPOrgAsArray(t *testing.T) {
	body := []byte(`{"entities":[{"roles":["registrant"],
	  "vcardArray":["vcard",[["version",{},"text","4.0"],
	    ["org",{},"text",["Contoso Ltd","IT Department"]]]]}]}`)
	var o Owner
	parseRDAP(body, &o)
	if o.Registrant != "Contoso Ltd" {
		t.Errorf("registrant: %q", o.Registrant)
	}
}

// A redacted registrant is normal and is itself information; it must come back
// empty rather than breaking the parse.
func TestParseRDAPRedacted(t *testing.T) {
	body := []byte(`{"events":[{"eventAction":"registration","eventDate":"2024-11-02T00:00:00Z"}],
	  "entities":[{"roles":["registrant"],"handle":"REDACTED FOR PRIVACY"}]}`)
	var o Owner
	parseRDAP(body, &o)
	if o.Registrant != "REDACTED FOR PRIVACY" {
		t.Errorf("registrant: %q", o.Registrant)
	}
	if o.Created.IsZero() {
		t.Error("registration date should still parse")
	}
}

func TestParseRDAPGarbage(t *testing.T) {
	var o Owner
	parseRDAP([]byte(`not json`), &o)
	if o.Err == "" {
		t.Error("want an error recorded, not a silent empty result")
	}
}

// Age in days is the signal that separates an established service from
// something registered last week, so an unknown date must read as unknown
// rather than as zero days old.
func TestAgeDays(t *testing.T) {
	var nilOwner *Owner
	if nilOwner.AgeDays() != -1 {
		t.Error("nil owner should report unknown age")
	}
	if (&Owner{}).AgeDays() != -1 {
		t.Error("missing date should report unknown age, not 0")
	}
	o := &Owner{Created: time.Now().Add(-72 * time.Hour)}
	if d := o.AgeDays(); d != 3 {
		t.Errorf("age: got %d want 3", d)
	}
}

// Lookups must not fire when RDAP is disabled: it is the one component that
// talks to the network, and off must mean off.
func TestOwnersDisabledMakesNoRequests(t *testing.T) {
	o := NewOwners(t.TempDir()+"/owners.json", false)
	if got := o.Lookup("example.com"); got != nil {
		t.Errorf("disabled lookup returned %+v", got)
	}
	select {
	case d := <-o.queue:
		t.Fatalf("queued %q with RDAP disabled", d)
	default:
	}
}

func TestOwnersCacheRoundTrip(t *testing.T) {
	path := t.TempDir() + "/owners.json"
	o := NewOwners(path, true)
	o.m["cursor.sh"] = &Owner{Domain: "cursor.sh", Registrant: "Anysphere, Inc.",
		Created: time.Now().Add(-800 * 24 * time.Hour), Fetched: time.Now()}
	if err := o.Save(); err != nil {
		t.Fatal(err)
	}

	o2 := NewOwners(path, true)
	if err := o2.Load(); err != nil {
		t.Fatal(err)
	}
	got := o2.Lookup("cursor.sh")
	if got == nil || got.Registrant != "Anysphere, Inc." {
		t.Fatalf("after load: %+v", got)
	}
	if d := got.AgeDays(); d < 795 || d > 805 {
		t.Errorf("age after load: %d", d)
	}
}
