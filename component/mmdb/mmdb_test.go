package mmdb

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
)

func TestInstallAcceptsOptionalDescription(t *testing.T) {
	data := testDatabase("sing-geoip", "aa")
	metadata := bytes.LastIndex(data, []byte("\xab\xcd\xefMaxMind.com")) + len("\xab\xcd\xefMaxMind.com")
	data[metadata]-- // the metadata map has one fewer entry
	data = data[:bytes.LastIndex(data, []byte("\x4bdescription"))]
	if err := InstallIP(data, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(IPInstance().Metadata.Description) != 0 {
		t.Fatal("changed source metadata")
	}
}

// Small, complete MMDBs with a one-node IPv4 tree. Both halves point to one record;
// every IP therefore exercises the same data without shipping a third-party database.
func testDatabase(kind, value string) []byte {
	str := func(s string) []byte {
		if len(s) < 29 {
			return append([]byte{0x40 | byte(len(s))}, []byte(s)...)
		}
		return append([]byte{0x5d, byte(len(s) - 29)}, []byte(s)...)
	}
	data := []byte{0, 0, 17, 0, 0, 17}
	data = append(data, make([]byte, 16)...)
	switch kind {
	case "Meta-geoip0":
		data[5] = 19              // right half points to the first string inside the array
		data = append(data, 2, 4) // extended type 11 (array), two values
		data = append(data, str(value)...)
		data = append(data, str("bb")...)
	case "sing-geoip":
		data = append(data, str(value)...)
	case "ipinfo generic_asn_free.mmdb":
		data = append(data, 0xe2)
		for _, s := range []string{"asn", value, "name", "Test"} {
			data = append(data, str(s)...)
		}
	}
	data = append(data, []byte("\xab\xcd\xefMaxMind.com")...)
	data = append(data, 0xe7)
	for _, item := range []struct {
		k string
		v byte
	}{
		{"node_count", 1}, {"record_size", 24}, {"ip_version", 4},
		{"binary_format_major_version", 2}, {"binary_format_minor_version", 0},
	} {
		data = append(data, str(item.k)...)
		data = append(data, 0xa1, item.v)
	}
	data = append(data, str("database_type")...)
	data = append(data, str(kind)...)
	data = append(data, str("description")...)
	data = append(data, 0xe1)
	data = append(data, str("en")...)
	data = append(data, str("test")...)
	return data
}

func TestInstallPreservesSnapshotsAndFailures(t *testing.T) {
	ok := func() error { return nil }
	if err := InstallIP(testDatabase("sing-geoip", "aa"), ok); err != nil {
		t.Fatal(err)
	}
	old := IPInstance()
	data := testDatabase("sing-geoip", "bb")
	if err := InstallIP(data, ok); err != nil {
		t.Fatal(err)
	}
	// The caller no longer owns the live reader's buffer.
	clear(data)
	ip := net.ParseIP("1.2.3.4")
	if got := old.LookupCode(ip); len(got) != 1 || got[0] != "aa" {
		t.Fatal(got)
	}
	if got := IPInstance().LookupCode(ip); len(got) != 1 || got[0] != "bb" {
		t.Fatal(got)
	}
	errDisk := errors.New("disk full")
	if err := InstallIP(testDatabase("sing-geoip", "cc"), func() error { return errDisk }); !errors.Is(err, errDisk) {
		t.Fatal(err)
	}
	if err := InstallIP([]byte("bad database"), func() error { t.Fatal("persisted bad data"); return nil }); err == nil {
		t.Fatal("accepted invalid data")
	}
	if got := IPInstance().LookupCode(ip); len(got) != 1 || got[0] != "bb" {
		t.Fatal(got)
	}
	if err := InstallASN(testDatabase("ipinfo generic_asn_free.mmdb", "AS123"), ok); err != nil {
		t.Fatal(err)
	}
	oldASN := ASNInstance()
	if err := InstallASN(testDatabase("ipinfo generic_asn_free.mmdb", "AS456"), ok); err != nil {
		t.Fatal(err)
	}
	if got, _ := oldASN.LookupASN(ip); got != "123" {
		t.Fatal(got)
	}
	if got, _ := ASNInstance().LookupASN(ip); got != "456" {
		t.Fatal(got)
	}
	if err := InstallASN(testDatabase("sing-geoip", "aa"), ok); err == nil {
		t.Fatal("accepted country database as ASN")
	}
}

func TestInstallConcurrentLookups(t *testing.T) {
	ok := func() error { return nil }
	if err := InstallIP(testDatabase("sing-geoip", "aa"), ok); err != nil {
		t.Fatal(err)
	}
	if err := InstallASN(testDatabase("ipinfo generic_asn_free.mmdb", "AS123"), ok); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := net.ParseIP("1.2.3.4")
			for range 500 {
				snapshot := IPInstance()
				asn := ASNInstance()
				if got := snapshot.LookupCode(ip); len(got) != 1 || (got[0] != "aa" && got[0] != "bb") {
					t.Error(got)
				}
				if got, _ := asn.LookupASN(ip); got != "123" && got != "456" {
					t.Error(got)
				}
			}
		}()
	}
	for i := range 100 {
		code, asn := "aa", "AS123"
		if i%2 == 0 {
			code, asn = "bb", "AS456"
		}
		if err := InstallIP(testDatabase("sing-geoip", code), ok); err != nil {
			t.Fatal(err)
		}
		if err := InstallASN(testDatabase("ipinfo generic_asn_free.mmdb", asn), ok); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestInstallAcceptsSharedRecordsAndRejectsBrokenPointers(t *testing.T) {
	data := testDatabase("Meta-geoip0", "aa")
	if err := InstallIP(data, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if got := IPInstance().LookupCode(net.ParseIP("1.2.3.4")); len(got) != 2 {
		t.Fatal(got)
	}
	if got := IPInstance().LookupCode(net.ParseIP("200.2.3.4")); len(got) != 1 || got[0] != "aa" {
		t.Fatal(got)
	}
	data[2] = 255 // outside the data section
	if err := InstallIP(data, func() error { t.Fatal("persisted invalid pointer"); return nil }); err == nil {
		t.Fatal("accepted invalid pointer")
	}
}
