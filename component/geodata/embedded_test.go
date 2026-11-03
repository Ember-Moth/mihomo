package geodata

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestExternalDownloadsNeverFetchOrDeleteInvalidData(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	dir := t.TempDir()
	C.SetHomeDir(dir)
	SetExternalDownloads(true)
	defer SetExternalDownloads(false)
	SetGeoIpUrl(server.URL)
	SetGeoSiteUrl(server.URL)
	SetMmdbUrl(server.URL)
	SetASNUrl(server.URL)
	SetGeodataMode(false)
	for _, init := range []func() error{InitGeoIP, InitASN} {
		if err := init(); err == nil {
			t.Fatal("missing file succeeded")
		}
	}
	bad := filepath.Join(dir, "ASN.mmdb")
	if err := os.WriteFile(bad, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InitASN(); err == nil {
		t.Fatal("invalid file succeeded")
	}
	if got, err := os.ReadFile(bad); err != nil || string(got) != "invalid" {
		t.Fatal("deleted original", err)
	}
	if calls.Load() != 0 {
		t.Fatal("implicit network request")
	}
}
