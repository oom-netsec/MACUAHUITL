//go:build windows

package transfer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

// B1: lo descargado lleva la Mark of the Web (ZoneId=3) sobre la ruta interna.
func TestDownloadEscribeMarkOfTheWeb(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("imagen")) }))
	defer ts.Close()
	u, _ := url.Parse(ts.URL + "/fw.bin")
	dest := t.TempDir()
	res, err := Download(context.Background(), Request{URL: u, DestDir: dest})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(res.Path + ":Zone.Identifier")
	if err != nil {
		t.Skip("el volumen no admite flujos alternos:", err)
	}
	if string(b) != "[ZoneTransfer]\r\nZoneId=3\r\n" {
		t.Fatalf("flujo = %q", b)
	}
}
