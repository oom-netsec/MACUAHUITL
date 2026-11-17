//go:build windows

package transfer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// B1: lo descargado lleva la Mark of the Web (ZoneId=3) sobre la ruta interna.
func TestDownloadEscribeMarkOfTheWeb(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("imagen")) }))
	defer ts.Close()
	u, _ := url.Parse(ts.URL + "/fw.bin")
	dest := t.TempDir()
	p := filepath.Join(dest, "sonda-flujo.tmp") // sondeo del volumen: salta solo si no hay flujos
	os.WriteFile(p, nil, 0o600)
	probe := sys.MarkOfTheWeb(p)
	os.Remove(p)
	if probe != nil {
		t.Skip("el volumen no admite flujos alternos:", probe)
	}
	res, err := Download(context.Background(), Request{Net: rawNet, URL: u, DestDir: dest})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(res.Path + ":Zone.Identifier")
	if err != nil {
		t.Fatal("el volumen admite flujos pero falta la marca:", err)
	}
	if string(b) != "[ZoneTransfer]\r\nZoneId=3\r\n" {
		t.Fatalf("flujo = %q", b)
	}
}
