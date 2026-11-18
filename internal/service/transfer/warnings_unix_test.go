//go:build !windows

package transfer

import (
	"os"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// ServerReady.warnings lleva el aviso de una carpeta publicada que otros pueden escribir, con la orden aparte,
// para que la UI lo muestre sin leer el texto de hint.
func TestServerReadyLlevaAvisosDeCarpeta(t *testing.T) {
	s, _ := newTest(t)
	pub := t.TempDir()
	if err := os.Chmod(pub, 0o757); err != nil { // o+w: el bit de otros, sin depender del grupo
		t.Fatal(err)
	}
	rd := startServer(t, s, &v1.StartServerRequest{Protocol: "tftp", Listen: "127.0.0.1:0", FromDir: pub, Allow: []string{"127.0.0.1"}}).ready
	if len(rd.Warnings) != 1 {
		t.Fatalf("avisos = %v", rd.Warnings)
	}
	w := rd.Warnings[0]
	if w.Code != "fileserve.hint.warn_from_writable" || w.Message == "" || strings.Contains(w.Message, "chmod") || !strings.Contains(w.Cmd, "chmod") || !strings.Contains(rd.Hint, w.Cmd) {
		t.Fatalf("aviso = %+v\nhint = %s", w, rd.Hint)
	}
	if rd2 := startServer(t, s, &v1.StartServerRequest{Protocol: "tftp", Listen: "127.0.0.1:0", FromDir: t.TempDir(), Allow: []string{"127.0.0.1"}}).ready; len(rd2.Warnings) != 0 {
		t.Fatalf("carpeta privada con avisos: %v", rd2.Warnings)
	}
}
