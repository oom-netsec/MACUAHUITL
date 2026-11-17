package sys

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMarkOfTheWebEscribeZoneIdentifier(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fw.bin")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MarkOfTheWeb(p); err != nil {
		t.Skip("el volumen no admite flujos alternos:", err)
	}
	b, err := os.ReadFile(p + ":Zone.Identifier")
	if err != nil || string(b) != "[ZoneTransfer]\r\nZoneId=3\r\n" {
		t.Fatalf("flujo = %q, %v", b, err)
	}
	if c, _ := os.ReadFile(p); string(c) != "x" {
		t.Fatalf("el contenido cambió: %q", c)
	}
	if err := MarkOfTheWeb(filepath.Join(filepath.Dir(p), "no-existe", "x")); err == nil {
		t.Error("marcar en una carpeta inexistente no falló")
	}
}
