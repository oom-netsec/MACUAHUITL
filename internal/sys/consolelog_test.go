package sys

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOpenLogRotaAlPasarElTope(t *testing.T) {
	p := filepath.Join(t.TempDir(), "macuahuitld.log")
	// Primer arranque: el archivo nace, y un segundo arranque agrega sin pisar.
	for _, línea := range []string{"uno\n", "dos\n"} {
		f, err := OpenLog(p, 100)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(línea)
		f.Close()
	}
	if b, _ := os.ReadFile(p); string(b) != "uno\ndos\n" {
		t.Fatalf("log = %q, quería uno y dos", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		t.Fatalf("modo %v: el log debe nacer privado", fi.Mode())
	}
	// Pasa del tope: el viejo queda en .1 (y reemplaza a un .1 anterior) y el nuevo empieza vacío.
	os.WriteFile(p+".1", []byte("muy viejo"), 0o600)
	os.WriteFile(p, []byte(strings.Repeat("x", 101)), 0o600)
	f, err := OpenLog(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("nuevo\n")
	f.Close()
	if b, _ := os.ReadFile(p); string(b) != "nuevo\n" {
		t.Fatalf("log = %q, quería solo «nuevo»", b)
	}
	if b, _ := os.ReadFile(p + ".1"); len(b) != 101 {
		t.Fatalf(".1 = %d bytes, quería los 101 del log rotado", len(b))
	}
	if _, err := os.Stat(p + ".2"); err == nil {
		t.Fatal("solo se conserva un .1")
	}
}

func TestOpenLogEnElTopeExactoNoRota(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.log")
	os.WriteFile(p, []byte(strings.Repeat("x", 100)), 0o600)
	f, err := OpenLog(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := os.Stat(p + ".1"); err == nil {
		t.Fatal("con exactamente el tope no se rota")
	}
}
