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

// M1: si el renombrado no se puede (aquí .1 es una carpeta con contenido), el registro se sigue usando.
func TestOpenLogRotacionFallidaNoImpideArrancar(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "a.log")
	os.MkdirAll(filepath.Join(p+".1", "x"), 0o700)
	os.WriteFile(p, []byte(strings.Repeat("x", 101)), 0o600)
	f, err := OpenLog(p, 100)
	if err != nil {
		t.Fatalf("OpenLog = %v, quería seguir agregando", err)
	}
	f.WriteString("fin\n")
	f.Close()
	if b, _ := os.ReadFile(p); !strings.HasSuffix(string(b), "fin\n") || len(b) != 105 {
		t.Fatalf("log = %d bytes, quería 101 + el agregado", len(b))
	}
}

// L4: un registro que es un enlace no se sigue.
func TestOpenLogRechazaUnEnlace(t *testing.T) {
	d := t.TempDir()
	obj := filepath.Join(d, "otro")
	os.WriteFile(obj, []byte("no tocar"), 0o600)
	p := filepath.Join(d, "a.log")
	if err := os.Symlink(obj, p); err != nil {
		t.Skip("sin enlaces simbólicos:", err)
	}
	if f, err := OpenLog(p, 100); err == nil {
		f.Close()
		t.Fatal("OpenLog siguió el enlace")
	}
	if b, _ := os.ReadFile(obj); string(b) != "no tocar" {
		t.Fatalf("el destino cambió: %q", b)
	}
}

func TestAppendLogAgregaSinRotar(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.log")
	os.WriteFile(p, []byte(strings.Repeat("x", 50<<20)), 0o600) // más que LogMax
	if err := appendLog(p, "falló"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + ".1"); err == nil {
		t.Fatal("appendLog no rota")
	}
	if b, _ := os.ReadFile(p); !strings.HasSuffix(string(b), " falló\n") {
		t.Fatalf("no quedó la línea: %q", b[len(b)-20:])
	}
}
