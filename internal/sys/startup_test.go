package sys

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func leer(t *testing.T, dir string) (m map[string]any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, StartupName))
	if err != nil {
		t.Fatal(err)
	}
	if b[len(b)-1] != '\n' {
		t.Fatalf("sin salto de línea final: %q", b)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestStartupJSON(t *testing.T) {
	at := time.Date(2026, 11, 16, 20, 30, 0, 0, time.FixedZone("x", -6*3600))
	var m map[string]any
	b := StartupJSON(at, i18n.New("harden.err.lockquota", i18n.A("cause", "boom")))
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["at"] != "2026-11-17T02:30:00Z" || m["code"] != "harden.err.lockquota" || m["args"].(map[string]any)["cause"] != "boom" ||
		m["text"] != i18n.In(i18n.En, i18n.New("harden.err.lockquota", i18n.A("cause", "boom"))) {
		t.Fatalf("%v", m)
	}
	// Error común: sin código, args vacío (objeto, no null) y texto siempre.
	if err := json.Unmarshal(StartupJSON(at, errors.New("boom")), &m); err != nil {
		t.Fatal(err)
	}
	if m["code"] != "" || m["text"] != "boom" || m["args"] == nil || len(m["args"].(map[string]any)) != 0 {
		t.Fatalf("%v", m)
	}
	// Envuelto, el código es el del i18n.Error que lleva.
	if err := json.Unmarshal(StartupJSON(at, i18n.Wrap("sys.err.not_owner", errors.New("x"), i18n.A("path", "p"))), &m); err != nil || m["code"] != "sys.err.not_owner" {
		t.Fatalf("%v %v", m, err)
	}
}

func TestWriteYClearStartup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	WriteStartup(dir, errors.New("uno")) // crea State
	if leer(t, dir)["text"] != "uno" {
		t.Fatal("no escribió")
	}
	WriteStartup(dir, errors.New("dos")) // sobrescribe: una sola línea
	if b, _ := os.ReadFile(filepath.Join(dir, StartupName)); leer(t, dir)["text"] != "dos" || len(b) > 0 && b[0] != '{' {
		t.Fatal("no sobrescribió")
	}
	ClearStartup(dir)
	if _, err := os.Lstat(filepath.Join(dir, StartupName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no se borró: %v", err)
	}
	ClearStartup(dir) // sin archivo: no falla
}

func TestWriteStartupNoSigueEnlaces(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	os.Mkdir(dir, 0o700)
	blanco := filepath.Join(base, "blanco")
	os.WriteFile(blanco, []byte("intacto"), 0o600)
	if err := os.Symlink(blanco, filepath.Join(dir, StartupName)); err != nil {
		t.Skip(err)
	}
	WriteStartup(dir, errors.New("x"))
	ClearStartup(dir)
	if b, _ := os.ReadFile(blanco); string(b) != "intacto" {
		t.Fatalf("escribió o borró por el enlace: %q", b)
	}
	if fi, err := os.Lstat(filepath.Join(dir, StartupName)); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatal("tocó el enlace")
	}
}

// Un proceso elevado no escribe nada: ni crea State ni deja el archivo (la ruta sale de una variable del usuario).
func TestWriteStartupElevadoNoEscribe(t *testing.T) {
	defer func(f func() bool) { isPrivileged = f }(isPrivileged)
	isPrivileged = func() bool { return true }
	base := t.TempDir()
	nueva := filepath.Join(base, "nueva")
	WriteStartup(nueva, errors.New("x"))
	if _, err := os.Lstat(nueva); err == nil {
		t.Fatal("el proceso elevado creó State")
	}
	dir := filepath.Join(base, "state")
	os.Mkdir(dir, 0o700)
	WriteStartup(dir, errors.New("x"))
	if _, err := os.Lstat(filepath.Join(dir, StartupName)); err == nil {
		t.Fatal("el proceso elevado escribió .startup")
	}
}

// El error de OpenLog sobre algo que no es un archivo regular sale del catálogo (va al text de .startup, en inglés) y
// conserva fs.ErrInvalid.
func TestOpenLogNoRegularEnIngles(t *testing.T) {
	d := t.TempDir()
	os.Mkdir(filepath.Join(d, "log"), 0o700)
	_, err := OpenLog(filepath.Join(d, "log"), LogMax)
	if !errors.Is(err, fs.ErrInvalid) || !strings.HasSuffix(i18n.In(i18n.En, err), "is not a regular file") {
		t.Fatalf("%v", err)
	}
}

// Dos aperturas seguidas del mismo registro nuevo escriben sin pisarse: la primera ya no tiene su propio puntero.
func TestOpenLogDosAperturasNoSePisan(t *testing.T) {
	p := filepath.Join(t.TempDir(), "macuahuitld.log")
	a, err := OpenLog(p, LogMax) // crea el archivo
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenLog(p, LogMax)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	a.WriteString("a1\n")
	b.WriteString("b1\n")
	a.WriteString("a2\n")
	got, _ := os.ReadFile(p)
	if string(got) != "a1\nb1\na2\n" {
		t.Fatalf("%q", got)
	}
}
