package sys

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

type fakeInfo struct {
	fs.FileInfo
	mode fs.FileMode
}

func (f fakeInfo) Mode() fs.FileMode { return f.mode }

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
	writeStartup(dir, errors.New("uno"), false) // crea State
	if leer(t, dir)["text"] != "uno" {
		t.Fatal("no escribió")
	}
	writeStartup(dir, errors.New("dos"), false) // sobrescribe: una sola línea
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
	for _, elev := range []bool{false, true} {
		writeStartup(dir, errors.New("x"), elev)
		ClearStartup(dir)
		if b, _ := os.ReadFile(blanco); string(b) != "intacto" {
			t.Fatalf("elevado=%v: escribió o borró por el enlace: %q", elev, b)
		}
		if fi, err := os.Lstat(filepath.Join(dir, StartupName)); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			t.Fatalf("elevado=%v: tocó el enlace", elev)
		}
	}
}

func TestWriteStartupElevado(t *testing.T) {
	base := t.TempDir()
	// State inexistente: elevado no la crea.
	nueva := filepath.Join(base, "nueva")
	writeStartup(nueva, errors.New("x"), true)
	if _, err := os.Lstat(nueva); err == nil {
		t.Fatal("el proceso elevado creó State")
	}
	// State propia y real: escribe.
	dir := filepath.Join(base, "state")
	os.Mkdir(dir, 0o700)
	writeStartup(dir, errors.New("x"), true)
	if leer(t, dir)["text"] != "x" {
		t.Fatal("elevado con State propia debía escribir")
	}
	// State es un enlace a una carpeta: no escribe en el destino.
	destino := filepath.Join(base, "destino")
	os.Mkdir(destino, 0o700)
	if err := os.Symlink(destino, filepath.Join(base, "enlace")); err == nil {
		writeStartup(filepath.Join(base, "enlace"), errors.New("x"), true)
		if _, err := os.Lstat(filepath.Join(destino, StartupName)); err == nil {
			t.Fatal("escribió a través de un enlace")
		}
	}
}

// La decisión de «¿puedo escribir aquí?» con datos inyectados (en Windows el caso elevado no se puede simular).
func TestStartupDirOK(t *testing.T) {
	const user, otro, admins = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002", "S-1-5-32-544"
	dir := fakeInfo{mode: fs.ModeDir | 0o700}
	for _, c := range []struct {
		name        string
		fi          fs.FileInfo
		owner, user string
		want        bool
	}{
		{"carpeta del usuario", dir, user, user, true},
		{"SID en otra capitalización", dir, "s-1-5-21-1-2-3-1001", user, true},
		{"dueño otro usuario", dir, otro, user, false},
		{"dueño Administradores (aquí no vale)", dir, admins, user, false},
		{"dueño vacío", dir, "", user, false},
		{"usuario vacío", dir, "", "", false},
		{"enlace simbólico", fakeInfo{mode: fs.ModeSymlink | fs.ModeDir}, user, user, false},
		{"junction (irregular)", fakeInfo{mode: fs.ModeIrregular}, user, user, false},
		{"archivo, no carpeta", fakeInfo{mode: 0o600}, user, user, false},
		{"sin datos", nil, user, user, false},
	} {
		if got := startupDirOK(c.fi, c.owner, c.user); got != c.want {
			t.Errorf("%s: %v, quería %v", c.name, got, c.want)
		}
	}
}
