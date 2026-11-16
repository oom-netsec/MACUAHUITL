// Package systest comprueba en las pruebas «solo el usuario tiene acceso»: el modo exacto en Linux (0600 o 0700, como
// siempre) y la DACL en Windows (ADR 0012, c). Solo se importa desde archivos _test.go.
package systest

import (
	"os"
	"runtime"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// Private exige que path haya quedado con want (0600 o 0700) en Linux y, en Windows, con la DACL protegida que da
// MkdirPrivate o ProtectFile: dueño el usuario y solo él, SYSTEM y Administradores.
func Private(t testing.TB, path string, want os.FileMode) {
	t.Helper()
	check(t, path, want, sys.IsPrivate)
}

// Inherited es Private para lo que se creó dentro de una carpeta hecha con sys.MkdirPrivate: en Windows hereda la
// DACL, así que no está protegida; basta que no dé acceso a nadie más.
func Inherited(t testing.TB, path string, want os.FileMode) {
	t.Helper()
	check(t, path, want, sys.OnlyOwnAccess)
}

func check(t testing.TB, path string, want os.FileMode, win func(string) (bool, error)) {
	t.Helper()
	if runtime.GOOS == "windows" {
		if ok, err := win(path); err != nil || !ok {
			t.Errorf("%s: ACL no es privada (ok=%v, err=%v)", path, ok, err)
		}
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Errorf("%s: %v", path, err)
		return
	}
	if fi.Mode().Perm() != want {
		t.Errorf("%s: modo %v, quería %v", path, fi.Mode().Perm(), want)
	}
}

// TempDir es t.TempDir() ya con la DACL protegida de MkdirPrivate (en Linux no cambia nada): lo que la prueba cree
// adentro la hereda, como bajo las carpetas propias del núcleo, y se comprueba con Inherited.
func TempDir(t testing.TB) string {
	t.Helper()
	d := t.TempDir()
	if err := sys.MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	return d
}
