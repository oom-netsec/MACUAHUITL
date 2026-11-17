// Package i18ntest da a las pruebas de regresión de texto un golden compartido (sin dependencias del núcleo).
package i18ntest

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Golden compara got con el archivo file (JSON con las claves ordenadas). Con UPDATE_GOLDEN=1 lo escribe: se hace
// una sola vez con el código de antes de un cambio de texto, para fijar byte por byte lo que ya se devolvía.
//
// skipWin son claves que en Windows no se comparan (ni en lo obtenido ni en el golden): su texto trae una ruta o un error
// del sistema que el golden fijó con los de Linux (/etc, «no such file or directory»). Hay que dar el motivo en el
// llamador; en Linux no cambia nada.
func Golden(t *testing.T, file string, got map[string]string, skipWin ...string) {
	t.Helper()
	b, _ := json.MarshalIndent(got, "", " ")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		got = maps.Clone(got) // quien llama sigue usando su mapa completo (p. ej. para comparar idiomas)
		for _, k := range skipWin {
			delete(got, k)
			delete(want, k)
		}
	}
	for k, v := range got {
		if want[k] != v {
			t.Errorf("%s: la salida en español cambió\n got: %q\nwant: %q", k, v, want[k])
		}
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("%s: falta en la salida", k)
		}
	}
}

// Dump junta el informe de una RPC (json y texto) o su error en una sola cadena para Golden.
func Dump(json, text string, err error) string {
	if err != nil {
		return "ERROR: " + err.Error()
	}
	return json + "\n---\n" + text
}

// TempDir es t.TempDir() con la ruta ya resuelta: en Windows TEMP viene en formato corto (RUNNER~1) y el código que
// resuelve rutas (EvalSymlinks) devuelve la larga, así que el texto no coincidiría con lo que la prueba normaliza.
func TempDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if r, err := filepath.EvalSymlinks(d); err == nil {
		return r
	}
	return d
}

// Dirs cambia cada carpeta de dirs por <dir>. En Windows además cubre la ruta dentro de un JSON (barras invertidas
// duplicadas) y deja lo que cuelga de <dir> con «/», como el golden de Linux. En Linux solo reemplaza.
func Dirs(v string, dirs []string) string {
	for _, d := range dirs {
		if runtime.GOOS == "windows" {
			v = strings.ReplaceAll(v, strings.ReplaceAll(d, `\`, `\\`), "<dir>")
		}
		v = strings.ReplaceAll(v, d, "<dir>")
	}
	if runtime.GOOS == "windows" {
		v = strings.ReplaceAll(strings.ReplaceAll(v, `<dir>\\`, "<dir>/"), `<dir>\`, "<dir>/")
	}
	return v
}
