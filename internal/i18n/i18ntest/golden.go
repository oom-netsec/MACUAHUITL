// Package i18ntest da a las pruebas de regresión de texto un golden compartido (sin dependencias del núcleo).
package i18ntest

import (
	"encoding/json"
	"os"
	"testing"
)

// Golden compara got con el archivo file (JSON con las claves ordenadas). Con UPDATE_GOLDEN=1 lo escribe: se hace
// una sola vez con el código de antes de un cambio de texto, para fijar byte por byte lo que ya se devolvía.
func Golden(t *testing.T, file string, got map[string]string) {
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
