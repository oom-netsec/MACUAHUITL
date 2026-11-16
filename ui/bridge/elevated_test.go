package bridge

import (
	"errors"
	"strings"
	"testing"
)

// El aviso de registro no abierto lleva la ruta y el error, en los dos idiomas e inglés primero.
func TestAppLogTextBilingue(t *testing.T) {
	m := AppLogText(`C:\x\state\macuahuitl.log`, errors.New("acceso denegado"))
	en, es := strings.Index(m, "could not open its log"), strings.Index(m, "no pudo abrir su registro")
	if en < 0 || es < 0 || en > es || strings.Count(m, `C:\x\state\macuahuitl.log`) != 2 || strings.Count(m, "acceso denegado") != 2 {
		t.Fatalf("%q", m)
	}
}

// La app elevada no arranca (el núcleo tampoco correría): el aviso va en los dos idiomas, inglés primero, como el de WebView2.
func TestElevatedTextBilingue(t *testing.T) {
	m := ElevatedText()
	en, es := strings.Index(m, "does not run elevated"), strings.Index(m, "no corre elevado")
	if en < 0 || es < 0 || en > es {
		t.Fatalf("falta un idioma o el orden no es en, es: %q", m)
	}
	// Quien usó «Ejecutar como administrador» con UAC activo tiene que saber que basta con abrirla normal; sin «ADR».
	if !strings.Contains(m, "Run as administrator") || !strings.Contains(m, "Ejecutar como administrador") || strings.Contains(m, "ADR") {
		t.Fatalf("%q", m)
	}
}
