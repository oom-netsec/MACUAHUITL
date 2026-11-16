package bridge

import (
	"strings"
	"testing"
)

// La app elevada no arranca (el núcleo tampoco correría): el aviso va en los dos idiomas, inglés primero, como el de WebView2.
func TestElevatedTextBilingue(t *testing.T) {
	m := ElevatedText()
	en, es := strings.Index(m, "does not run elevated"), strings.Index(m, "no corre elevado")
	if en < 0 || es < 0 || en > es {
		t.Fatalf("falta un idioma o el orden no es en, es: %q", m)
	}
}
