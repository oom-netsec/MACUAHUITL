package bridge

import (
	"strings"
	"testing"
)

// Microsoft: «pv» vacío, ausente o 0.0.0.0 en HKLM y en HKCU = WebView2 no instalado; basta una de las dos con versión.
func TestWebView2Missing(t *testing.T) {
	for _, c := range []struct {
		pv   []string
		want bool
	}{
		{[]string{"", ""}, true},
		{[]string{"0.0.0.0", ""}, true},
		{[]string{"0.0.0.0", "0.0.0.0"}, true},
		{[]string{"131.0.2903.70", ""}, false},
		{[]string{"", "131.0.2903.70"}, false},
		{[]string{" ", ""}, true},
	} {
		if got := WebView2Missing(c.pv...); got != c.want {
			t.Errorf("WebView2Missing(%q) = %v, quiero %v", c.pv, got, c.want)
		}
	}
}

// El aviso sale antes de conocer el idioma elegido (vive en el núcleo): lleva los dos, inglés primero, y el enlace oficial.
func TestWebView2MissingTextBilingueConEnlace(t *testing.T) {
	m := WebView2MissingText()
	en, es := strings.Index(m, "WebView2 Runtime is not installed"), strings.Index(m, "no está instalado el runtime WebView2")
	if en < 0 || es < 0 || en > es {
		t.Fatalf("falta un idioma o el orden no es en, es: %q", m)
	}
	if strings.Count(m, WebView2DownloadURL) != 2 {
		t.Fatalf("el enlace debe ir en los dos idiomas: %q", m)
	}
}
