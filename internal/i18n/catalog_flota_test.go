package i18n

import (
	"regexp"
	"strings"
	"testing"
)

var flotaPrefixes = []string{"fleet.", "analyze.", "acl.", "change.", "upgrade.", "compliance.", "drift.", "cleaner."}

// españolEnIngles son palabras y letras que no deben quedar en un texto en inglés (ni en su plantilla).
var españolEnIngles = regexp.MustCompile(`(?i)[áéíóúñ¿¡]|\b(sin|ningún|ninguna|equipo|equipos|tiene|vecino|saltos?|flota|origen|destino|tabla|aparece|libre|usada|corta|ignora|salida|puerto|las|los|del|una|con|por|para|según|línea|líneas|regla|reglas|ronda|rondas|hay)\b`)

// Los textos de flota, análisis, ACL, cambios, actualización, cumplimiento, deriva y limpieza: el inglés no
// deja español y el español no es una copia del inglés (salvo textos que son solo un dato).
func TestCatalogoFlotaEnIngles(t *testing.T) {
	var n int
	for code, e := range catalog {
		if !anyOf(flotaPrefixes, func(p string) bool { return strings.HasPrefix(code, p) }) {
			continue
		}
		n++
		plain := regexp.MustCompile(`\{[^}]*\}`).ReplaceAllString(e.En, "")
		if m := españolEnIngles.FindString(plain); m != "" {
			t.Errorf("%s: español en el inglés: %q (%s)", code, e.En, m)
		}
		if e.Es == e.En && strings.Trim(regexp.MustCompile(`\{[^}]*\}`).ReplaceAllString(e.Es, ""), " :·/()-") != "" {
			t.Errorf("%s: el inglés es igual al español: %q", code, e.En)
		}
	}
	if n == 0 {
		t.Error("ningún código de flota")
	}
}

func anyOf(l []string, f func(string) bool) bool {
	for _, x := range l {
		if f(x) {
			return true
		}
	}
	return false
}
