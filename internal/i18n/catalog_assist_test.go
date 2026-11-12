package i18n

import (
	"regexp"
	"strings"
	"testing"
)

// Ningún código del asistente declara un argumento que pueda llevar un secreto (la community, contraseñas, hashes, llaves).
func TestAsistenteSinArgumentosSecretos(t *testing.T) {
	secretos := regexp.MustCompile(`(?i)secret|passw|hash|community|key|token`)
	n := 0
	for code, e := range catalog {
		if !strings.HasPrefix(code, "assist.") {
			continue
		}
		n++
		for _, a := range append(append([]string{}, e.Args...), e.Extra...) {
			if secretos.MatchString(a) {
				t.Errorf("%s: el argumento %q podría llevar un secreto", code, a)
			}
		}
	}
	if n < 200 {
		t.Fatalf("solo %d códigos assist.*", n)
	}
}

// Los avisos del plan (assist.note.*) sin argumentos son texto fijo: el de en no hereda el español.
func TestAsistenteEnSinEspanol(t *testing.T) {
	es := regexp.MustCompile(`[áéíóúñ¿¡«»]|\b(el equipo|la reversa|no se pudo|puerto|solo|tiene)\b`)
	for code, e := range catalog {
		if strings.HasPrefix(code, "assist.") && es.MatchString(e.En) {
			t.Errorf("%s: español en la versión en: %q", code, e.En)
		}
	}
}
