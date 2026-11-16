package mask_test

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/mask"
)

// Un valor pegado desde Word, Confluence o un correo trae NBSP u otro espacio Unicode entre la palabra clave y el valor.
// \s de RE2 solo conoce el espacio ASCII: sin normalizar los tramos de M₂, el valor se ve en todas las vías.
// Cada plantilla de canales_test.go, con uno, todos o el primero junto a un espacio de los separadores cambiados.
func TestEspaciosUnicodeNingunSecretoSeVe(t *testing.T) {
	espacios := map[string]string{"NBSP U+00A0": "\u00a0", "U+2009": "\u2009", "U+202F": "\u202f", "U+3000": "\u3000", "tab": "\t",
		"U+2003": "\u2003", "U+0085": "\u0085", "U+1680": "\u1680", "ZWSP": "\u200b"}
	cmds, plats := canalCasos(len(canalPlantillas))
	formas := map[string]func(c, sp string) string{
		"uno":         func(c, sp string) string { return strings.Replace(c, " ", sp, 1) },
		"todos":       func(c, sp string) string { return strings.ReplaceAll(c, " ", sp) },
		"con espacio": func(c, sp string) string { return strings.ReplaceAll(c, " ", sp+" ") },
		"sin espacio ASCII antes del valor": func(c, sp string) string {
			i := strings.LastIndex(c, " ")
			if i < 0 {
				return c
			}
			return c[:i] + sp + c[i+1:]
		},
	}
	// Solo las plantillas que cubre M₂ (mask.Command las tapa tecleadas con espacios ASCII). Las que solo ve una regla de la
	// v0.6.5 sobre configuración impresa («api-key X», «crypto pki export … pem terminal 3des X») dependen de S1, que no cambia.
	usadas := 0
	malos := 0
	for nom, sp := range espacios {
		for fn, f := range formas {
			for i, c := range cmds {
				marcas := canalMarca.FindAllString(c, -1)
				if o, _ := mask.Command(c); anyIn(o, marcas) {
					continue
				}
				in := f(c, sp)
				usadas++
				for _, ch := range canales {
					if sp == "\t" && strings.HasPrefix(ch.nombre, "12") { // en la terminal un tabulador es la tecla de completar: se tapa todo desde él (typedLine)
						continue
					}
					out := ch.f(plats[i], in)
					for _, m := range marcas {
						if strings.Contains(out, m) {
							if malos++; malos <= 25 {
								t.Errorf("[%s] %s/%s (%s)\n  entrada: %q\n  salida:  %q", ch.nombre, nom, fn, plats[i], in, strings.TrimSpace(out))
							}
							break
						}
					}
				}
			}
		}
	}
	if usadas < 1000 {
		t.Errorf("muy pocas plantillas cubiertas: %d", usadas)
	}
	if malos > 25 {
		t.Errorf("%d fugas en total", malos)
	}
}

func anyIn(s string, ms []string) bool {
	for _, m := range ms {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// Un espacio Unicode dentro del valor es parte del token para IOS: no se parte el valor (la vía de eco desplazado
// depende de recordar el valor entero).
func TestEspacioUnicodeDentroDelValorNoLoParte(t *testing.T) {
	for _, sp := range []string{" ", " ", " ", "　", "\t", " ", "\u0085", " "} {
		cmd := "pre-shared-key local #AbCd" + sp + "Zq02231 remote AbCd" + sp + "Zq02232!"
		for _, ch := range canales {
			if sp == "\t" && strings.HasPrefix(ch.nombre, "12") {
				continue
			}
			out := ch.f("ios-xe", cmd)
			for _, m := range []string{"Zq02231", "Zq02232"} {
				if strings.Contains(out, m) {
					t.Errorf("[%s] %q: %s visible: %q", ch.nombre, sp, m, out)
				}
			}
		}
	}
}
