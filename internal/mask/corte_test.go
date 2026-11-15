package mask_test

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/mask"
)

// Propiedad de cut sola: con textos y tramos al azar (también tramos que caen dentro de un <MASKED:…>, separadores
// « ; » y valores que terminan en «>»), la salida está bien formada y es s1 con una región cambiada por marcadores:
// nunca muestra algo que s1 no mostraba.
func TestCortePropiedad(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	piezas := []string{"word", "x", " ", " ", "enable secret", "5", " ; ", "<MASKED:secret>", "<MASKED:type7>", "a>", "<", ">", "ñandú", "'", "Zq00001"}
	malos := 0
	for n := 0; n < 20000; n++ {
		var o, s strings.Builder
		for k := 1 + r.Intn(10); k > 0; k-- {
			p := piezas[r.Intn(len(piezas))]
			s.WriteString(p)
			if strings.HasPrefix(p, "<MASKED:") && r.Intn(2) == 0 {
				p = []string{"Zq00001>", "secret", ">", "ab>", "<x"}[r.Intn(5)] // en el original ahí había un valor
			}
			o.WriteString(p)
		}
		orig, s1 := o.String(), s.String()
		if r.Intn(3) == 0 {
			orig = s1 // las reglas no cambiaron nada: los tramos pueden caer dentro de un marcador
		}
		var spans [][2]int
		for k := r.Intn(3); k >= 0; k-- {
			a := r.Intn(len(orig) + 1)
			spans = append(spans, [2]int{a, a + r.Intn(len(orig)-a+1)})
		}
		out, _ := mask.Cut(orig, s1, spans)
		if !bienFormada(out) || !superconjunto(out, s1) {
			if malos++; malos <= 10 {
				t.Errorf("orig %q\n  s1 %q\n  spans %v\n  out %q", orig, s1, spans, out)
			}
		}
	}
	if malos > 10 {
		t.Errorf("%d violaciones en total", malos)
	}
}
