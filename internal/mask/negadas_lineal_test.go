package mask

import (
	"strings"
	"testing"
	"time"
)

// Muchos «no» seguidos se quitan de una pasada: 4 veces más «no» tarda unas 4 veces más (cuadrático serían 16). Se
// mide la escala y no un tiempo fijo; se toma el mínimo de tres corridas.
func TestNegadasLineal(t *testing.T) {
	for _, form := range []string{"%ssnmp-server community Cl4ve RO\n", "- %ssnmp-server community Cl4ve RO\n"} {
		best := func(n int) time.Duration {
			in := strings.Replace(form, "%s", strings.Repeat("no ", n), 1)
			min := time.Duration(1<<63 - 1)
			for range 3 {
				start := time.Now()
				out, _ := Apply("ios", in)
				if strings.Contains(out, "Cl4ve") {
					t.Fatalf("fuga con %d «no»", n)
				}
				if d := time.Since(start); d < min {
					min = d
				}
			}
			return min
		}
		small, big := best(10000), best(40000) // con menos, el ruido de arranque pesa más que la escala
		if big > 10*small {
			t.Fatalf("%q: 4 veces más «no» tardó %v contra %v: no es lineal", form, big, small)
		}
	}
}

// Las formas en mayúsculas pasan también por el diff y el eco de prompt.
func TestNegadasMayusculasEnCaminosEspeciales(t *testing.T) {
	for _, in := range []string{
		"- NO snmp-server community Cl4ve RO",
		"+ No snmp-server community Cl4ve RO",
		"R1(config)#NO snmp-server community Cl4ve RO",
		"line vty 0 4\n NO password Cl4ve",
	} {
		if out, _ := Apply("ios", in+"\n"); strings.Contains(out, "Cl4ve") {
			t.Errorf("%q -> %q", in, out)
		}
	}
}
