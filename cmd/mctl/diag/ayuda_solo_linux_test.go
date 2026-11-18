package diag

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Toda clave que internal/diag rechaza en Windows (winOnly) aparece en la línea de la ayuda que habla de Windows.
func TestAyudaDiagMarcaOpcionesSoloLinux(t *testing.T) {
	src, err := os.ReadFile("../../../internal/diag/args_ping.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`winOnly\("([a-z_]+)"\)`).FindAllStringSubmatch(string(src), -1)
	if len(m) < 4 {
		t.Fatalf("se esperaban al menos 4 llamadas a winOnly, hay %d", len(m))
	}
	var winLine string
	for _, l := range strings.Split(help, "\n") {
		if strings.Contains(l, "En Windows no van") {
			winLine = l
		}
	}
	if winLine == "" {
		t.Fatal("la ayuda no tiene la línea de opciones que no van en Windows")
	}
	for _, k := range m {
		if !strings.Contains(winLine, k[1]) {
			t.Errorf("la ayuda no menciona %q entre lo que no va en Windows", k[1])
		}
	}
	for _, k := range []string{"tos (0-255, solo Linux", "interval (0.2-60, solo Linux"} {
		if !strings.Contains(help, k) {
			t.Errorf("la ayuda no contiene %q", k)
		}
	}
}
