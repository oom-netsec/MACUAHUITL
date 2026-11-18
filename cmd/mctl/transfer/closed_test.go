package transfer

import "testing"

// 43e-6 punto 1: el pie de cierre no sale sin comando (vacío o solo espacios).
func TestClosedLineSinComandoNoImprime(t *testing.T) {
	for _, c := range []string{"", "  ", "\n \t"} {
		if got := closedLine(c); got != "" {
			t.Errorf("%q: %q", c, got)
		}
	}
	if closedLine("sudo nft delete table ip x") == "" {
		t.Error("con comando debe imprimir")
	}
}
