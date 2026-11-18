package transfer

import (
	"strings"
	"testing"
)

// 43e-6 punto 1: el pie de cierre no sale sin comando (vacío o solo espacios).
func TestClosedLineSinComandoNoImprime(t *testing.T) {
	for _, c := range []string{"", "  ", "\n \t"} {
		for _, goos := range []string{"linux", "windows"} {
			if got := closedLineFor(goos, c); got != "" {
				t.Errorf("%s %q: %q", goos, c, got)
			}
		}
	}
	if closedLineFor("linux", "sudo nft delete table ip x") == "" {
		t.Error("con comando debe imprimir")
	}
}

// En Windows la regla es de firewall, no una redirección: el pie lo dice.
func TestClosedLineWindowsHablaDeFirewall(t *testing.T) {
	w := closedLineFor("windows", "Remove-NetFirewallRule -DisplayName 'x'")
	l := closedLineFor("linux", "sudo nft delete table ip x")
	if !strings.Contains(strings.ToLower(w), "firewall") || strings.Contains(w, "redirect") || strings.Contains(w, "redirección") || !strings.Contains(l, "redirect") && !strings.Contains(l, "redirección") {
		t.Errorf("win=%q linux=%q", w, l)
	}
}
