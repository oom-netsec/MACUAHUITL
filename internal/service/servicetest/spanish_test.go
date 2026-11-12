package servicetest

import "testing"

func TestSpanishWords(t *testing.T) {
	for in, want := range map[string]int{
		"passed=1 of 2":                     0,
		"pasaron=1 de 2":                    1,
		`reason="razón rara" guard=revoked`: 0,
		"devices=2 path=/tmp/x":             0,
		"el equipo cerró la sesión":         0, // texto de un error sin código: se deja tal cual
		"guard=revocado carpeta=/x":         2,
		"run=de183bc8 command=show vlan":    0,
		"3 nuevos, 1 omitidos":              2,
	} {
		if got := SpanishWords(in); len(got) != want {
			t.Errorf("%q: %v", in, got)
		}
	}
}
