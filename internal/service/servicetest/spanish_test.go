package servicetest

import "testing"

func TestSpanishWords(t *testing.T) {
	for in, want := range map[string]int{
		"passed=1 of 2":                     0,
		"pasaron=1 de 2":                    2,
		`reason="razón rara" guard=revoked`: 0,
		"devices=2 path=/tmp/x":      0,
		"sesión nueva abierta":              1,
		"guard=revocado carpeta=/x":         2,
	} {
		if got := SpanishWords(in); len(got) != want {
			t.Errorf("%q: %v", in, got)
		}
	}
}
