package i18n

import "testing"

// El valor canónico de una decisión de importación es el inglés; el español sigue valiendo como alias.
func TestDecision(t *testing.T) {
	for in, want := range map[string]string{
		"rename": "rename", "replace": "replace", "skip": "skip",
		"renombrar": "rename", "reemplazar": "replace", "omitir": "skip",
		"fusionar": "fusionar", "": "",
	} {
		if got := Decision(in); got != want {
			t.Errorf("Decision(%q) = %q, quiero %q", in, got, want)
		}
	}
}
