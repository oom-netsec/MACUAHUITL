package msgkb

import (
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestLoadErroresEsYEn(t *testing.T) {
	ok := "  meaning: m\n  cause: c\n  action: a\n  verify: [show version]\n"
	for _, w := range []struct{ data, es, en string }{
		{"- id: SYS-2-X\n" + ok, `msgkb: ID inválido "SYS-2-X"`, `msgkb: invalid ID "SYS-2-X"`},
		{"- id: \"%SYS-2-X\"\n" + ok + "- id: \"%SYS-2-X\"\n" + ok, "msgkb: ID repetido %SYS-2-X", "msgkb: duplicate ID %SYS-2-X"},
		{"- id: \"%SYS-2-X\"\n", "msgkb: %SYS-2-X: faltan significado, causa, acción o verificación", "msgkb: %SYS-2-X: meaning, cause, action or verification is missing"},
	} {
		_, err := Load([]byte(w.data))
		if err == nil || err.Error() != w.es || i18n.In("en", err) != w.en {
			t.Errorf("es %v en %q, quería %q / %q", err, i18n.In("en", err), w.es, w.en)
		}
	}
	if _, err := Load([]byte("- id: [")); err == nil || err.Error()[:7] != "msgkb: " || i18n.In("en", err)[:7] != "msgkb: " {
		t.Errorf("yaml: %v", err)
	}
}
