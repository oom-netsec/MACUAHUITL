package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// Un error del canal (catálogo) se imprime en el idioma de mctl: inglés por omisión, no el español de Error().
func TestPrintErrErrorDelCanalEnIdioma(t *testing.T) {
	defer cli.SetLang("")
	for lang, want := range map[string]string{"en": "the core is not running", "es": "el núcleo no está corriendo"} {
		cli.SetLang(lang)
		var b bytes.Buffer
		printErr(&b, ipc.ErrNotRunning)
		if !strings.Contains(b.String(), want) {
			t.Errorf("%s: %q no contiene %q", lang, b.String(), want)
		}
	}
}
