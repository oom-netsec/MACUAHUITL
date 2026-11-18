package main

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
)

// Sin núcleo, mctl dice qué hacer en vez de mostrar el Unavailable crudo de gRPC (Linux y Windows, es y en).
func TestCoreCaidoMensajeLegible(t *testing.T) {
	defer cli.SetLang("")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	ipctest.Isolate(t) // sin servidor
	for lang, want := range map[string]string{"en": "the core is not running; start it", "es": "el núcleo no está corriendo; arráncalo"} {
		_, err := mctlRaw(t, "", "--lang", lang, "job", "list")
		if err == nil {
			t.Fatalf("%s: sin núcleo debe fallar", lang)
		}
		var b strings.Builder
		printErr(&b, err)
		s := b.String()
		if !strings.Contains(s, want) || !strings.Contains(s, "macuahuitld") {
			t.Errorf("%s: %q no contiene %q", lang, s, want)
		}
		for _, bad := range []string{"rpc error", "Unavailable", "pipe", "cannot find", "dial", "connection error"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s: %q contiene %q", lang, s, bad)
			}
		}
		if cli.ExitCode(err) != 1 {
			t.Errorf("código %d", cli.ExitCode(err))
		}
	}
}
