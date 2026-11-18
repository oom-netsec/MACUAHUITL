package main

import (
	"path/filepath"
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

// Una ruta relativa se rechaza con un mensaje del catálogo antes de cualquier Stat: nunca sale la cadena cruda del
// sistema (GetFileAttributesEx, lstat…). Las tres variantes del QA: prefs set --outputs, diag --out.
func TestOutputsRelativaSinApiCruda(t *testing.T) {
	startCore(t)
	cmds := map[string][]string{
		"prefs":      {"prefs", "set", "--outputs", "rel"},
		"diag":       {"diag", "ping", "127.0.0.1", "--out", "rel"},
		"diag-punto": {"diag", "ping", "127.0.0.1", "--out", "./rel"},
	}
	for name, args := range cmds {
		for lang, want := range map[string]string{"en": "must be absolute", "es": "debe ser absoluta"} {
			_, err := mctlRaw(t, "", append([]string{"--lang", lang}, args...)...)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s/%s: err = %v, quería %q", name, lang, err, want)
				continue
			}
			for _, bad := range []string{"GetFileAttributesEx", "lstat", "fileserve", "no such file", "0700"} {
				if strings.Contains(err.Error(), bad) {
					t.Errorf("%s/%s: %q contiene %q", name, lang, err, bad)
				}
			}
		}
	}
}

// ca_written imprime la carpeta limpia y absoluta, sin «/» pegada al final: en Windows saldría «…\ca/».
func TestCaWrittenUnaBarra(t *testing.T) {
	startCore(t)
	wd := t.TempDir()
	t.Chdir(wd)
	out := mustRaw(t, "capw\ncapw\n", "--lang", "en", "pki", "ca", "init", "--name", "Lab CA", "--out", "ca")
	want := "CA in " + filepath.Join(wd, "ca") + " (ca.crt.pem, sealed ca.key.pem)"
	if !strings.Contains(out, want) {
		t.Fatalf("%q no contiene %q", out, want)
	}
}

// Una carpeta absoluta que no existe sale sin la llamada del sistema (lstat, GetFileAttributesEx en Windows) ni la ruta repetida.
func TestTransferCarpetaInexistenteSinLlamadaCruda(t *testing.T) {
	startCore(t)
	d := filepath.Join(t.TempDir(), "no-existe")
	for _, a := range [][]string{
		{"transfer", "serve", "--proto", "tftp", "--listen", "127.0.0.1", "--write", "--allow", "127.0.0.1", "--dir", d},
		{"transfer", "serve", "--proto", "tftp", "--listen", "127.0.0.1", "--from", d},
	} {
		_, err := mctlRaw(t, "", append([]string{"--lang", "en"}, a...)...)
		if err == nil {
			t.Fatal("debe fallar")
		}
		for _, bad := range []string{"lstat", "GetFileAttributesEx", d + ": "} {
			if strings.Contains(err.Error(), bad) {
				t.Errorf("%q contiene %q", err, bad)
			}
		}
		if !strings.Contains(err.Error(), "no such file or directory") {
			t.Errorf("falta la causa: %q", err)
		}
	}
}
