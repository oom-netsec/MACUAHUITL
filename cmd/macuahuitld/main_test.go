package main

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestConsolePrefix(t *testing.T) {
	defer func(l string) { consoleLang = l }(consoleLang)
	for lang, want := range map[string]string{"en": "warning:", "es": "aviso:"} {
		consoleLang = lang
		if got := consolePrefix(); got != want {
			t.Errorf("%s: %q", lang, got)
		}
	}
}

func TestParseLang(t *testing.T) {
	for in, want := range map[string]string{"": "en", "en": "en", "es": "es", "ES-mx": "es", "en_US": "en"} {
		if got, err := parseLang(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"fr", "espanol", "esx"} {
		if _, err := parseLang(in); err == nil {
			t.Errorf("%q debía fallar", in)
		}
	}
}

func TestErroresFatalesPorIdioma(t *testing.T) {
	defer func(l string) { consoleLang = l }(consoleLang)
	t.Setenv("XDG_RUNTIME_DIR", "")
	if os.Geteuid() == 0 {
		t.Skip("root")
	}
	if runtime.GOOS == "windows" { // el error es de XDG_RUNTIME_DIR; en Windows el canal es un pipe por SID y run() arrancaría un núcleo de verdad
		t.Skip("sin XDG_RUNTIME_DIR en Windows (ADR 0012)")
	}
	for lang, want := range map[string]string{"en": "XDG_RUNTIME_DIR is not set", "es": "XDG_RUNTIME_DIR no está definido"} {
		consoleLang = lang
		if err := run(func() ([]i18n.Text, error) { return nil, nil }); err == nil || err.Error() != want {
			t.Errorf("%s: %v", lang, err)
		}
	}
}

// Si el endurecimiento falla (p. ej. no se pudo asegurar el bloqueo de memoria), el núcleo no arranca.
func TestHardenFallidoNoArranca(t *testing.T) {
	defer func(l string) { consoleLang = l }(consoleLang)
	consoleLang = "en"
	if os.Geteuid() == 0 {
		t.Skip("root")
	}
	err := run(func() ([]i18n.Text, error) { return nil, i18n.New("harden.err.lockquota", i18n.A("cause", "boom")) })
	if err == nil || !strings.Contains(err.Error(), "boom") || !strings.Contains(err.Error(), "does not start") {
		t.Fatalf("err = %v", err)
	}
}

// Elevado (root en Linux, token elevado en Windows) el núcleo no arranca, y ni siquiera llega a endurecer.
func TestElevadoNoArranca(t *testing.T) {
	old := privileged
	privileged = func() bool { return true }
	t.Cleanup(func() { privileged = old })
	want := "harden.err.root"
	if runtime.GOOS == "windows" {
		want = "harden.err.elevated"
	}
	err := run(func() ([]i18n.Text, error) { t.Fatal("no debe endurecer"); return nil, nil })
	var ie *i18n.Error
	if !errors.As(err, &ie) || ie.Code != want {
		t.Fatalf("err = %v, quería %s", err, want)
	}
}
