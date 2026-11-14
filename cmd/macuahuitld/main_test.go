package main

import (
	"os"
	"testing"
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
	for lang, want := range map[string]string{"en": "XDG_RUNTIME_DIR is not set", "es": "XDG_RUNTIME_DIR no está definido"} {
		consoleLang = lang
		if err := run(); err == nil || err.Error() != want {
			t.Errorf("%s: %v", lang, err)
		}
	}
}
