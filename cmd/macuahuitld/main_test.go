package main

import "testing"

func TestConsolePrefix(t *testing.T) {
	defer func(l string) { consoleLang = l }(consoleLang)
	for lang, want := range map[string]string{"en": "warning:", "es": "aviso:"} {
		consoleLang = lang
		if got := consolePrefix(); got != want {
			t.Errorf("%s: %q", lang, got)
		}
	}
}
