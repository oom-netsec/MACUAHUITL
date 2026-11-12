package cli

import (
	"reflect"
	"testing"
)

func TestStripValueFlag(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		rest []string
		val  string
		ok   bool
	}{
		{[]string{"vault", "status"}, []string{"vault", "status"}, "", false},
		{[]string{"--lang", "en", "vault", "status"}, []string{"vault", "status"}, "en", true},
		{[]string{"vault", "--lang=en", "status"}, []string{"vault", "status"}, "en", true},
		{[]string{"vault", "status", "--lang"}, []string{"vault", "status"}, "", true},
		{[]string{"--lang", "en", "--lang", "es", "x"}, []string{"x"}, "es", true},
	} {
		rest, val, ok := StripValueFlag(tc.in, "--lang")
		if !reflect.DeepEqual(rest, tc.rest) || val != tc.val || ok != tc.ok {
			t.Errorf("%v: %v %q %v", tc.in, rest, val, ok)
		}
	}
}

// --lang manda; si no, LC_ALL, LC_MESSAGES y LANG por ese orden; si no, es.
func TestLangDeLaConsola(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for name, tc := range map[string]struct {
		flag string
		env  map[string]string
		want string
	}{
		"sin nada":               {"", nil, "es"},
		"bandera en":             {"en", map[string]string{"LANG": "es_MX.UTF-8"}, "en"},
		"bandera es gana":        {"es", map[string]string{"LC_ALL": "en_US.UTF-8"}, "es"},
		"LANG":                   {"", map[string]string{"LANG": "en_US.UTF-8"}, "en"},
		"LC_MESSAGES sobre LANG": {"", map[string]string{"LC_MESSAGES": "es_MX.UTF-8", "LANG": "en_US.UTF-8"}, "es"},
		"LC_ALL sobre todo":      {"", map[string]string{"LC_ALL": "en_GB.UTF-8", "LC_MESSAGES": "es_MX.UTF-8", "LANG": "es"}, "en"},
		"C es es":                {"", map[string]string{"LANG": "C"}, "es"},
		"POSIX es es":            {"", map[string]string{"LC_ALL": "POSIX", "LANG": "en_US.UTF-8"}, "es"},
		"desconocido":            {"fr", map[string]string{"LANG": "en_US.UTF-8"}, "es"},
	} {
		if got := Lang(tc.flag, env(tc.env)); got != tc.want {
			t.Errorf("%s: %q, quiero %q", name, got, tc.want)
		}
	}
}
