package cli

import (
	"reflect"
	"testing"
)

func TestStripLang(t *testing.T) {
	for name, tc := range map[string]struct {
		in   []string
		rest []string
		lang string
		bad  bool
	}{
		"sin bandera":         {[]string{"vault", "status"}, []string{"vault", "status"}, "", false},
		"separada":            {[]string{"--lang", "en", "vault", "status"}, []string{"vault", "status"}, "en", false},
		"con igual":           {[]string{"--lang=en", "vault", "status"}, []string{"vault", "status"}, "en", false},
		"un guion":            {[]string{"-lang", "es", "vault"}, []string{"vault"}, "es", false},
		"etiqueta":            {[]string{"--lang", "en-US", "vault"}, []string{"vault"}, "en", false},
		"con otra global":     {[]string{"--no-color", "--lang", "en", "vault"}, []string{"--no-color", "vault"}, "en", false},
		"después del comando": {[]string{"vault", "--lang", "en"}, []string{"vault", "--lang", "en"}, "", false},
		"tras --":             {[]string{"--", "--lang", "en"}, []string{"--", "--lang", "en"}, "", false},
		"se come el comando":  {[]string{"--lang", "vault", "status"}, nil, "", true},
		"sin valor":           {[]string{"--lang"}, nil, "", true},
		"fr":                  {[]string{"--lang=fr", "vault"}, nil, "", true},
	} {
		rest, lang, err := StripLang(tc.in)
		if (err != nil) != tc.bad || lang != tc.lang || (!tc.bad && !reflect.DeepEqual(rest, tc.rest)) {
			t.Errorf("%s: %v %q %v", name, rest, lang, err)
		}
	}
}
