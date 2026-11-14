package cli

import (
	"errors"
	"testing"
)

func TestLocalizeUsage(t *testing.T) {
	t.Cleanup(func() { SetLang("") })
	e := errors.New("uso: mctl backup diff ID_A ID_B | ID_A --now -d EQUIPO --cred ID [--accept HUELLA] [--all=renombrar|reemplazar|omitir]")
	SetLang("")
	want := "usage: mctl backup diff ID_A ID_B | ID_A --now -d DEVICE --cred ID [--accept FINGERPRINT] [--all=renombrar|reemplazar|omitir]"
	if got := LocalizeUsage(e); got.Error() != want {
		t.Fatalf("en: %v", got)
	}
	SetLang("es")
	if got := LocalizeUsage(e); got != e {
		t.Fatalf("es debe quedar igual: %v", got)
	}
	if got := LocalizeUsage(errors.New("otro")); got.Error() != "otro" {
		t.Fatal(got)
	}
}

func TestLocaleSinIdiomaEsIngles(t *testing.T) {
	SetLang("")
	if Lang() != "en" {
		t.Fatalf("Lang() = %q", Lang())
	}
}
