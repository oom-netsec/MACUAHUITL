package main

import (
	"errors"
	"os"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// El runner de CI de Windows corre elevado, y run se niega a arrancar elevado (ADR 0012): las pruebas de run fijan «no elevado».
func TestMain(m *testing.M) {
	privileged = func() bool { return false }
	os.Exit(m.Run())
}

// 3.7: con todas las variables vacías el núcleo no arranca y dice cuál falta (LOCALAPPDATA); no cae a %APPDATA% ni a C:\Windows.
func TestSinVariablesNoArranca(t *testing.T) {
	for _, k := range []string{"LOCALAPPDATA", "APPDATA", "USERPROFILE", "HOME", "TEMP", "TMP"} {
		t.Setenv(k, "")
	}
	err := run(func() ([]i18n.Text, error) { return nil, nil })
	var ie *i18n.Error
	if !errors.As(err, &ie) || ie.Code != "harden.err.localappdata" {
		t.Fatalf("err = %v", err)
	}
}
