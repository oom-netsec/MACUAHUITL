package sys

import (
	"errors"
	"strings"
	"testing"
)

func TestHibernateWarnings(t *testing.T) {
	if w := hibernateWarnings(0, nil); len(w) != 0 {
		t.Fatalf("HibernateEnabled=0 no debe avisar: %v", w)
	}
	w := hibernateWarnings(1, nil)
	if len(w) != 1 || !strings.Contains(w[0].In("en"), "BitLocker") || !strings.Contains(w[0].In("es"), "BitLocker") {
		t.Fatalf("HibernateEnabled=1 debe avisar y recomendar BitLocker: %v", w)
	}
	w = hibernateWarnings(0, errors.New("acceso denegado"))
	if len(w) != 1 || !strings.Contains(w[0].In("en"), "could not check") || !strings.Contains(w[0].In("en"), "acceso denegado") {
		t.Fatalf("si no se puede leer, debe decirlo: %v", w)
	}
}

func TestPagefileWarnings(t *testing.T) {
	if w := pagefileWarnings(nil, false, nil); len(w) != 0 {
		t.Fatalf("sin PagingFiles no hay aviso: %v", w)
	}
	if w := pagefileWarnings([]string{"", ""}, false, nil); len(w) != 0 {
		t.Fatalf("entradas vacías no cuentan: %v", w)
	}
	w := pagefileWarnings([]string{`?:\pagefile.sys`, ""}, false, nil)
	if len(w) != 1 || !strings.Contains(w[0].In("en"), `the system drive (\pagefile.sys)`) || strings.Contains(w[0].In("en"), "?:") || !strings.Contains(w[0].In("es"), `la unidad del sistema (\pagefile.sys)`) || !strings.Contains(w[0].In("en"), "BitLocker") {
		t.Fatalf("?: debe leerse como la unidad del sistema, con BitLocker: %q %q", w[0].In("en"), w[0].In("es"))
	}
	w = pagefileWarnings([]string{`C:\pagefile.sys`}, false, nil)
	if len(w) != 1 || !strings.Contains(w[0].In("en"), `paging file is on (C:\pagefile.sys)`) {
		t.Fatalf("una letra de unidad sale tal cual: %v", w)
	}
	w = pagefileWarnings([]string{`C:\pagefile.sys 0 0`}, false, nil)
	if len(w) != 1 || !strings.Contains(w[0].In("en"), `(C:\pagefile.sys)`) {
		t.Fatalf("solo la ruta, sin tamaños: %q", w[0].In("en"))
	}
	if w := pagefileWarnings([]string{`?:\pagefile.sys`}, true, nil); len(w) != 0 {
		t.Fatalf("EncryptPagingFile=1: sin aviso: %v", w)
	}
	w = pagefileWarnings(nil, false, errors.New("sin clave"))
	if len(w) != 1 || !strings.Contains(w[0].In("es"), "no se pudo comprobar") {
		t.Fatalf("si no se puede leer, debe decirlo: %v", w)
	}
}

func TestUnsafeVolume(t *testing.T) {
	for vol, want := range map[string]bool{
		"": false, "C:": false, "z:": false, // sin volumen (relativa) o unidad simple
		`\\host\share`: true, `\\?\C:`: true, `\\.\pipe`: true, `\\.\COM1`: true, `//host/share`: true,
	} {
		if got := unsafeVolume(vol); got != want {
			t.Errorf("unsafeVolume(%q) = %v", vol, got)
		}
	}
}
