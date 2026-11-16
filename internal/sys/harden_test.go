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
	if w := pagefileWarnings(nil, nil); len(w) != 0 {
		t.Fatalf("sin PagingFiles no hay aviso: %v", w)
	}
	if w := pagefileWarnings([]string{"", ""}, nil); len(w) != 0 {
		t.Fatalf("entradas vacías no cuentan: %v", w)
	}
	w := pagefileWarnings([]string{`?:\pagefile.sys`, ""}, nil)
	if len(w) != 1 || !strings.Contains(w[0].In("en"), `?:\pagefile.sys`) || !strings.Contains(w[0].In("en"), "BitLocker") {
		t.Fatalf("pagefile activo debe avisar con la ruta y BitLocker: %v", w)
	}
	w = pagefileWarnings(nil, errors.New("sin clave"))
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
