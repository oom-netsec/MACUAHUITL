package scripts

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var ahora = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

func muestra(i int) Script {
	return Script{ID: NewID(), Name: fmt.Sprintf("script %02d", i), Tech: "l3", Platform: "ios-xe", Description: "d",
		Commands: []string{"show ip route", fmt.Sprintf("show ip ospf %d", i)}, Tags: []string{"ospf"}, Origin: OrigenUsuario, CreatedAt: ahora, UpdatedAt: ahora}
}

func TestExportParseIdaYVuelta(t *testing.T) {
	var todos []Script
	for i := 0; i < 15; i++ {
		todos = append(todos, muestra(i))
	}
	b, err := Marshal(todos, ahora)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(b)
	if err != nil || len(got) != 15 {
		t.Fatalf("got=%d err=%v", len(got), err)
	}
	for i := range got {
		if got[i].ID != todos[i].ID || !Same(got[i], todos[i]) {
			t.Fatalf("script %d cambió: %+v", i, got[i])
		}
	}
	// un archivo reindentado (mismo contenido) sigue valiendo: la suma es del JSON canónico
	if _, err := Parse([]byte(strings.ReplaceAll(string(b), `"scripts":[`, "\"scripts\":[\n"))); err != nil {
		t.Fatalf("espacio en blanco: %v", err)
	}
}

func TestParseRechazaUnByteCambiado(t *testing.T) {
	b, _ := Marshal([]Script{muestra(1)}, ahora)
	mal := strings.Replace(string(b), "show ip route", "show ip rout3", 1)
	if _, err := Parse([]byte(mal)); err == nil || !strings.Contains(err.Error(), "suma") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRechazos(t *testing.T) {
	ok, _ := Marshal([]Script{muestra(1)}, ahora)
	casos := map[string]string{
		"no es JSON":    "hola",
		"otro formato":  strings.Replace(string(ok), "macuahuitl-scripts", "otra-cosa", 1),
		"otra versión":  strings.Replace(string(ok), `"version":1`, `"version":2`, 1),
		"campo extraño": strings.Replace(string(ok), `"formato"`, `"extra":1,"formato"`, 1),
		"sin suma":      strings.Replace(string(ok), `"sha256":"`, `"sha256":"00`, 1),
	}
	for nombre, s := range casos {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("%s: debió fallar", nombre)
		}
	}
	// un script inválido dentro de un archivo con suma correcta se rechaza por las reglas del §1
	s := muestra(1)
	s.Commands = []string{"show clóck"}
	b, _ := Marshal([]Script{s}, ahora)
	if _, err := Parse(b); err == nil || !strings.Contains(err.Error(), "ASCII") {
		t.Fatalf("script inválido: %v", err)
	}
	// IDs o nombres repetidos dentro del archivo
	a, c := muestra(1), muestra(2)
	c.ID = a.ID
	b, _ = Marshal([]Script{a, c}, ahora)
	if _, err := Parse(b); err == nil {
		t.Fatal("ID repetido debió fallar")
	}
	c = muestra(2)
	c.Name = a.Name
	b, _ = Marshal([]Script{a, c}, ahora)
	if _, err := Parse(b); err == nil {
		t.Fatal("nombre repetido debió fallar")
	}
}

func TestParseVersionFuturaYBasuraAlFinal(t *testing.T) {
	// una versión futura puede traer campos que esta no conoce: debe decir «versión», no «campo desconocido»
	futura := `{"formato":"macuahuitl-scripts","version":2,"exportado":"x","nuevo":true,"scripts":[{"otro":1}],"sha256":"z"}`
	if _, err := Parse([]byte(futura)); err == nil || !strings.Contains(err.Error(), "versión 2 no soportada") {
		t.Fatalf("futura: %v", err)
	}
	if _, err := Parse([]byte(`{"formato":"otra","version":1}`)); err == nil || !strings.Contains(err.Error(), "formato") {
		t.Fatalf("formato: %v", err)
	}
	ok, _ := Marshal([]Script{muestra(1)}, ahora)
	for _, basura := range []string{"{}", "x", " [1]"} {
		if _, err := Parse(append(append([]byte{}, ok...), basura...)); err == nil {
			t.Errorf("basura %q al final debió fallar", basura)
		}
	}
	if _, err := Parse(append(append([]byte{}, ok...), " \n"...)); err != nil {
		t.Fatalf("espacio al final es válido: %v", err)
	}
}

func TestParseNombresSigmaRepetidos(t *testing.T) {
	a, b := muestra(1), muestra(2)
	a.Name, b.Name = "aς", "aσ"
	raw, _ := Marshal([]Script{a, b}, ahora)
	if _, err := Parse(raw); err == nil || !strings.Contains(err.Error(), "repetido") {
		t.Fatalf("sigma: %v", err)
	}
}

func TestParseTopes(t *testing.T) {
	if _, err := Parse(make([]byte, MaxImportBytes+1)); err == nil || !strings.Contains(err.Error(), "MB") {
		t.Fatalf("tamaño: %v", err)
	}
	var muchos []Script
	for i := 0; i < MaxImportScripts+1; i++ {
		muchos = append(muchos, muestra(i))
	}
	b, _ := Marshal(muchos, ahora)
	if _, err := Parse(b); err == nil || !strings.Contains(err.Error(), "1000") {
		t.Fatalf("cantidad: %v", err)
	}
	// con 1000 exactos pasa
	b, _ = Marshal(muchos[:MaxImportScripts], ahora)
	if _, err := Parse(b); err != nil {
		t.Fatalf("1000: %v", err)
	}
}

// La suma es opcional: sin ella se valida campo por campo y se avisa; con una que no coincide, se rechaza.
func TestSumaOpcionalEnScripts(t *testing.T) {
	s := muestra(1)
	ok, _ := Marshal([]Script{s}, ahora)
	quita := func(b []byte) []byte {
		i := strings.Index(string(b), `,"sha256"`)
		return []byte(string(b[:i]) + "}")
	}
	sin := quita(ok)
	got, avisos, err := ParseAvisos(sin)
	if err != nil || len(got) != 1 || len(avisos) != 1 || avisos[0] != AvisoSinSuma {
		t.Fatalf("sin suma: %v %v %v", got, avisos, err)
	}
	if _, err := Parse(sin); err != nil {
		t.Errorf("Parse sin suma: %v", err)
	}
	// vacía vale como ausente
	vacia := []byte(string(sin[:len(sin)-1]) + `,"sha256":""}`)
	if _, avisos, err := ParseAvisos(vacia); err != nil || len(avisos) != 1 {
		t.Errorf("suma vacía: %v %v", avisos, err)
	}
	// con la suma correcta no hay aviso; con una que no coincide, error
	if _, avisos, err := ParseAvisos(ok); err != nil || len(avisos) != 0 {
		t.Errorf("con suma: %v %v", avisos, err)
	}
	if _, _, err := ParseAvisos([]byte(strings.Replace(string(ok), `"sha256":"`, `"sha256":"00`, 1))); err == nil || !strings.Contains(err.Error(), "suma") {
		t.Errorf("suma mala: %v", err)
	}
	// sin suma se valida igual cada campo
	malo := muestra(2)
	malo.Commands = []string{"show clóck"}
	b, _ := Marshal([]Script{malo}, ahora)
	if _, _, err := ParseAvisos(quita(b)); err == nil || !strings.Contains(err.Error(), "ASCII") {
		t.Errorf("script inválido sin suma: %v", err)
	}
	// y un byte cambiado sin suma ya no se detecta, pero IDs repetidos sí
	c := muestra(3)
	c.ID = s.ID
	b, _ = Marshal([]Script{s, c}, ahora)
	if _, _, err := ParseAvisos(quita(b)); err == nil {
		t.Error("ID repetido sin suma debió fallar")
	}
}

func TestSumaOpcionalEnColecciones(t *testing.T) {
	s1 := muestra(1)
	c := col("Una", s1.ID)
	ok, _ := MarshalColecciones([]Coleccion{c}, []Script{s1}, ahora)
	i := strings.Index(string(ok), `,"sha256"`)
	sin := []byte(string(ok[:i]) + "}")
	cols, scs, avisos, err := ParseColeccionesAvisos(sin)
	if err != nil || len(cols) != 1 || len(scs) != 1 || len(avisos) != 1 || avisos[0] != AvisoSinSuma {
		t.Fatalf("sin suma: %v %v %v %v", cols, scs, avisos, err)
	}
	if _, _, avisos, err := ParseColeccionesAvisos(ok); err != nil || len(avisos) != 0 {
		t.Errorf("con suma: %v %v", avisos, err)
	}
	if _, _, _, err := ParseColeccionesAvisos([]byte(strings.Replace(string(ok), `"sha256":"`, `"sha256":"00`, 1))); err == nil {
		t.Error("suma mala debió fallar")
	}
	// sin suma se sigue exigiendo que las referencias viajen
	m, _ := MarshalColecciones([]Coleccion{col("X", NewID())}, nil, ahora)
	j := strings.Index(string(m), `,"sha256"`)
	if _, _, _, err := ParseColeccionesAvisos([]byte(string(m[:j]) + "}")); err == nil {
		t.Error("referencia que no viaja, sin suma, debió fallar")
	}
}
