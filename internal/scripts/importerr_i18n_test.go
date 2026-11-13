package scripts

import (
	"regexp"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

var hex32 = regexp.MustCompile(`[0-9a-f]{32}`)

// erroresImport arma cada error de importación de scripts y colecciones; los ID aleatorios se enmascaran.
// Devuelve el error y su texto en es.
func erroresImport(t *testing.T) (map[string]string, map[string]error) {
	t.Helper()
	texts, errs := map[string]string{}, map[string]error{}
	put := func(n string, err error) {
		if err == nil {
			t.Errorf("%s: debió fallar", n)
			return
		}
		errs[n] = err
		texts[n] = hex32.ReplaceAllString(err.Error(), "<ID>")
	}
	// scripts (Apply)
	a, b := muestra(1), muestra(2)
	guardados := []Script{a, b}
	cid := con(a, func(s *Script) { s.Commands = []string{"show clock"} })
	items := Plan([]Script{cid}, guardados, nil)
	_, err := Apply(items, nil, guardados, nil, ahora)
	put("apply-falta", err)
	_, err = Apply(items, map[string]string{cid.ID: "fusionar"}, guardados, nil, ahora)
	put("apply-desconocida", err)
	_, err = Apply(items, map[string]string{cid.ID: Omitir, "otro": Omitir}, guardados, nil, ahora)
	put("apply-id-ajeno", err)
	n := muestra(5)
	_, err = Apply(Plan([]Script{n}, guardados, nil), map[string]string{n.ID: Reemplazar}, guardados, nil, ahora)
	put("apply-solo-omitir", err)
	choca := con(a, func(s *Script) { s.Name = b.Name; s.Commands = []string{"show clock"} })
	_, err = Apply(Plan([]Script{choca}, guardados, nil), map[string]string{a.ID: Reemplazar}, guardados, nil, ahora)
	put("apply-nombre-dos", err)
	dup1, dup2 := con(a, func(s *Script) { s.Commands = []string{"show clock"} }), con(a, func(s *Script) { s.Commands = []string{"show vlan"} })
	dup2.ID = NewID()
	dup2.Name = a.Name
	itemsDup := []Item{{Script: dup1, Estado: ConflictoID, Con: a.ID}, {Script: dup2, Estado: ConflictoNombre, Con: a.ID}}
	_, err = Apply(itemsDup, map[string]string{dup1.ID: Reemplazar, dup2.ID: Reemplazar}, []Script{a}, nil, ahora)
	put("apply-dos-reemplazos", err)
	lib := Script{ID: "lib-x", Name: "Lib", Tech: "l3", Platform: "ios-xe", Commands: []string{"show clock"}, Tags: []string{}, Origin: OrigenBiblioteca}
	libItem := []Item{{Script: con(muestra(7), func(s *Script) { s.Name = "Lib" }), Estado: ConflictoNombre, Con: "lib-x"}}
	_, err = Apply(libItem, map[string]string{libItem[0].Script.ID: Reemplazar}, nil, []Script{lib}, ahora)
	put("apply-biblioteca", err)
	nuevo := []Item{{Script: muestra(8), Estado: Nuevo}}
	_, err = Apply(nuevo, nil, []Script{con(muestra(9), func(s *Script) { s.Name = nuevo[0].Script.Name })}, nil, ahora)
	put("apply-nombre-existe", err)
	malo := muestra(10)
	malo.Commands = []string{"show clóck"}
	_, err = Apply([]Item{{Script: malo, Estado: Nuevo}}, nil, nil, nil, ahora)
	put("apply-invalido", err)
	// scripts (Parse)
	_, err = Parse(make([]byte, MaxImportBytes+1))
	put("parse-5mb", err)
	_, err = Parse([]byte("no es json"))
	put("parse-no-json", err)
	_, err = Parse([]byte(`{"formato":"otra","version":1}`))
	put("parse-formato", err)
	_, err = Parse([]byte(`{"formato":"macuahuitl-scripts","version":2}`))
	put("parse-version", err)
	ok, _ := Marshal([]Script{muestra(1)}, ahora)
	_, err = Parse(append(append([]byte{}, ok...), "{}"...))
	put("parse-basura", err)
	_, err = Parse([]byte(`{"formato":"macuahuitl-scripts","version":1,"scripts":5}`))
	put("parse-ilegibles", err)
	_, err = Parse([]byte(strings.Replace(string(ok), `"script 01"`, `"script 99"`, 1)))
	put("parse-suma", err)
	var muchos []Script
	for i := 0; i < MaxImportScripts+1; i++ {
		muchos = append(muchos, muestra(i))
	}
	bm, _ := Marshal(muchos, ahora)
	_, err = Parse(bm)
	put("parse-tope", err)
	// colecciones
	u1 := NewID()
	ca, cchoca, cnueva := col("A", u1), col("a", u1), col("Nueva", u1)
	mapa := map[string]string{u1: u1}
	_, err = applyCol(t, []Coleccion{cchoca}, []Coleccion{ca}, nil, mapa)
	put("col-falta", err)
	_, err = applyCol(t, []Coleccion{cnueva, cchoca}, []Coleccion{ca}, map[string]string{cchoca.ID: "fusionar"}, mapa)
	put("col-desconocida", err)
	_, err = applyCol(t, []Coleccion{cnueva, cchoca}, []Coleccion{ca}, map[string]string{NewID(): Omitir}, mapa)
	put("col-id-ajeno", err)
	_, err = applyCol(t, []Coleccion{cnueva, cchoca}, []Coleccion{ca}, map[string]string{cnueva.ID: Reemplazar, cchoca.ID: Omitir}, mapa)
	put("col-solo-omitir", err)
	nc := col("N", u1)
	f1 := Coleccion{ID: nc.ID, Name: "M", ScriptIDs: []string{u1}, CreatedAt: ahora, UpdatedAt: ahora}
	f2 := col("n", u1)
	_, err = applyCol(t, []Coleccion{f1, f2}, []Coleccion{nc}, map[string]string{f1.ID: Reemplazar, f2.ID: Reemplazar}, mapa)
	put("col-dos-reemplazos", err)
	otra := col("Otra", u1)
	f3 := Coleccion{ID: nc.ID, Name: "OTRA", ScriptIDs: []string{u1}, CreatedAt: ahora, UpdatedAt: ahora}
	_, err = applyCol(t, []Coleccion{f3}, []Coleccion{nc, otra}, map[string]string{f3.ID: Reemplazar}, mapa)
	put("col-reemplazo-nombre", err)
	falsa := col("FAVORITOS", u1)
	_, err = applyCol(t, []Coleccion{falsa}, []Coleccion{favoritos(u1)}, map[string]string{falsa.ID: Reemplazar}, mapa)
	put("col-favoritos", err)
	s1 := muestra(1)
	okc, _ := MarshalColecciones([]Coleccion{col("Una", s1.ID)}, []Script{s1}, ahora)
	_, _, err = ParseColecciones([]byte(strings.Replace(string(okc), `"version":1`, `"version":2`, 1)))
	put("pcol-version", err)
	_, _, err = ParseColecciones([]byte(strings.Replace(string(okc), `"formato"`, `"extra":1,"formato"`, 1)))
	put("pcol-campo", err)
	_, _, err = ParseColecciones([]byte(string(okc) + "{}"))
	put("pcol-basura", err)
	_, _, err = ParseColecciones(make([]byte, MaxImportBytes+1))
	put("pcol-5mb", err)
	bc, _ := MarshalColecciones([]Coleccion{col("X", NewID())}, nil, ahora)
	_, _, err = ParseColecciones(bc)
	put("pcol-referencia", err)
	bc, _ = MarshalColecciones([]Coleccion{col("X")}, []Script{lib}, ahora)
	_, _, err = ParseColecciones(bc)
	put("pcol-biblioteca", err)
	bc, _ = MarshalColecciones([]Coleccion{col("X"), col("x")}, nil, ahora)
	_, _, err = ParseColecciones(bc)
	put("pcol-nombre-repetido", err)
	return texts, errs
}

func TestErroresImportEspanolRegresion(t *testing.T) {
	texts, _ := erroresImport(t)
	i18ntest.Golden(t, "testdata/importerr_es.golden.json", texts)
}

// Con en, cada error de importación sale en inglés (el texto de sistema del JSON no se traduce).
func TestErroresImportEn(t *testing.T) {
	_, errs := erroresImport(t)
	spanish := regexp.MustCompile(`(?i)[áéíóúñ¿]|\b(decisión|archivo|falta|conflicto|nombre|choca|reemplazan|colecciones|suma|versión|formato|datos|trae|tope|script de la|omitir|omítela|renómbra)\b`)
	for n, err := range errs {
		en := i18n.In("en", err)
		if en == err.Error() || spanish.MatchString(en) {
			t.Errorf("%s: %q", n, en)
		}
		if n == "apply-invalido" && !strings.Contains(en, "printable ASCII") {
			t.Errorf("la causa no se tradujo: %q", en)
		}
	}
	if en := i18n.In("en", errs["parse-version"]); en != "version 2 not supported (only 1)" {
		t.Errorf("version: %q", en)
	}
}
