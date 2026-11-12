package scripts

import (
	"strings"
	"testing"
	"time"
)

func col(nombre string, ids ...string) Coleccion {
	return Coleccion{ID: NewID(), Name: nombre, ScriptIDs: ids, CreatedAt: ahora, UpdatedAt: ahora}
}

func favoritos(ids ...string) Coleccion {
	return Coleccion{ID: FavoritosID, Name: FavoritosNombre, ScriptIDs: ids, CreatedAt: ahora, UpdatedAt: ahora}
}

func TestColeccionValidate(t *testing.T) {
	u := NewID()
	ok := col("Mi lista", u, "lib-l2-stp")
	if err := ok.Validate(); err != nil {
		t.Fatalf("válida: %v", err)
	}
	if err := favoritos(u).Validate(); err != nil {
		t.Fatalf("favoritos: %v", err)
	}
	malas := map[string]Coleccion{
		"nombre vacío":           col(""),
		"nombre con espacios":    col(" x"),
		"nombre largo":           col(strings.Repeat("a", MaxName+1)),
		"descripción larga":      con2(ok, func(c *Coleccion) { c.Description = strings.Repeat("a", MaxDescription+1) }),
		"id inválido":            con2(ok, func(c *Coleccion) { c.ID = "xyz" }),
		"script repetido":        col("a", u, u),
		"script con id inválido": col("a", "no-es-un-id"),
		"favoritos renombrada":   con2(favoritos(), func(c *Coleccion) { c.Name = "Otra" }),
		"demasiados scripts": con2(ok, func(c *Coleccion) {
			c.ScriptIDs = nil
			for i := 0; i < MaxScriptsColeccion+1; i++ {
				c.ScriptIDs = append(c.ScriptIDs, NewID())
			}
		}),
	}
	for n, c := range malas {
		if c.Validate() == nil {
			t.Errorf("%s: debió fallar", n)
		}
	}
}

func con2(c Coleccion, f func(*Coleccion)) Coleccion {
	c.ScriptIDs = append([]string{}, c.ScriptIDs...)
	f(&c)
	return c
}

func TestPlanColecciones(t *testing.T) {
	u1, u2 := NewID(), NewID()
	a, b, c := col("A", u1), col("B", u1, u2), col("C", u2)
	locales := []Coleccion{favoritos("lib-x"), a, b, c}
	entrante := []Coleccion{
		col("Nueva", u1), // 0 nueva
		a,                // 1 igual
		con2(b, func(c *Coleccion) { c.ScriptIDs = []string{u2} }), // 2 mismo ID, otro contenido
		col("c", u1),                // 3 otro ID, mismo nombre sin importar mayúsculas
		favoritos("lib-x"),          // 4 favoritos sin nada que agregar
		favoritos("lib-x", "lib-y"), // 5 favoritos con algo que agregar
		col("favoritos", u1),        // 6 otro ID con el nombre de favoritos
	}
	got := PlanColecciones(entrante, locales)
	want := []string{ColNueva, Igual, ConflictoID, ConflictoNombre, Igual, ColFusionar, ConflictoNombre}
	for i, w := range want {
		if got[i].Estado != w {
			t.Errorf("item %d: estado %q, quiero %q", i, got[i].Estado, w)
		}
	}
	if got[2].Con != b.ID || got[3].Con != c.ID || got[5].Con != FavoritosID || got[6].Con != FavoritosID || got[0].Con != "" {
		t.Errorf("con = %q %q %q %q %q", got[0].Con, got[2].Con, got[3].Con, got[5].Con, got[6].Con)
	}
}

func applyCol(t *testing.T, entrante, locales []Coleccion, dec map[string]string, mapa map[string]string) (ResultadoCol, error) {
	t.Helper()
	return ApplyColecciones(PlanColecciones(entrante, locales), dec, locales, mapa, map[string]bool{"lib-x": true}, ahora.Add(time.Hour))
}

func TestApplyColeccionesDecisiones(t *testing.T) {
	u1 := NewID()
	a := col("A", u1)
	nueva := col("Nueva", u1, "lib-x")
	choca := col("a", u1) // choca por nombre con A
	idem := con2(a, func(c *Coleccion) { c.Description = "otra" })
	mapa := map[string]string{u1: u1}

	// sin decisión para un conflicto: error y nada
	if _, err := applyCol(t, []Coleccion{choca}, []Coleccion{a}, nil, mapa); err == nil || !strings.Contains(err.Error(), "falta") {
		t.Fatalf("sin decisión: %v", err)
	}
	r, err := applyCol(t, []Coleccion{nueva, choca}, []Coleccion{a}, map[string]string{choca.ID: Renombrar}, mapa)
	if err != nil || r.Created != 1 || r.Renamed != 1 || len(r.Writes) != 2 {
		t.Fatalf("nueva+renombrar: %+v %v", r, err)
	}
	if r.Writes[0].ID != nueva.ID || r.Writes[1].ID == choca.ID || r.Writes[1].Name != "a (importado)" {
		t.Errorf("escrituras: %+v", r.Writes)
	}
	// reemplazar conserva el ID y la fecha de creación locales
	r, err = applyCol(t, []Coleccion{idem}, []Coleccion{a}, map[string]string{idem.ID: Reemplazar}, mapa)
	if err != nil || r.Replaced != 1 || r.Writes[0].ID != a.ID || r.Writes[0].Description != "otra" || !r.Writes[0].CreatedAt.Equal(a.CreatedAt) {
		t.Fatalf("reemplazar: %+v %v", r, err)
	}
	// omitir un conflicto y una nueva
	r, err = applyCol(t, []Coleccion{choca, nueva}, []Coleccion{a}, map[string]string{choca.ID: Omitir, nueva.ID: Omitir}, mapa)
	if err != nil || r.Skipped != 2 || len(r.Writes) != 0 {
		t.Fatalf("omitir: %+v %v", r, err)
	}
	// «igual» se salta solo
	if r, err = applyCol(t, []Coleccion{a}, []Coleccion{a}, nil, mapa); err != nil || r.Skipped != 1 || len(r.Writes) != 0 {
		t.Fatalf("igual: %+v %v", r, err)
	}
}

func TestApplyColeccionesErrores(t *testing.T) {
	u1 := NewID()
	a := col("A", u1)
	choca := col("a", u1)
	nueva := col("Nueva", u1)
	mapa := map[string]string{u1: u1}
	casos := map[string]map[string]string{
		"acción desconocida":      {choca.ID: "fusionar"},
		"decisión de un ID ajeno": {NewID(): Omitir},
		"reemplazar una nueva":    {nueva.ID: Reemplazar, choca.ID: Omitir},
		"renombrar una nueva":     {nueva.ID: Renombrar, choca.ID: Omitir},
	}
	for n, dec := range casos {
		if _, err := applyCol(t, []Coleccion{nueva, choca}, []Coleccion{a}, dec, mapa); err == nil {
			t.Errorf("%s: debió fallar", n)
		}
	}
}

// Mismo escenario del revisor de 28c: dos reemplazos sobre la misma colección local.
func TestApplyColeccionesDosReemplazosSobreLaMisma(t *testing.T) {
	u1 := NewID()
	n := col("N", u1)
	f1 := Coleccion{ID: n.ID, Name: "M", ScriptIDs: []string{u1}, CreatedAt: ahora, UpdatedAt: ahora} // mismo ID, otro nombre
	f2 := col("n", u1)                                                                                // otro ID, mismo nombre
	_, err := applyCol(t, []Coleccion{f1, f2}, []Coleccion{n}, map[string]string{f1.ID: Reemplazar, f2.ID: Reemplazar}, map[string]string{u1: u1})
	if err == nil || !strings.Contains(err.Error(), "misma") {
		t.Fatalf("doble reemplazo: %v", err)
	}
	// un reemplazo que dejaría dos con el mismo nombre
	otra := col("Otra", u1)
	f3 := Coleccion{ID: n.ID, Name: "OTRA", ScriptIDs: []string{u1}, CreatedAt: ahora, UpdatedAt: ahora}
	if _, err = applyCol(t, []Coleccion{f3}, []Coleccion{n, otra}, map[string]string{f3.ID: Reemplazar}, map[string]string{u1: u1}); err == nil {
		t.Fatal("reemplazar tomando el nombre de otra colección debió fallar")
	}
}

func TestApplyColeccionesRenombreEvitaNombresDelArchivoYSigma(t *testing.T) {
	u1 := NewID()
	a := col("aς", u1)
	choca := col("aσ", u1)             // choca con «aς» por la clave de nombre
	ocupa := col("aσ (importado)", u1) // el archivo ya usa el nombre al que iría el renombrado
	r, err := applyCol(t, []Coleccion{choca, ocupa}, []Coleccion{a}, map[string]string{choca.ID: Renombrar}, map[string]string{u1: u1})
	if err != nil {
		t.Fatal(err)
	}
	if r.Writes[0].Name != "aσ (importado 2)" {
		t.Errorf("nombre = %q", r.Writes[0].Name)
	}
}

func TestApplyColeccionesFavoritosSeFusionaYNuncaSeReemplaza(t *testing.T) {
	u1, u2 := NewID(), NewID()
	local := favoritos(u1, "lib-x")
	mapa := map[string]string{u1: u1, u2: u2}
	fav := favoritos(u2, u1, "lib-x") // u2 falta, el resto ya está
	r, err := applyCol(t, []Coleccion{fav}, []Coleccion{local}, nil, mapa)
	if err != nil || r.Merged != 1 || len(r.Writes) != 1 {
		t.Fatalf("fusión: %+v %v", r, err)
	}
	w := r.Writes[0]
	if w.ID != FavoritosID || strings.Join(w.ScriptIDs, ",") != strings.Join([]string{u1, "lib-x", u2}, ",") {
		t.Errorf("fusionada = %+v", w)
	}
	for _, a := range []string{Reemplazar, Renombrar} {
		if _, err := applyCol(t, []Coleccion{fav}, []Coleccion{local}, map[string]string{FavoritosID: a}, mapa); err == nil {
			t.Errorf("%s sobre favoritos debió fallar", a)
		}
	}
	// una colección con el nombre «favoritos» y otro ID no la reemplaza (error), pero sí se puede renombrar
	falsa := col("FAVORITOS", u2)
	if _, err := applyCol(t, []Coleccion{falsa}, []Coleccion{local}, map[string]string{falsa.ID: Reemplazar}, mapa); err == nil {
		t.Error("reemplazar favoritos con otra colección debió fallar")
	}
	r, err = applyCol(t, []Coleccion{falsa}, []Coleccion{local}, map[string]string{falsa.ID: Renombrar}, mapa)
	if err != nil || r.Writes[0].Name != "FAVORITOS (importado)" {
		t.Fatalf("renombrar: %+v %v", r, err)
	}
	// fusionar con omitir
	if r, err = applyCol(t, []Coleccion{fav}, []Coleccion{local}, map[string]string{FavoritosID: Omitir}, mapa); err != nil || r.Skipped != 1 || len(r.Writes) != 0 {
		t.Fatalf("omitir fusión: %+v %v", r, err)
	}
}

func TestApplyColeccionesReflejaIDsYAvisa(t *testing.T) {
	enArchivo, reasignado, omitido, nuevoID := NewID(), NewID(), NewID(), NewID()
	c := col("C", enArchivo, reasignado, omitido, "lib-x", "lib-no-existe")
	mapa := map[string]string{enArchivo: enArchivo, reasignado: nuevoID}
	r, err := applyCol(t, []Coleccion{c}, nil, nil, mapa)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.Writes[0].ScriptIDs, ","); got != strings.Join([]string{enArchivo, nuevoID, "lib-x"}, ",") {
		t.Errorf("referencias = %s", got)
	}
	if len(r.Warnings) != 2 || !strings.Contains(strings.Join(r.Warnings, "|"), "lib-no-existe") || !strings.Contains(strings.Join(r.Warnings, "|"), omitido) {
		t.Errorf("avisos = %q", r.Warnings)
	}
	// dos referencias que acaban en el mismo ID quedan una sola vez
	d := col("D", enArchivo, reasignado)
	r, err = applyCol(t, []Coleccion{d}, nil, nil, map[string]string{enArchivo: nuevoID, reasignado: nuevoID})
	if err != nil || strings.Join(r.Writes[0].ScriptIDs, ",") != nuevoID {
		t.Errorf("duplicados: %+v %v", r.Writes, err)
	}
}

func TestColeccionesExportParseIdaYVuelta(t *testing.T) {
	s1, s2, s3 := muestra(1), muestra(2), muestra(3)
	c1 := col("Una", s1.ID, "lib-l2-stp", s2.ID)
	c2 := col("Otra", s3.ID)
	b, err := MarshalColecciones([]Coleccion{favoritos(s1.ID), c1, c2}, []Script{s1, s2, s3}, ahora)
	if err != nil {
		t.Fatal(err)
	}
	cols, scs, err := ParseColecciones(b)
	if err != nil || len(cols) != 3 || len(scs) != 3 {
		t.Fatalf("cols=%d scs=%d err=%v", len(cols), len(scs), err)
	}
	if cols[1].ID != c1.ID || strings.Join(cols[1].ScriptIDs, ",") != strings.Join(c1.ScriptIDs, ",") || !Same(scs[0], s1) {
		t.Errorf("cambió: %+v", cols[1])
	}
	// reindentado
	if _, _, err := ParseColecciones([]byte(strings.Replace(string(b), `"scripts":[`, "\"scripts\":[\n", 1))); err != nil {
		t.Errorf("espacio en blanco: %v", err)
	}
	// un archivo de scripts no es un archivo de colecciones, ni al revés
	sb, _ := Marshal([]Script{s1}, ahora)
	if _, _, err := ParseColecciones(sb); err == nil {
		t.Error("un archivo de scripts no debe valer")
	}
	if _, err := Parse(b); err == nil {
		t.Error("un archivo de colecciones no debe valer como de scripts")
	}
}

func TestParseColeccionesRechazos(t *testing.T) {
	s1 := muestra(1)
	c := col("Una", s1.ID)
	ok, _ := MarshalColecciones([]Coleccion{c}, []Script{s1}, ahora)
	casos := map[string]string{
		"un byte cambiado en una colección": strings.Replace(string(ok), `"Una"`, `"Unb"`, 1),
		"un byte cambiado en un script":     strings.Replace(string(ok), "show ip route", "show ip rout3", 1),
		"otra versión":                      strings.Replace(string(ok), `"version":1`, `"version":2`, 1),
		"campo extraño":                     strings.Replace(string(ok), `"formato"`, `"extra":1,"formato"`, 1),
		"basura al final":                   string(ok) + "{}",
	}
	for n, s := range casos {
		if _, _, err := ParseColecciones([]byte(s)); err == nil {
			t.Errorf("%s: debió fallar", n)
		}
	}
	malos := map[string]struct {
		cols []Coleccion
		scs  []Script
	}{
		"referencia a un script que no viaja":    {[]Coleccion{col("X", NewID())}, nil},
		"script de biblioteca dentro de scripts": {[]Coleccion{col("X")}, []Script{{ID: "lib-l2-stp", Name: "L2", Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}, Tags: []string{}, Origin: OrigenBiblioteca}}},
		"nombre repetido":                        {[]Coleccion{col("X"), col("x")}, nil},
		"ID repetido":                            {[]Coleccion{c, c}, []Script{s1}},
		"colección inválida":                     {[]Coleccion{col("")}, nil},
		"script inválido":                        {[]Coleccion{col("X", s1.ID)}, []Script{con(s1, func(s *Script) { s.Commands = []string{"show clóck"} })}},
	}
	for n, m := range malos {
		b, err := MarshalColecciones(m.cols, m.scs, ahora)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := ParseColecciones(b); err == nil {
			t.Errorf("%s: debió fallar", n)
		}
	}
	if _, _, err := ParseColecciones(make([]byte, MaxImportBytes+1)); err == nil || !strings.Contains(err.Error(), "MB") {
		t.Errorf("tamaño: %v", err)
	}
	var muchas []Coleccion
	for i := 0; i < MaxColecciones+1; i++ {
		muchas = append(muchas, col(strings.Repeat("c", 1)+string(rune('a'+i%26))+strings.Repeat("z", i/26)))
	}
	b, _ := MarshalColecciones(muchas, nil, ahora)
	if _, _, err := ParseColecciones(b); err == nil || !strings.Contains(err.Error(), "100") {
		t.Errorf("cantidad: %v", err)
	}
}

// Favoritos se compara con los IDs del archivo, pero se fusiona con los ya traducidos: un script que cambió de ID
// al importar entra aunque el plan haya dicho «igual».
func TestApplyColeccionesFavoritosFusionaConLosIDsTraducidos(t *testing.T) {
	x, y := NewID(), NewID()
	local := favoritos(x)
	fav := favoritos(x) // igual por los IDs del archivo
	if p := PlanColecciones([]Coleccion{fav}, []Coleccion{local}); p[0].Estado != Igual {
		t.Fatalf("estado = %s", p[0].Estado)
	}
	r, err := applyCol(t, []Coleccion{fav}, []Coleccion{local}, nil, map[string]string{x: y})
	if err != nil || r.Merged != 1 || len(r.Writes) != 1 || strings.Join(r.Writes[0].ScriptIDs, ",") != x+","+y {
		t.Fatalf("fusión: %+v %v", r, err)
	}
	// con omitir no se toca, y si la traducción no agrega nada es una omisión
	if r, err = applyCol(t, []Coleccion{fav}, []Coleccion{local}, map[string]string{FavoritosID: Omitir}, map[string]string{x: y}); err != nil || r.Skipped != 1 || len(r.Writes) != 0 {
		t.Fatalf("omitir: %+v %v", r, err)
	}
	if r, err = applyCol(t, []Coleccion{fav}, []Coleccion{local}, nil, map[string]string{x: x}); err != nil || r.Skipped != 1 || len(r.Writes) != 0 {
		t.Fatalf("sin novedades: %+v %v", r, err)
	}
}
