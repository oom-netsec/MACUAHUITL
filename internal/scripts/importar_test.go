package scripts

import (
	"strings"
	"testing"
	"time"
)

func con(s Script, f func(*Script)) Script {
	c := s
	c.Commands = append([]string{}, s.Commands...)
	f(&c)
	return c
}

func TestPlanEstados(t *testing.T) {
	a, b, c := muestra(1), muestra(2), muestra(3)
	guardados := []Script{a, b, c}
	entrante := []Script{
		muestra(10), // nuevo
		con(a, func(s *Script) { s.UpdatedAt = ahora.Add(time.Hour) }),                                // mismo ID y contenido (las fechas no cuentan)
		con(b, func(s *Script) { s.Commands = []string{"show clock"} }),                               // mismo ID, otro contenido
		con(muestra(11), func(s *Script) { s.Name = "SCRIPT 03" }),                                    // otro ID, mismo nombre (sin importar mayúsculas)
		con(c, func(s *Script) { s.ID, s.Origin = "lib-l2-stp", OrigenBiblioteca; s.Name = "libre" }), // de biblioteca, nombre libre
	}
	entrante[0].Name = "nuevo"
	got := Plan(entrante, guardados, nil)
	want := []string{Nuevo, Igual, ConflictoID, ConflictoNombre, Nuevo}
	for i, w := range want {
		if got[i].Estado != w {
			t.Errorf("item %d: estado %q, quiero %q", i, got[i].Estado, w)
		}
	}
	if got[2].Con != b.ID || got[3].Con != c.ID {
		t.Errorf("con = %q, %q", got[2].Con, got[3].Con)
	}
	// una copia de biblioteca que ya importaste (mismo nombre y contenido) es igual, no un conflicto
	lib := con(c, func(s *Script) { s.ID, s.Origin = "lib-x", OrigenBiblioteca })
	if p := Plan([]Script{lib}, guardados, nil); p[0].Estado != Igual {
		t.Errorf("lib ya importado: %q", p[0].Estado)
	}
	lib.Commands = []string{"show clock"}
	if p := Plan([]Script{lib}, guardados, nil); p[0].Estado != ConflictoNombre {
		t.Errorf("lib distinto: %q", p[0].Estado)
	}
}

func TestApplyDecisiones(t *testing.T) {
	a, b, c := muestra(1), muestra(2), muestra(3)
	a.CreatedAt = ahora.Add(-48 * time.Hour)
	guardados := []Script{a, b, c}
	nuevo := muestra(10)
	cid := con(a, func(s *Script) { s.Commands = []string{"show clock"} }) // conflicto_id con a
	cnom := con(muestra(11), func(s *Script) { s.Name = b.Name })          // conflicto_nombre con b
	cnom2 := con(muestra(12), func(s *Script) { s.Name = c.Name })         // conflicto_nombre con c
	igual := b
	items := Plan([]Script{nuevo, cid, cnom, cnom2, igual}, guardados, nil)
	dec := map[string]string{cid.ID: Reemplazar, cnom.ID: Renombrar, cnom2.ID: Omitir}
	r, err := Apply(items, dec, guardados, nil, ahora)
	if err != nil {
		t.Fatal(err)
	}
	if r.Created != 1 || r.Replaced != 1 || r.Renamed != 1 || r.Skipped != 2 || len(r.Writes) != 3 {
		t.Fatalf("resultado = %+v", r)
	}
	w := map[string]Script{}
	for _, x := range r.Writes {
		w[x.ID] = x
		if x.Origin != OrigenUsuario || x.Validate() != nil {
			t.Errorf("write inválido: %+v (%v)", x, x.Validate())
		}
	}
	if nuevo := w[nuevo.ID]; nuevo.Name != "script 10" || !nuevo.CreatedAt.Equal(ahora) {
		t.Errorf("nuevo = %+v", nuevo)
	}
	// reemplazar conserva el ID guardado y su fecha de creación, y cambia el contenido
	if x := w[a.ID]; x.Commands[0] != "show clock" || !x.CreatedAt.Equal(a.CreatedAt) || !x.UpdatedAt.Equal(ahora) {
		t.Errorf("reemplazo = %+v", x)
	}
	// renombrar: ID nuevo y «(importado)»
	var ren Script
	for id, x := range w {
		if strings.HasSuffix(x.Name, "(importado)") {
			ren = x
			if id == cnom.ID {
				t.Error("renombrar debe dar un ID nuevo")
			}
		}
	}
	if ren.Name != b.Name+" (importado)" {
		t.Errorf("renombrado = %q", ren.Name)
	}
}

func TestApplyErrores(t *testing.T) {
	a := muestra(1)
	guardados := []Script{a}
	cid := con(a, func(s *Script) { s.Commands = []string{"show clock"} })
	items := Plan([]Script{cid}, guardados, nil)
	if _, err := Apply(items, nil, guardados, nil, ahora); err == nil || !strings.Contains(err.Error(), "decisión") {
		t.Fatalf("falta decisión: %v", err)
	}
	if _, err := Apply(items, map[string]string{cid.ID: "fusionar"}, guardados, nil, ahora); err == nil {
		t.Fatal("acción desconocida debió fallar")
	}
	if _, err := Apply(items, map[string]string{cid.ID: Omitir, "otro": Omitir}, guardados, nil, ahora); err == nil {
		t.Fatal("decisión de un ID que no está en el archivo debió fallar")
	}
	n := muestra(5)
	items = Plan([]Script{n}, guardados, nil)
	if _, err := Apply(items, map[string]string{n.ID: Reemplazar}, guardados, nil, ahora); err == nil {
		t.Fatal("reemplazar un script nuevo no tiene sentido")
	}
	if r, err := Apply(items, map[string]string{n.ID: Omitir}, guardados, nil, ahora); err != nil || r.Skipped != 1 || len(r.Writes) != 0 {
		t.Fatalf("omitir un nuevo: %+v %v", r, err)
	}
	// reemplazar que dejaría dos scripts con el mismo nombre
	b := muestra(2)
	guardados = []Script{a, b}
	choca := con(a, func(s *Script) { s.Name = b.Name; s.Commands = []string{"show clock"} })
	items = Plan([]Script{choca}, guardados, nil)
	if _, err := Apply(items, map[string]string{a.ID: Reemplazar}, guardados, nil, ahora); err == nil || !strings.Contains(err.Error(), "nombre") {
		t.Fatalf("nombre repetido: %v", err)
	}
}

// Un script de la biblioteca de otra persona llega como script del usuario con un ID propio.
func TestApplyDaIDNuevoALosDeBiblioteca(t *testing.T) {
	lib := con(muestra(1), func(s *Script) { s.ID, s.Origin = "lib-l2-stp", OrigenBiblioteca })
	items := Plan([]Script{lib}, nil, nil)
	r, err := Apply(items, nil, nil, nil, ahora)
	if err != nil || len(r.Writes) != 1 || IsLib(r.Writes[0].ID) || r.Writes[0].Origin != OrigenUsuario || r.Created != 1 {
		t.Fatalf("r = %+v err = %v", r, err)
	}
	// y renombrar un conflicto de nombre con uno de biblioteca también
	g := muestra(2)
	choca := con(lib, func(s *Script) { s.Name = g.Name })
	r, err = Apply(Plan([]Script{choca}, []Script{g}, nil), map[string]string{"lib-l2-stp": Renombrar}, []Script{g}, nil, ahora)
	if err != nil || IsLib(r.Writes[0].ID) {
		t.Fatalf("renombrar: %+v %v", r, err)
	}
}

// Dos «reemplazar» sobre el mismo guardado: el segundo pisaría al primero en silencio.
func TestApplyDosReemplazosAlMismoDestino(t *testing.T) {
	a := muestra(1)
	f1 := con(a, func(s *Script) { s.Name = "M"; s.Commands = []string{"show clock"} }) // conflicto_id con a
	f2 := con(muestra(2), func(s *Script) { s.Name = a.Name })                          // conflicto_nombre con a
	items := Plan([]Script{f1, f2}, []Script{a}, nil)
	if items[0].Estado != ConflictoID || items[1].Estado != ConflictoNombre || items[1].Con != a.ID {
		t.Fatalf("estados = %+v", items)
	}
	_, err := Apply(items, map[string]string{f1.ID: Reemplazar, f2.ID: Reemplazar}, []Script{a}, nil, ahora)
	if err == nil || !strings.Contains(err.Error(), "mismo") {
		t.Fatalf("err = %v", err)
	}
	// con una sola de las dos como reemplazo, la otra renombrada, sí
	if r, err := Apply(items, map[string]string{f1.ID: Reemplazar, f2.ID: Renombrar}, []Script{a}, nil, ahora); err != nil || r.Replaced != 1 || r.Renamed != 1 {
		t.Fatalf("r = %+v err = %v", r, err)
	}
}

// El nombre renombrado no puede chocar con otro del mismo archivo.
func TestApplyRenombreEvitaNombresDelArchivo(t *testing.T) {
	g := muestra(1)
	g.Name = "Foo"
	f1 := con(muestra(2), func(s *Script) { s.Name = "Foo" })
	f2 := con(muestra(3), func(s *Script) { s.Name = "Foo (importado)" })
	items := Plan([]Script{f1, f2}, []Script{g}, nil)
	r, err := Apply(items, map[string]string{f1.ID: Renombrar}, []Script{g}, nil, ahora)
	if err != nil || len(r.Writes) != 2 {
		t.Fatalf("r = %+v err = %v", r, err)
	}
	nombres := map[string]bool{}
	for _, w := range r.Writes {
		if nombres[NameKey(w.Name)] {
			t.Fatalf("nombre repetido %q", w.Name)
		}
		nombres[NameKey(w.Name)] = true
	}
	if !nombres[NameKey("Foo (importado 2)")] {
		t.Errorf("nombres = %v", nombres)
	}
}

func TestPlanYApplyContraLaBibliotecaLocal(t *testing.T) {
	lib := con(muestra(1), func(s *Script) { s.ID, s.Origin, s.Name = "lib-l2-stp", OrigenBiblioteca, "L2 · STP" })
	// el mismo script de biblioteca de otra instalación: igual, aunque no haya copia propia
	if p := Plan([]Script{lib}, nil, []Script{lib}); p[0].Estado != Igual {
		t.Fatalf("lib igual a la local: %q", p[0].Estado)
	}
	// una versión distinta con el mismo nombre choca con la biblioteca, que no se reemplaza
	otra := con(lib, func(s *Script) { s.Commands = []string{"show clock"} })
	p := Plan([]Script{otra}, nil, []Script{lib})
	if p[0].Estado != ConflictoNombre || p[0].Con != lib.ID {
		t.Fatalf("lib distinta: %+v", p[0])
	}
	if _, err := Apply(p, map[string]string{otra.ID: Reemplazar}, nil, []Script{lib}, ahora); err == nil || !strings.Contains(err.Error(), "biblioteca") {
		t.Fatalf("reemplazar la biblioteca: %v", err)
	}
	r, err := Apply(p, map[string]string{otra.ID: Renombrar}, nil, []Script{lib}, ahora)
	if err != nil || r.Writes[0].Name != "L2 · STP (importado)" || IsLib(r.Writes[0].ID) {
		t.Fatalf("renombrar: %+v %v", r, err)
	}
	// un script de usuario con el nombre de uno de la biblioteca también choca con ella
	u := con(muestra(2), func(s *Script) { s.Name = lib.Name })
	if p := Plan([]Script{u}, nil, []Script{lib}); p[0].Estado != ConflictoNombre || p[0].Con != lib.ID {
		t.Fatalf("usuario con nombre de biblioteca: %+v", p[0])
	}
	// y un «nuevo» nunca toma un nombre reservado por la biblioteca
	if _, err := Apply([]Item{{Script: u, Estado: Nuevo}}, nil, nil, []Script{lib}, ahora); err == nil {
		t.Fatal("un nuevo con nombre de biblioteca debió fallar")
	}
}

func TestNombreLibre(t *testing.T) {
	tomados := map[string]bool{"x (importado)": true, "x (importado 2)": true}
	usado := func(n string) bool { return tomados[n] }
	if got := NombreLibre("x", "importado", usado); got != "x (importado 3)" {
		t.Errorf("got %q", got)
	}
	if got := NombreLibre("y", "importado", usado); got != "y (importado)" {
		t.Errorf("got %q", got)
	}
	largo := strings.Repeat("n", 64)
	if got := NombreLibre(largo, "copia", func(string) bool { return false }); len([]rune(got)) > MaxName || !strings.HasSuffix(got, " (copia)") {
		t.Errorf("largo: %q", got)
	}
}

// Resultado.IDs dice en qué ID quedó cada script del archivo: lo usan las colecciones importadas.
func TestApplyDevuelveElMapaDeIDs(t *testing.T) {
	a, b := muestra(1), muestra(2)
	guardados := []Script{a, b}
	nuevo := muestra(10)
	cid := con(a, func(s *Script) { s.Commands = []string{"show clock"} })                                         // reemplazar: queda en a.ID
	cnom := con(muestra(11), func(s *Script) { s.Name = b.Name })                                                  // renombrar: ID nuevo
	omitido := con(muestra(12), func(s *Script) { s.Name = muestra(3).Name; s.Commands = []string{"show users"} }) // nuevo, pero se omite
	libNuevo := con(muestra(13), func(s *Script) { s.ID, s.Origin, s.Name = "lib-otra-instalacion", OrigenBiblioteca, "de otra" })
	igual := b
	items := Plan([]Script{nuevo, cid, cnom, omitido, libNuevo, igual}, guardados, nil)
	r, err := Apply(items, map[string]string{cid.ID: Reemplazar, cnom.ID: Renombrar, omitido.ID: Omitir}, guardados, nil, ahora)
	if err != nil {
		t.Fatal(err)
	}
	if r.IDs[nuevo.ID] != nuevo.ID || r.IDs[cid.ID] != a.ID || r.IDs[igual.ID] != b.ID {
		t.Errorf("mapa = %v", r.IDs)
	}
	if id := r.IDs[cnom.ID]; id == "" || id == cnom.ID || id == b.ID {
		t.Errorf("renombrado: %q", id)
	}
	if id := r.IDs[libNuevo.ID]; id == "" || IsLib(id) {
		t.Errorf("lib de otra instalación debe recibir un ID de usuario: %q", id)
	}
	if _, ok := r.IDs[omitido.ID]; ok {
		t.Error("un script omitido no entra al mapa")
	}
	// lo que está en el mapa existe entre las escrituras o ya estaba guardado
	esc := map[string]bool{a.ID: true, b.ID: true}
	for _, w := range r.Writes {
		esc[w.ID] = true
	}
	for k, v := range r.IDs {
		if !esc[v] {
			t.Errorf("%s -> %s no existe", k, v)
		}
	}
}
