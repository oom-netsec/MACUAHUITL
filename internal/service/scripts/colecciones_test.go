package scripts

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/pack"
	"github.com/oom-netsec/MACUAHUITL/internal/pack/packtest"
	dom "github.com/oom-netsec/MACUAHUITL/internal/scripts"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

func colGuardar(t *testing.T, s *svc, name string) *v1.Collection {
	t.Helper()
	r, err := s.SaveCollection(bg, &v1.SaveCollectionRequest{Collection: &v1.Collection{Name: name}})
	if err != nil {
		t.Fatalf("SaveCollection(%q): %v", name, err)
	}
	return r.Collection
}

func colPon(t *testing.T, s *svc, id string, ids ...string) *v1.Collection {
	t.Helper()
	r, err := s.SetCollectionScripts(bg, &v1.SetCollectionScriptsRequest{Id: id, ScriptIds: ids})
	if err != nil {
		t.Fatalf("SetCollectionScripts(%s): %v", id, err)
	}
	return r.Collection
}

func colGet(t *testing.T, s *svc, id string) *v1.Collection {
	t.Helper()
	r, err := s.GetCollection(bg, &v1.GetCollectionRequest{Id: id})
	if err != nil {
		t.Fatalf("GetCollection(%s): %v", id, err)
	}
	return r.Collection
}

func unidos(l []string) string { return strings.Join(l, ",") }

func TestFavoritosEsLaColeccionPorDefecto(t *testing.T) {
	s, d := nuevoSvc(t)
	r, err := s.ListCollections(bg, &v1.ListCollectionsRequest{})
	if err != nil || len(r.Collections) != 1 || r.Collections[0].Id != "favoritos" || r.Collections[0].Name != "Favoritos" || r.Collections[0].Order != 0 {
		t.Fatalf("lista inicial = %v err = %v", r, err)
	}
	// ni se borra ni se renombra
	_, err = s.DeleteCollection(bg, &v1.DeleteCollectionRequest{Id: "favoritos"})
	codigo(t, err, codes.FailedPrecondition)
	_, err = s.SaveCollection(bg, &v1.SaveCollectionRequest{Collection: &v1.Collection{Id: "favoritos", Name: "Otro"}})
	codigo(t, err, codes.InvalidArgument)
	// la descripción sí se edita
	if r, err := s.SaveCollection(bg, &v1.SaveCollectionRequest{Collection: &v1.Collection{Id: "favoritos", Name: "Favoritos", Description: "los de siempre"}}); err != nil || r.Collection.Description != "los de siempre" {
		t.Fatalf("descripción = %v %v", r, err)
	}
	// SetFavorite sigue siendo el atajo: agrega y quita en «favoritos», en orden de marcado
	a, b := guardar(t, s, "Uno"), guardar(t, s, "Dos")
	for _, id := range []string{b.Id, "lib-l2-stp", a.Id, b.Id} { // repetido: idempotente
		if _, err := s.SetFavorite(bg, &v1.SetFavoriteRequest{Id: id, Favorite: true}); err != nil {
			t.Fatal(err)
		}
	}
	if got := unidos(colGet(t, s, "favoritos").ScriptIds); got != unidos([]string{b.Id, "lib-l2-stp", a.Id}) {
		t.Fatalf("favoritos = %s", got)
	}
	if g := get(t, s, a.Id); !g.Favorite || unidos(g.Collections) != "favoritos" {
		t.Errorf("script = favorite %v collections %v", g.Favorite, g.Collections)
	}
	if _, err := s.SetFavorite(bg, &v1.SetFavoriteRequest{Id: b.Id, Favorite: false}); err != nil {
		t.Fatal(err)
	}
	if got := unidos(colGet(t, s, "favoritos").ScriptIds); got != unidos([]string{"lib-l2-stp", a.Id}) {
		t.Fatalf("tras quitar = %s", got)
	}
	if l, _ := s.ListScripts(bg, &v1.ListScriptsRequest{OnlyFavorites: true}); len(l.Scripts) != 2 {
		t.Errorf("only_favorites = %d", len(l.Scripts))
	}
	if g := get(t, s, b.Id); g.Favorite || len(g.Collections) != 0 {
		t.Errorf("desmarcado = %v", g)
	}
	// también se reordena con las demás
	c := colGuardar(t, s, "Redes")
	if _, err := s.ReorderCollections(bg, &v1.ReorderCollectionsRequest{Ids: []string{c.Id, "favoritos"}}); err != nil {
		t.Fatal(err)
	}
	l, _ := s.ListCollections(bg, &v1.ListCollectionsRequest{})
	if l.Collections[0].Id != c.Id || l.Collections[1].Id != "favoritos" || l.Collections[1].Order != 1 {
		t.Errorf("orden = %v", l.Collections)
	}
	if !strings.Contains(d.AuditText(), "scripts.coleccion.reordenar") {
		t.Error("sin auditoría de reordenar")
	}
}

func TestColeccionesCrearEditarBorrarYNombres(t *testing.T) {
	s, d := nuevoSvc(t)
	a := colGuardar(t, s, "  Redes  ")
	if a.Name != "Redes" || len(a.Id) != 32 || a.Order != 1 || a.CreatedMs == 0 {
		t.Fatalf("creada = %v", a)
	}
	b := colGuardar(t, s, "Otra")
	// nombre único con la clave de nombre (mayúsculas y sigma), también contra «Favoritos»
	for _, n := range []string{"REDES", "redes", "favoritos", "FAVORITOS"} {
		_, err := s.SaveCollection(bg, &v1.SaveCollectionRequest{Collection: &v1.Collection{Name: n}})
		codigo(t, err, codes.AlreadyExists)
	}
	colGuardar(t, s, "aς")
	_, err := s.SaveCollection(bg, &v1.SaveCollectionRequest{Collection: &v1.Collection{Name: "aσ"}})
	codigo(t, err, codes.AlreadyExists)
	for _, n := range []string{"", strings.Repeat("a", 65), "con\ncontrol"} {
		_, err := s.SaveCollection(bg, &v1.SaveCollectionRequest{Collection: &v1.Collection{Name: n}})
		codigo(t, err, codes.InvalidArgument)
	}
	_, err = s.SaveCollection(bg, &v1.SaveCollectionRequest{Collection: &v1.Collection{Name: "x", Description: strings.Repeat("d", 513)}})
	codigo(t, err, codes.InvalidArgument)
	// editar conserva el ID, la fecha de creación y los scripts
	u := guardar(t, s, "Uno")
	colPon(t, s, a.Id, u.Id, "lib-l2-stp")
	e, err := s.SaveCollection(bg, &v1.SaveCollectionRequest{Collection: &v1.Collection{Id: a.Id, Name: "Redes 2", Description: "d", ScriptIds: []string{"ignorados"}}})
	if err != nil || e.Collection.Id != a.Id || e.Collection.CreatedMs != a.CreatedMs || e.Collection.Description != "d" || unidos(e.Collection.ScriptIds) != unidos([]string{u.Id, "lib-l2-stp"}) {
		t.Fatalf("editada = %v err = %v", e, err)
	}
	// editar sin cambiar el nombre no choca consigo misma; tomar el de otra sí
	if _, err := s.SaveCollection(bg, &v1.SaveCollectionRequest{Collection: &v1.Collection{Id: a.Id, Name: "REDES 2"}}); err != nil {
		t.Fatalf("mismo nombre: %v", err)
	}
	_, err = s.SaveCollection(bg, &v1.SaveCollectionRequest{Collection: &v1.Collection{Id: a.Id, Name: "otra"}})
	codigo(t, err, codes.AlreadyExists)
	_, err = s.SaveCollection(bg, &v1.SaveCollectionRequest{Collection: &v1.Collection{Id: dom.NewID(), Name: "fantasma"}})
	codigo(t, err, codes.NotFound)
	_, err = s.GetCollection(bg, &v1.GetCollectionRequest{Id: "nada"})
	codigo(t, err, codes.NotFound)
	// borrar no toca los scripts
	if _, err := s.DeleteCollection(bg, &v1.DeleteCollectionRequest{Id: a.Id}); err != nil {
		t.Fatal(err)
	}
	_, err = s.DeleteCollection(bg, &v1.DeleteCollectionRequest{Id: a.Id})
	codigo(t, err, codes.NotFound)
	if g := get(t, s, u.Id); len(g.Collections) != 0 {
		t.Errorf("collections tras borrar = %v", g.Collections)
	}
	_ = b
	for _, want := range []string{"scripts.coleccion.crear", "scripts.coleccion.editar", "scripts.coleccion.borrar", "scripts.coleccion.scripts"} {
		if !strings.Contains(d.AuditText(), want) {
			t.Errorf("auditoría sin %q", want)
		}
	}
}

func TestUnScriptEnVariasColeccionesYBorrarloLoQuitaDeTodas(t *testing.T) {
	s, _ := nuevoSvc(t)
	a, b := guardar(t, s, "Uno"), guardar(t, s, "Dos")
	c1, c2 := colGuardar(t, s, "C1"), colGuardar(t, s, "C2")
	colPon(t, s, c1.Id, a.Id, "lib-l2-stp", b.Id)
	colPon(t, s, c2.Id, "lib-l2-stp", a.Id)
	s.SetFavorite(bg, &v1.SetFavoriteRequest{Id: a.Id, Favorite: true})
	if g := get(t, s, a.Id); unidos(g.Collections) != unidos([]string{"favoritos", c1.Id, c2.Id}) {
		t.Fatalf("collections de a = %v", g.Collections)
	}
	// la biblioteca se referencia, no se copia
	n0 := len(mustList(t, s))
	if g := get(t, s, "lib-l2-stp"); g.Origin != "biblioteca" || unidos(g.Collections) != unidos([]string{c1.Id, c2.Id}) {
		t.Errorf("lib = %v", g)
	}
	if len(mustList(t, s)) != n0 {
		t.Error("referenciar la biblioteca cambió la lista")
	}
	// reordenar y quitar de una vez
	if got := colPon(t, s, c1.Id, b.Id, a.Id); unidos(got.ScriptIds) != unidos([]string{b.Id, a.Id}) {
		t.Errorf("reordenada = %v", got.ScriptIds)
	}
	// borrar a: sale de las tres; el orden de los demás se conserva
	if _, err := s.DeleteScript(bg, &v1.DeleteScriptRequest{Id: a.Id}); err != nil {
		t.Fatal(err)
	}
	if unidos(colGet(t, s, c1.Id).ScriptIds) != b.Id || unidos(colGet(t, s, c2.Id).ScriptIds) != "lib-l2-stp" || len(colGet(t, s, "favoritos").ScriptIds) != 0 {
		t.Errorf("tras borrar: %v %v %v", colGet(t, s, c1.Id).ScriptIds, colGet(t, s, c2.Id).ScriptIds, colGet(t, s, "favoritos").ScriptIds)
	}
	// validaciones de SetCollectionScripts
	_, err := s.SetCollectionScripts(bg, &v1.SetCollectionScriptsRequest{Id: c1.Id, ScriptIds: []string{b.Id, b.Id}})
	codigo(t, err, codes.InvalidArgument)
	_, err = s.SetCollectionScripts(bg, &v1.SetCollectionScriptsRequest{Id: c1.Id, ScriptIds: []string{a.Id}})
	codigo(t, err, codes.NotFound)
	_, err = s.SetCollectionScripts(bg, &v1.SetCollectionScriptsRequest{Id: c1.Id, ScriptIds: []string{"lib-no-existe"}})
	codigo(t, err, codes.NotFound)
	_, err = s.SetCollectionScripts(bg, &v1.SetCollectionScriptsRequest{Id: dom.NewID(), ScriptIds: nil})
	codigo(t, err, codes.NotFound)
	if unidos(colGet(t, s, c1.Id).ScriptIds) != b.Id {
		t.Error("una llamada inválida cambió la colección")
	}
}

func mustList(t *testing.T, s *svc) []*v1.Script {
	t.Helper()
	r, err := s.ListScripts(bg, &v1.ListScriptsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return r.Scripts
}

func TestReordenarColeccionesExigeUnaPermutacion(t *testing.T) {
	s, _ := nuevoSvc(t)
	a, b := colGuardar(t, s, "A"), colGuardar(t, s, "B")
	for _, ids := range [][]string{{a.Id, b.Id}, {"favoritos", a.Id}, {"favoritos", a.Id, a.Id}, {"favoritos", a.Id, b.Id, "x"}, {"favoritos", a.Id, dom.NewID()}} {
		_, err := s.ReorderCollections(bg, &v1.ReorderCollectionsRequest{Ids: ids})
		codigo(t, err, codes.InvalidArgument)
	}
	if _, err := s.ReorderCollections(bg, &v1.ReorderCollectionsRequest{Ids: []string{b.Id, "favoritos", a.Id}}); err != nil {
		t.Fatal(err)
	}
	l, _ := s.ListCollections(bg, &v1.ListCollectionsRequest{})
	if l.Collections[0].Id != b.Id || l.Collections[1].Id != "favoritos" || l.Collections[2].Id != a.Id || l.Collections[2].Order != 2 {
		t.Fatalf("orden = %v", l.Collections)
	}
}

func TestFijadosTopeDeCincoYOrden(t *testing.T) {
	s, d := nuevoSvc(t)
	var ids []string
	for i := 0; i < 6; i++ {
		ids = append(ids, guardar(t, s, fmt.Sprintf("p%d", i)).Id)
	}
	fija := func(id string, v bool) error {
		_, err := s.SetPinned(bg, &v1.SetPinnedRequest{Id: id, Pinned: v})
		return err
	}
	for _, id := range ids[:4] {
		if err := fija(id, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := fija("lib-l2-stp", true); err != nil { // la biblioteca también se fija: son 5
		t.Fatal(err)
	}
	if err := fija(ids[0], true); err != nil { // ya fijado: idempotente, aunque estén los 5
		t.Fatalf("re-fijar con 5: %v", err)
	}
	err := fija(ids[5], true)
	codigo(t, err, codes.FailedPrecondition)
	if !strings.Contains(err.Error(), "5") {
		t.Errorf("el motivo debe decir el tope: %v", err)
	}
	if get(t, s, ids[5]).Pinned {
		t.Error("el sexto quedó fijado")
	}
	// el orden es el de fijado; desfijar libera lugar
	p, _ := s.ListPinned(bg, &v1.ListPinnedRequest{})
	var got []string
	for _, x := range p.Scripts {
		got = append(got, x.Id)
		if !x.Pinned {
			t.Errorf("%s sin pinned", x.Id)
		}
	}
	if unidos(got) != unidos(append(append([]string{}, ids[:4]...), "lib-l2-stp")) {
		t.Fatalf("fijados = %v", got)
	}
	if err := fija(ids[1], false); err != nil {
		t.Fatal(err)
	}
	if err := fija(ids[5], true); err != nil {
		t.Fatal(err)
	}
	// ReorderPinned exige una permutación
	for _, bad := range [][]string{{ids[0]}, {ids[0], ids[0], ids[2], ids[3], "lib-l2-stp"}, {ids[0], ids[2], ids[3], "lib-l2-stp", ids[1]}} {
		_, err := s.ReorderPinned(bg, &v1.ReorderPinnedRequest{Ids: bad})
		codigo(t, err, codes.InvalidArgument)
	}
	nuevo := []string{ids[5], "lib-l2-stp", ids[3], ids[2], ids[0]}
	if _, err := s.ReorderPinned(bg, &v1.ReorderPinnedRequest{Ids: nuevo}); err != nil {
		t.Fatal(err)
	}
	p, _ = s.ListPinned(bg, &v1.ListPinnedRequest{})
	got = nil
	for _, x := range p.Scripts {
		got = append(got, x.Id)
	}
	if unidos(got) != unidos(nuevo) {
		t.Fatalf("tras reordenar = %v", got)
	}
	// independiente de las colecciones; borrar un script lo desfija; no existe -> NotFound
	if len(get(t, s, ids[5]).Collections) != 0 || !get(t, s, ids[5]).Pinned {
		t.Error("fijar no debe meter el script en una colección")
	}
	if _, err := s.DeleteScript(bg, &v1.DeleteScriptRequest{Id: ids[5]}); err != nil {
		t.Fatal(err)
	}
	if p, _ = s.ListPinned(bg, &v1.ListPinnedRequest{}); len(p.Scripts) != 4 {
		t.Errorf("tras borrar un fijado quedan %d", len(p.Scripts))
	}
	var filas int
	s.d.DB().QueryRow(`SELECT count(*) FROM script_pins`).Scan(&filas)
	if filas != 4 {
		t.Errorf("filas en script_pins = %d: borrar el script debe quitar su fila", filas)
	}
	codigo(t, fija("no-existe", true), codes.NotFound)
	if !strings.Contains(d.AuditText(), "scripts.fijar") || !strings.Contains(d.AuditText(), "scripts.fijados.reordenar") {
		t.Error("sin auditoría de fijados")
	}
}

// ---- export / import de colecciones ----

func exportarCol(t *testing.T, s *svc, path string, ids ...string) {
	t.Helper()
	if _, err := s.ExportCollections(bg, &v1.ExportCollectionsRequest{Ids: ids, Path: path}); err != nil {
		t.Fatalf("ExportCollections: %v", err)
	}
}

func previewCol(t *testing.T, s *svc, path string) *v1.PreviewImportCollectionsResponse {
	t.Helper()
	p, err := s.PreviewImportCollections(bg, &v1.PreviewImportCollectionsRequest{Path: path})
	if err != nil {
		t.Fatalf("PreviewImportCollections: %v", err)
	}
	return p
}

func decs(pares ...string) []*v1.ImportDecision {
	var out []*v1.ImportDecision
	for i := 0; i+1 < len(pares); i += 2 {
		out = append(out, &v1.ImportDecision{ScriptId: pares[i], Action: pares[i+1]})
	}
	return out
}

func porNombre(l []*v1.Collection, n string) *v1.Collection {
	for _, c := range l {
		if c.Name == n {
			return c
		}
	}
	return nil
}

func TestColeccionesIdaYVueltaConTresPropiosYDosDeBiblioteca(t *testing.T) {
	a, da := nuevoSvc(t)
	ids := llena(t, a, 3)
	col := colGuardar(t, a, "Mi kit")
	mezcla := []string{ids[0], "lib-l2-stp", ids[1], "lib-cfg-vlan-acceso", ids[2]}
	colPon(t, a, col.Id, mezcla...)
	otra := colGuardar(t, a, "Vacía")
	path := filepath.Join(t.TempDir(), "c.json")
	r, err := a.ExportCollections(bg, &v1.ExportCollectionsRequest{Ids: []string{col.Id, otra.Id}, Path: path})
	if err != nil || r.Collections != 2 || r.Scripts != 3 {
		t.Fatalf("export = %v err = %v", r, err)
	}
	if au := da.AuditText(); !strings.Contains(au, "scripts.coleccion.exportar") || !strings.Contains(au, path) {
		t.Errorf("auditoría de export: %s", au)
	}
	// el archivo de colecciones no lo acepta el import de scripts, ni al revés
	if _, err := a.PreviewImport(bg, &v1.PreviewImportRequest{Path: path}); err == nil {
		t.Error("el import de scripts aceptó un archivo de colecciones")
	}

	b, db := nuevoSvc(t)
	p := previewCol(t, b, path)
	if len(p.Collections) != 2 || len(p.Scripts) != 3 || len(p.Warnings) != 0 {
		t.Fatalf("preview = %v", p)
	}
	for _, it := range p.Collections {
		if it.State != "nueva" {
			t.Errorf("%s: %s", it.Collection.Name, it.State)
		}
	}
	for _, it := range p.Scripts {
		if it.State != "nuevo" {
			t.Errorf("%s: %s", it.Script.Name, it.State)
		}
	}
	ap, err := b.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token})
	if err != nil || ap.ScriptsCreated != 3 || ap.CollectionsCreated != 2 || len(ap.Warnings) != 0 {
		t.Fatalf("apply = %v err = %v", ap, err)
	}
	l, _ := b.ListCollections(bg, &v1.ListCollectionsRequest{})
	got := porNombre(l.Collections, "Mi kit")
	if got == nil || len(got.ScriptIds) != 5 || got.ScriptIds[0] != ids[0] || got.ScriptIds[1] != "lib-l2-stp" || got.ScriptIds[3] != "lib-cfg-vlan-acceso" || got.ScriptIds[4] != ids[2] {
		t.Fatalf("importada = %v", got)
	}
	if l.Collections[len(l.Collections)-1].Name != "Vacía" || l.Collections[1].Name != "Mi kit" { // al final, en el orden del archivo
		t.Errorf("orden = %v", l.Collections)
	}
	// la biblioteca no se copió
	for _, sc := range mustList(t, b) {
		if sc.Origin == "usuario" && strings.HasPrefix(sc.Name, "L2") {
			t.Errorf("se copió un script de la biblioteca: %v", sc.Name)
		}
	}
	if au := db.AuditText(); !strings.Contains(au, "scripts.coleccion.importar") || !strings.Contains(au, path) {
		t.Errorf("auditoría de import: %s", au)
	}
	// el token se gastó y una segunda vista previa da todo «igual»
	_, err = b.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token})
	codigo(t, err, codes.NotFound)
	for _, it := range previewCol(t, b, path).Collections {
		if it.State != "igual" {
			t.Errorf("segunda vez %s: %s", it.Collection.Name, it.State)
		}
	}
}

func TestImportColeccionesEstadosDecisionesYReferencias(t *testing.T) {
	a, _ := nuevoSvc(t)
	ids := llena(t, a, 2) // script 00, script 01
	c1, c2, c3 := colGuardar(t, a, "Igual"), colGuardar(t, a, "Choca ID"), colGuardar(t, a, "Choca nombre")
	colPon(t, a, c1.Id, ids[0])
	colPon(t, a, c2.Id, ids[0], ids[1])
	colPon(t, a, c3.Id, ids[1])
	path := filepath.Join(t.TempDir(), "c.json")
	exportarCol(t, a, path, c1.Id, c2.Id, c3.Id)

	b, _ := nuevoSvc(t)
	// b tiene el script 00 igual, el 01 con otro contenido (mismo ID: conflicto_id) y colecciones que chocan
	for i, id := range ids {
		sc := get(t, a, id)
		cmd := `["show vlan id 1"]`
		if i == 1 {
			cmd = `["show clock"]`
		}
		b.d.DB().Exec(`INSERT INTO scripts VALUES(?,?,?,?,?,?,?,?,?)`, sc.Id, sc.Name, sc.Tech, sc.Platform, sc.Description, cmd, `[]`, "2026-11-07T00:00:00Z", "2026-11-07T00:00:00Z")
	}
	b.d.DB().Exec(`INSERT INTO script_collections VALUES(?,?,?,?,?,?)`, c1.Id, "Igual", "", 1, "2026-11-07T00:00:00Z", "2026-11-07T00:00:00Z")
	b.d.DB().Exec(`INSERT INTO script_collection_items VALUES(?,?,0)`, c1.Id, ids[0])
	b.d.DB().Exec(`INSERT INTO script_collections VALUES(?,?,?,?,?,?)`, c2.Id, "Otro nombre", "", 2, "2026-11-07T00:00:00Z", "2026-11-07T00:00:00Z")
	otro := colGuardar(t, b, "choca NOMBRE")
	p := previewCol(t, b, path)
	est := map[string]string{}
	con := map[string]string{}
	for _, it := range p.Collections {
		est[it.Collection.Name], con[it.Collection.Name] = it.State, it.ConflictsWith
	}
	if est["Igual"] != "igual" || est["Choca ID"] != "conflicto_id" || est["Choca nombre"] != "conflicto_nombre" || con["Choca ID"] != c2.Id || con["Choca nombre"] != otro.Id {
		t.Fatalf("estados = %v con = %v", est, con)
	}
	est = map[string]string{}
	for _, it := range p.Scripts {
		est[it.Script.Name] = it.State
	}
	if est["script 00"] != "igual" || est["script 01"] != "conflicto_id" {
		t.Fatalf("estados de scripts = %v", est)
	}
	// falta una decisión de colección: error, nada escrito y el token sigue vivo
	_, err := b.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token, ScriptDecisions: decs(ids[1], "reemplazar"), CollectionDecisions: decs(c2.Id, "reemplazar")})
	codigo(t, err, codes.InvalidArgument)
	if get(t, b, ids[1]).Commands[0] != "show clock" {
		t.Fatal("se escribió un script aunque faltaba la decisión de una colección")
	}
	// falta la de un script
	_, err = b.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token, CollectionDecisions: decs(c2.Id, "reemplazar", c3.Id, "renombrar")})
	codigo(t, err, codes.InvalidArgument)
	ap, err := b.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token,
		ScriptDecisions: decs(ids[1], "reemplazar"), CollectionDecisions: decs(c2.Id, "reemplazar", c3.Id, "renombrar")})
	if err != nil || ap.CollectionsReplaced != 1 || ap.CollectionsRenamed != 1 || ap.CollectionsSkipped != 1 || ap.ScriptsReplaced != 1 {
		t.Fatalf("apply = %v err = %v", ap, err)
	}
	if get(t, b, ids[1]).Commands[0] != "show vlan id 2" {
		t.Error("el script no se reemplazó")
	}
	l, _ := b.ListCollections(bg, &v1.ListCollectionsRequest{})
	rep := colGet(t, b, c2.Id)
	if rep.Name != "Choca ID" || unidos(rep.ScriptIds) != unidos([]string{ids[0], ids[1]}) || rep.Order != 2 {
		t.Errorf("reemplazada = %v", rep)
	}
	ren := porNombre(l.Collections, "Choca nombre (importado)")
	if ren == nil || ren.Id == c3.Id || unidos(ren.ScriptIds) != ids[1] {
		t.Errorf("renombrada = %v", ren)
	}
	if colGet(t, b, otro.Id).Name != "choca NOMBRE" {
		t.Error("la local con el nombre en conflicto cambió")
	}
}

func TestImportColeccionesReflejaLosIDsReasignadosOmitidosYLibInexistente(t *testing.T) {
	b, _ := nuevoSvc(t)
	guardar(t, b, "Mio", "show version") // el del archivo se llamará igual: conflicto_nombre
	s1 := dom.Script{ID: dom.NewID(), Name: "mio", Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}, Tags: []string{}, Origin: "usuario"}
	s2 := dom.Script{ID: dom.NewID(), Name: "Otro", Tech: "l2", Platform: "ios-xe", Commands: []string{"show users"}, Tags: []string{}, Origin: "usuario"}
	s3 := dom.Script{ID: dom.NewID(), Name: "Omitido", Tech: "l2", Platform: "ios-xe", Commands: []string{"show arp"}, Tags: []string{}, Origin: "usuario"}
	c := dom.Coleccion{ID: dom.NewID(), Name: "Kit", ScriptIDs: []string{s1.ID, "lib-no-existe", s2.ID, "lib-l2-stp", s3.ID}}
	raw, err := dom.MarshalColecciones([]dom.Coleccion{c}, []dom.Script{s1, s2, s3}, b.clock())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "k.json")
	if err := service.WriteExport(context.Background(), path, raw, false); err != nil {
		t.Fatal(err)
	}
	p := previewCol(t, b, path)
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "lib-no-existe") {
		t.Fatalf("avisos del preview = %v", p.Warnings)
	}
	ap, err := b.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token, ScriptDecisions: decs(s1.ID, "renombrar", s3.ID, "omitir")})
	if err != nil || ap.ScriptsRenamed != 1 || ap.ScriptsCreated != 1 || ap.CollectionsCreated != 1 {
		t.Fatalf("apply = %v err = %v", ap, err)
	}
	if len(ap.Warnings) != 2 {
		t.Errorf("avisos = %v", ap.Warnings)
	}
	got := colGet(t, b, c.ID)
	if len(got.ScriptIds) != 3 || got.ScriptIds[1] != s2.ID || got.ScriptIds[2] != "lib-l2-stp" {
		t.Fatalf("colección = %v", got.ScriptIds)
	}
	// la primera referencia apunta al ID nuevo del renombrado, no al del archivo
	ren := get(t, b, got.ScriptIds[0])
	if got.ScriptIds[0] == s1.ID || ren.Name != "mio (importado)" || ren.Origin != "usuario" {
		t.Errorf("referencia reasignada = %s (%v)", got.ScriptIds[0], ren)
	}
	for _, id := range got.ScriptIds {
		if _, err := b.GetScript(bg, &v1.GetScriptRequest{Id: id}); err != nil {
			t.Errorf("referencia colgada %s: %v", id, err)
		}
	}
}

func TestImportFavoritosSeFusionaYNuncaReemplaza(t *testing.T) {
	a, _ := nuevoSvc(t)
	x, y := guardar(t, a, "X"), guardar(t, a, "Y")
	colPon(t, a, "favoritos", y.Id, x.Id, "lib-l2-stp")
	path := filepath.Join(t.TempDir(), "f.json")
	exportarCol(t, a, path, "favoritos")

	b, _ := nuevoSvc(t)
	z := guardar(t, b, "Z")
	colPon(t, b, "favoritos", z.Id, "lib-l2-stp")
	p := previewCol(t, b, path)
	if len(p.Collections) != 1 || p.Collections[0].State != "fusionar" || p.Collections[0].ConflictsWith != "favoritos" {
		t.Fatalf("preview = %v", p.Collections)
	}
	for _, a := range []string{"reemplazar", "renombrar"} {
		_, err := b.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token, CollectionDecisions: decs("favoritos", a)})
		codigo(t, err, codes.InvalidArgument)
	}
	ap, err := b.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token})
	if err != nil || ap.CollectionsMerged != 1 || ap.ScriptsCreated != 2 {
		t.Fatalf("apply = %v err = %v", ap, err)
	}
	fav := colGet(t, b, "favoritos")
	// los locales primero y sin duplicar; los que faltaban, al final y en el orden del archivo
	if len(fav.ScriptIds) != 4 || fav.ScriptIds[0] != z.Id || fav.ScriptIds[1] != "lib-l2-stp" || fav.ScriptIds[2] != y.Id || fav.ScriptIds[3] != x.Id || fav.Name != "Favoritos" {
		t.Fatalf("favoritos fusionada = %v", fav)
	}
	// y una segunda vez ya no hay nada que agregar
	if p = previewCol(t, b, path); p.Collections[0].State != "igual" {
		t.Errorf("segunda vez = %s", p.Collections[0].State)
	}
}

func TestImportColeccionesTodoONada(t *testing.T) {
	a, _ := nuevoSvc(t)
	ids := llena(t, a, 2)
	c1, c2 := colGuardar(t, a, "Una"), colGuardar(t, a, "Dos")
	colPon(t, a, c1.Id, ids[0])
	colPon(t, a, c2.Id, ids[1])
	path := filepath.Join(t.TempDir(), "c.json")
	exportarCol(t, a, path, c1.Id, c2.Id)
	b, _ := nuevoSvc(t)
	colGuardar(t, b, "dos") // choca con «Dos» y no hay decisión
	p := previewCol(t, b, path)
	_, err := b.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token})
	codigo(t, err, codes.InvalidArgument)
	if len(mustListUsuario(t, b)) != 0 {
		t.Fatal("se creó un script aunque la transacción debía fallar")
	}
	if l, _ := b.ListCollections(bg, &v1.ListCollectionsRequest{}); len(l.Collections) != 2 {
		t.Fatalf("colecciones tras el fallo = %d", len(l.Collections))
	}
	// con la decisión sí entra todo
	if _, err := b.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token, CollectionDecisions: decs(c2.Id, "renombrar")}); err != nil {
		t.Fatal(err)
	}
	if len(mustListUsuario(t, b)) != 2 {
		t.Error("faltan los scripts importados")
	}
}

func mustListUsuario(t *testing.T, s *svc) []*v1.Script {
	t.Helper()
	var out []*v1.Script
	for _, x := range mustList(t, s) {
		if x.Origin == "usuario" {
			out = append(out, x)
		}
	}
	return out
}

func TestImportColeccionesDobleReemplazoYNombresDeColecciones(t *testing.T) {
	s, _ := nuevoSvc(t)
	n := colGuardar(t, s, "N")
	u := guardar(t, s, "U")
	f1 := dom.Coleccion{ID: n.Id, Name: "M", ScriptIDs: []string{u.Id}}        // mismo ID, otro nombre
	f2 := dom.Coleccion{ID: dom.NewID(), Name: "n", ScriptIDs: []string{u.Id}} // otro ID, mismo nombre (sin importar mayúsculas)
	path := archivoCol(t, s, []dom.Coleccion{f1, f2}, []dom.Script{{ID: u.Id, Name: "U", Tech: "gestion", Platform: "ios-xe", Commands: []string{"show version"}, Tags: []string{}, Origin: "usuario"}})
	p := previewCol(t, s, path)
	_, err := s.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token, CollectionDecisions: decs(f1.ID, "reemplazar", f2.ID, "reemplazar")})
	codigo(t, err, codes.InvalidArgument)
	if colGet(t, s, n.Id).Name != "N" {
		t.Fatal("se escribió algo")
	}
	// la decisión inválida deja el token vivo para corregirla
	if _, err := s.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token, CollectionDecisions: decs(f1.ID, "reemplazar", f2.ID, "renombrar")}); err != nil {
		t.Fatalf("reintento: %v", err)
	}
	if colGet(t, s, n.Id).Name != "M" {
		t.Error("el reemplazo no se aplicó")
	}
	// una decisión repetida también devuelve el token
	p = previewCol(t, s, path)
	_, err = s.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token, CollectionDecisions: decs(f1.ID, "omitir", f1.ID, "omitir")})
	codigo(t, err, codes.InvalidArgument)
	if _, err := s.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token, CollectionDecisions: decs(f2.ID, "omitir")}); err != nil {
		t.Fatalf("reintento tras repetida: %v", err)
	}
}

func archivoCol(t *testing.T, s *svc, cols []dom.Coleccion, scs []dom.Script) string {
	t.Helper()
	raw, err := dom.MarshalColecciones(cols, scs, s.clock())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "x.json")
	if err := service.WriteExport(context.Background(), path, raw, false); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestImportColeccionesTokenEnParaleloVencidoYDeOtroTipo(t *testing.T) {
	s, _ := nuevoSvc(t)
	c := dom.Coleccion{ID: dom.NewID(), Name: "Kit", ScriptIDs: []string{"lib-l2-stp"}}
	path := archivoCol(t, s, []dom.Coleccion{c}, nil)
	p := previewCol(t, s, path)
	var wg sync.WaitGroup
	var ok, fallo int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token}); err == nil {
				atomic.AddInt32(&ok, 1)
			} else {
				atomic.AddInt32(&fallo, 1)
			}
		}()
	}
	wg.Wait()
	if l, _ := s.ListCollections(bg, &v1.ListCollectionsRequest{}); ok != 1 || fallo != 7 || len(l.Collections) != 2 {
		t.Fatalf("aplicados=%d rechazados=%d colecciones=%d (quiero 1, 7 y 2)", ok, fallo, len(l.Collections))
	}
	// vencido
	ahora := time.Now()
	s.now = func() time.Time { return ahora }
	p = previewCol(t, s, path)
	s.now = func() time.Time { return ahora.Add(10*time.Minute + time.Second) }
	_, err := s.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token})
	codigo(t, err, codes.FailedPrecondition)
	s.now = func() time.Time { return ahora }
	_, err = s.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token})
	codigo(t, err, codes.NotFound)
	_, err = s.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: "desconocido"})
	codigo(t, err, codes.NotFound)
	// un token de scripts no vale para colecciones, ni al revés, y el equivocado no se gasta
	a, _ := nuevoSvc(t)
	ids := llena(t, a, 1)
	sp := filepath.Join(t.TempDir(), "s.json")
	exportar(t, a, sp, ids...)
	b, _ := nuevoSvc(t)
	ps, err := b.PreviewImport(bg, &v1.PreviewImportRequest{Path: sp})
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: ps.Token})
	codigo(t, err, codes.FailedPrecondition)
	if _, err := b.ApplyImport(bg, &v1.ApplyImportRequest{Token: ps.Token}); err != nil {
		t.Fatalf("el token de scripts debía seguir vivo: %v", err)
	}
	pc := previewCol(t, b, path)
	_, err = b.ApplyImport(bg, &v1.ApplyImportRequest{Token: pc.Token})
	codigo(t, err, codes.FailedPrecondition)
	if _, err := b.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: pc.Token}); err != nil {
		t.Fatalf("el token de colecciones debía seguir vivo: %v", err)
	}
}

func TestExportColeccionesRechazos(t *testing.T) {
	s, _ := nuevoSvc(t)
	c := colGuardar(t, s, "Kit")
	ok := filepath.Join(t.TempDir(), "k.json")
	casos := map[string]*v1.ExportCollectionsRequest{
		"ruta relativa": {Ids: []string{c.Id}, Path: "k.json"},
		"sin colección": {Path: ok},
		"inexistente":   {Ids: []string{dom.NewID()}, Path: ok},
	}
	for n, r := range casos {
		if _, err := s.ExportCollections(bg, r); err == nil {
			t.Errorf("%s: debió fallar", n)
		}
	}
	exportarCol(t, s, ok, c.Id, c.Id) // repetida: se exporta una vez
	if _, err := s.ExportCollections(bg, &v1.ExportCollectionsRequest{Ids: []string{c.Id}, Path: ok}); err == nil {
		t.Error("sin overwrite sobre un archivo existente debió fallar")
	}
	if _, err := s.ExportCollections(bg, &v1.ExportCollectionsRequest{Ids: []string{c.Id}, Path: ok, Overwrite: true}); err != nil {
		t.Errorf("con overwrite: %v", err)
	}
	if _, err := s.PreviewImportCollections(bg, &v1.PreviewImportCollectionsRequest{Path: ok}); err != nil {
		t.Errorf("lo exportado debe poder importarse: %v", err)
	}
	if _, err := s.PreviewImportCollections(bg, &v1.PreviewImportCollectionsRequest{Path: "relativa.json"}); err == nil {
		t.Error("ruta relativa en el preview debió fallar")
	}
	if _, err := s.PreviewImportCollections(bg, &v1.PreviewImportCollectionsRequest{Path: filepath.Join(t.TempDir(), "no.json")}); err == nil {
		t.Error("archivo inexistente debió fallar")
	}
}

// Un «lib-*» que una biblioteca nueva ya no trae no debe llegar a la UI ni al export.
func TestColeccionesOmitenLibInexistentes(t *testing.T) {
	s, _ := nuevoSvc(t)
	c := colGuardar(t, s, "Vieja")
	colPon(t, s, c.Id, "lib-l2-stp")
	s.d.DB().Exec(`INSERT INTO script_collection_items VALUES(?,?,5)`, c.Id, "lib-ya-no-existe")
	if got := colGet(t, s, c.Id).ScriptIds; unidos(got) != "lib-l2-stp" {
		t.Errorf("GetCollection = %v", got)
	}
	l, _ := s.ListCollections(bg, &v1.ListCollectionsRequest{})
	if got := porNombre(l.Collections, "Vieja").ScriptIds; unidos(got) != "lib-l2-stp" {
		t.Errorf("ListCollections = %v", got)
	}
	path := filepath.Join(t.TempDir(), "v.json")
	exportarCol(t, s, path, c.Id)
	raw, _ := service.ReadImport(context.Background(), path, dom.MaxImportBytes)
	cols, _, err := dom.ParseColecciones(raw)
	if err != nil || unidos(cols[0].ScriptIDs) != "lib-l2-stp" {
		t.Errorf("export = %v %v", cols, err)
	}
}

func TestColeccionesTopeDeCien(t *testing.T) {
	s, _ := nuevoSvc(t)
	for i := 0; i < dom.MaxColecciones-2; i++ { // con favoritos son 99
		colGuardar(t, s, fmt.Sprintf("c%03d", i))
	}
	a := dom.Coleccion{ID: dom.NewID(), Name: "Extra A", ScriptIDs: []string{}}
	b := dom.Coleccion{ID: dom.NewID(), Name: "Extra B", ScriptIDs: []string{}}
	p := previewCol(t, s, archivoCol(t, s, []dom.Coleccion{a, b}, nil))
	_, err := s.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token})
	codigo(t, err, codes.InvalidArgument)
	// la decisión de omitir una corrige el exceso con el mismo token
	if _, err := s.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token, CollectionDecisions: decs(b.ID, "omitir")}); err != nil {
		t.Fatalf("reintento: %v", err)
	}
	_, err = s.SaveCollection(bg, &v1.SaveCollectionRequest{Collection: &v1.Collection{Name: "Una más"}})
	codigo(t, err, codes.FailedPrecondition)
}

// Revisión: un fijado «lib-*» que la biblioteca ya no trae no debe atascar la barra.
func TestFijadoLibInexistenteNoAtascaLaBarra(t *testing.T) {
	s, _ := nuevoSvc(t)
	var ids []string
	for i := 0; i < 5; i++ {
		ids = append(ids, guardar(t, s, fmt.Sprintf("p%d", i)).Id)
	}
	for _, id := range ids[:4] {
		if _, err := s.SetPinned(bg, &v1.SetPinnedRequest{Id: id, Pinned: true}); err != nil {
			t.Fatal(err)
		}
	}
	fantasma := func() { s.d.DB().Exec(`INSERT OR REPLACE INTO script_pins VALUES('lib-ya-no-existe', 9)`) }
	cuenta := func() (n int) {
		s.d.DB().QueryRow(`SELECT count(*) FROM script_pins WHERE script_id = 'lib-ya-no-existe'`).Scan(&n)
		return
	}
	// fijar otro: los visibles son 4, así que cabe
	fantasma()
	if _, err := s.SetPinned(bg, &v1.SetPinnedRequest{Id: ids[4], Pinned: true}); err != nil {
		t.Fatalf("fijar el quinto: %v", err)
	}
	if cuenta() != 0 {
		t.Error("el fantasma debió limpiarse")
	}
	// desfijar el fantasma no es error
	fantasma()
	if _, err := s.SetPinned(bg, &v1.SetPinnedRequest{Id: "lib-ya-no-existe", Pinned: false}); err != nil {
		t.Fatalf("desfijar el fantasma: %v", err)
	}
	// reordenar lo que se ve
	fantasma()
	p, _ := s.ListPinned(bg, &v1.ListPinnedRequest{})
	var vis []string
	for _, x := range p.Scripts {
		vis = append([]string{x.Id}, vis...)
	}
	if _, err := s.ReorderPinned(bg, &v1.ReorderPinnedRequest{Ids: vis}); err != nil {
		t.Fatalf("reordenar los visibles: %v", err)
	}
	if cuenta() != 0 {
		t.Error("el fantasma debió limpiarse al reordenar")
	}
}

func TestSetFavoriteRespetaElTopeDeLaColeccion(t *testing.T) {
	s, _ := nuevoSvc(t)
	tx, _ := s.d.DB().Begin()
	for i := 0; i < dom.MaxScriptsColeccion; i++ {
		tx.Exec(`INSERT INTO script_collection_items VALUES('favoritos', ?, ?)`, fmt.Sprintf("%032x", i+1), i)
	}
	tx.Commit()
	y := guardar(t, s, "Y")
	_, err := s.SetFavorite(bg, &v1.SetFavoriteRequest{Id: y.Id, Favorite: true})
	codigo(t, err, codes.FailedPrecondition)
	if n := len(colGet(t, s, "favoritos").ScriptIds); n != dom.MaxScriptsColeccion {
		t.Errorf("favoritos = %d", n)
	}
	// quitar sigue valiendo con la colección llena
	if _, err := s.SetFavorite(bg, &v1.SetFavoriteRequest{Id: "lib-l2-stp", Favorite: false}); err != nil {
		t.Errorf("quitar: %v", err)
	}
}

func TestBorrarUnaColeccionDejaElOrdenContiguo(t *testing.T) {
	s, _ := nuevoSvc(t)
	a, b, c := colGuardar(t, s, "A"), colGuardar(t, s, "B"), colGuardar(t, s, "C")
	if _, err := s.DeleteCollection(bg, &v1.DeleteCollectionRequest{Id: a.Id}); err != nil {
		t.Fatal(err)
	}
	l, _ := s.ListCollections(bg, &v1.ListCollectionsRequest{})
	if len(l.Collections) != 3 || l.Collections[0].Order != 0 || l.Collections[1].Id != b.Id || l.Collections[1].Order != 1 || l.Collections[2].Id != c.Id || l.Collections[2].Order != 2 {
		t.Fatalf("orden tras borrar = %v", l.Collections)
	}
}

// Revisión: X está en favoritos, se edita en local y se reimporta renombrando: la copia entra a favoritos.
func TestImportFavoritosRecibeLaCopiaRenombrada(t *testing.T) {
	a, _ := nuevoSvc(t)
	x := guardar(t, a, "X", "show clock")
	colPon(t, a, "favoritos", x.Id)
	path := filepath.Join(t.TempDir(), "f.json")
	exportarCol(t, a, path, "favoritos")
	if _, err := a.SaveScript(bg, &v1.SaveScriptRequest{Script: &v1.Script{Id: x.Id, Name: "X", Tech: "gestion", Platform: "ios-xe", Commands: []string{"show users"}}}); err != nil {
		t.Fatal(err)
	}
	p := previewCol(t, a, path)
	ap, err := a.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: p.Token, ScriptDecisions: decs(x.Id, "renombrar")})
	if err != nil || ap.CollectionsMerged != 1 {
		t.Fatalf("apply = %v err = %v", ap, err)
	}
	fav := colGet(t, a, "favoritos").ScriptIds
	if len(fav) != 2 || fav[0] != x.Id || get(t, a, fav[1]).Name != "X (importado)" {
		t.Errorf("favoritos = %v", fav)
	}
}

func sinSuma(b []byte) []byte {
	i := strings.Index(string(b), `,"sha256"`)
	return []byte(string(b[:i]) + "}")
}

func escribe(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.json")
	if err := service.WriteExport(context.Background(), p, b, false); err != nil {
		t.Fatal(err)
	}
	return p
}

// El sha256 es opcional: sin él la vista previa avisa y se puede importar; con uno malo se rechaza.
func TestImportSinSumaAvisaYSeAplica(t *testing.T) {
	s, _ := nuevoSvc(t)
	sc := dom.Script{ID: dom.NewID(), Name: "Sin suma", Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}, Tags: []string{}, Origin: "usuario"}
	raw, _ := dom.Marshal([]dom.Script{sc}, s.clock())
	p, err := s.PreviewImport(bg, &v1.PreviewImportRequest{Path: escribe(t, raw)})
	if err != nil || len(p.Warnings) != 0 {
		t.Fatalf("con suma: %v %v", p.GetWarnings(), err)
	}
	p, err = s.PreviewImport(bg, &v1.PreviewImportRequest{Path: escribe(t, sinSuma(raw))})
	if err != nil || len(p.Warnings) != 1 || p.Warnings[0] != dom.AvisoSinSuma || p.Items[0].State != "nuevo" {
		t.Fatalf("sin suma: %v %v", p, err)
	}
	if ap, err := s.ApplyImport(bg, &v1.ApplyImportRequest{Token: p.Token}); err != nil || ap.Created != 1 {
		t.Fatalf("apply: %v %v", ap, err)
	}
	mala := strings.Replace(string(raw), `"sha256":"`, `"sha256":"00`, 1)
	if _, err := s.PreviewImport(bg, &v1.PreviewImportRequest{Path: escribe(t, []byte(mala))}); err == nil {
		t.Error("suma mala debió fallar")
	}

	c := dom.Coleccion{ID: dom.NewID(), Name: "Col", ScriptIDs: []string{"lib-l2-stp"}}
	craw, _ := dom.MarshalColecciones([]dom.Coleccion{c}, nil, s.clock())
	pc := previewCol(t, s, escribe(t, craw))
	if len(pc.Warnings) != 0 {
		t.Errorf("con suma: %v", pc.Warnings)
	}
	pc = previewCol(t, s, escribe(t, sinSuma(craw)))
	if len(pc.Warnings) != 1 || pc.Warnings[0] != dom.AvisoSinSuma {
		t.Errorf("sin suma: %v", pc.Warnings)
	}
	if _, err := s.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: pc.Token}); err != nil {
		t.Errorf("apply: %v", err)
	}
}

// La plantilla pasa la vista previa con la biblioteca real: todo «nuevo» y solo el aviso de que no trae suma.
func TestPlantillaDeImportPasaLaVistaPrevia(t *testing.T) {
	s, _ := nuevoSvc(t)
	r, err := s.ImportTemplate(bg, &v1.ImportTemplateRequest{Kind: "scripts"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.PreviewImport(bg, &v1.PreviewImportRequest{Path: escribe(t, []byte(r.Json))})
	if err != nil || len(p.Items) != 3 || len(p.Warnings) != 1 || p.Warnings[0] != dom.AvisoSinSuma {
		t.Fatalf("scripts: %v %v", p, err)
	}
	for _, it := range p.Items {
		if it.State != "nuevo" {
			t.Errorf("%s: %s", it.Script.Name, it.State)
		}
	}
	if ap, err := s.ApplyImport(bg, &v1.ApplyImportRequest{Token: p.Token}); err != nil || ap.Created != 3 {
		t.Fatalf("apply: %v %v", ap, err)
	}

	r, err = s.ImportTemplate(bg, &v1.ImportTemplateRequest{Kind: "colecciones"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := nuevoSvc(t) // base limpia: la plantilla de colecciones trae sus propios scripts
	pc := previewCol(t, b, escribe(t, []byte(r.Json)))
	if len(pc.Collections) != 1 || pc.Collections[0].State != "nueva" || len(pc.Scripts) != 2 || len(pc.Warnings) != 1 || pc.Warnings[0] != dom.AvisoSinSuma {
		t.Fatalf("colecciones: %v", pc)
	}
	for _, it := range pc.Scripts {
		if it.State != "nuevo" {
			t.Errorf("%s: %s", it.Script.Name, it.State)
		}
	}
	ap, err := b.ApplyImportCollections(bg, &v1.ApplyImportCollectionsRequest{Token: pc.Token})
	if err != nil || ap.CollectionsCreated != 1 || ap.ScriptsCreated != 2 || len(ap.Warnings) != 0 {
		t.Fatalf("apply: %v %v", ap, err)
	}
	if got := colGet(t, b, pc.Collections[0].Collection.Id).ScriptIds; len(got) != 3 || !strings.HasPrefix(got[1], "lib-") {
		t.Errorf("referencias = %v", got)
	}
	_, err = s.ImportTemplate(bg, &v1.ImportTemplateRequest{Kind: "otra"})
	codigo(t, err, codes.InvalidArgument)
}

func TestFormatoDeImportListaLosCampos(t *testing.T) {
	s, _ := nuevoSvc(t)
	for kind, quiere := range map[string]string{"scripts": "scripts[].commands", "colecciones": "colecciones[].script_ids"} {
		r, err := s.ImportFormat(bg, &v1.ImportFormatRequest{Kind: kind})
		if err != nil {
			t.Fatal(err)
		}
		var nombres []string
		for _, f := range r.Fields {
			nombres = append(nombres, f.Name)
			if f.Name == "formato" && (!f.Required || f.Example == "") {
				t.Errorf("%s formato: %v", kind, f)
			}
			if f.Name == "sha256" && f.Required {
				t.Error("sha256 es opcional")
			}
		}
		if !strings.Contains(strings.Join(nombres, " "), quiere) {
			t.Errorf("%s: faltan campos: %v", kind, nombres)
		}
	}
	_, err := s.ImportFormat(bg, &v1.ImportFormatRequest{Kind: ""})
	codigo(t, err, codes.InvalidArgument)
}

// Los scripts movidos a un paquete (o de uno quitado) que el usuario tenía fijados o en colecciones no se pierden
// mientras el paquete no está instalado: ni la poda de fijados ni la limpieza de colecciones los tocan.
func TestMovidosSinPaqueteConservanFijadosYColecciones(t *testing.T) {
	d := servicetest.New(t)
	st, _, err := pack.Open(t.TempDir(), "dev", packtest.Keys(), pack.Base{})
	if err != nil {
		t.Fatal(err)
	}
	s := &svc{d: d, packs: st} // sin oom/ios-xe
	if _, err := d.DB().Exec(`INSERT INTO script_pins(script_id, position) VALUES('lib-l2-stp', 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DB().Exec(`INSERT INTO script_collection_items(collection_id, script_id, position) VALUES('favoritos', 'lib-l2-stp', 0)`); err != nil {
		t.Fatal(err)
	}
	// También el de un paquete quitado (anotado en pack_removed).
	d.DB().Exec(`INSERT INTO pack_removed(playbook_id, pack) VALUES('ios-xe/acme-x', 'acme/demo')`)
	d.DB().Exec(`INSERT INTO script_pins(script_id, position) VALUES('lib-acme-x', 1)`)
	d.DB().Exec(`INSERT INTO pack_removed(playbook_id, pack) VALUES('ios/acme-y', 'acme/demo')`) // otra plataforma: lib-ios-acme-y
	d.DB().Exec(`INSERT INTO script_pins(script_id, position) VALUES('lib-ios-acme-y', 2)`)

	mio := guardar(t, s, "Mi script", "show clock")
	if _, err := s.SetPinned(bg, &v1.SetPinnedRequest{Id: mio.Id, Pinned: true}); err != nil { // corre prunePins
		t.Fatal(err)
	}
	lc, err := s.ListCollections(bg, &v1.ListCollectionsRequest{})
	if err != nil || !slices.Contains(lc.Collections[0].ScriptIds, "lib-l2-stp") {
		t.Fatalf("la vista de colecciones lo oculta: %+v %v", lc, err)
	}
	// Guardar la colección como la vería el cliente no debe perderlo.
	if _, err := s.SetCollectionScripts(bg, &v1.SetCollectionScriptsRequest{Id: "favoritos", ScriptIds: lc.Collections[0].ScriptIds}); err != nil {
		t.Fatal(err)
	}
	pins := func() []string {
		var out []string
		rows, _ := d.DB().Query(`SELECT script_id FROM script_pins`)
		defer rows.Close()
		for rows.Next() {
			var id string
			rows.Scan(&id)
			out = append(out, id)
		}
		return out
	}
	if p := pins(); !slices.Contains(p, "lib-l2-stp") || !slices.Contains(p, "lib-acme-x") || !slices.Contains(p, "lib-ios-acme-y") {
		t.Fatalf("la poda borró fijados: %v", p)
	}
	// Se instala el paquete: el fijado y la colección siguen ahí.
	if _, err := st.Install(packtest.IOSXE(t), false); err != nil {
		t.Fatal(err)
	}
	lc, _ = s.ListCollections(bg, &v1.ListCollectionsRequest{})
	if !slices.Contains(lc.Collections[0].ScriptIds, "lib-l2-stp") || !slices.Contains(pins(), "lib-l2-stp") {
		t.Fatalf("tras instalar: %+v %v", lc, pins())
	}
	// Un lib-* que no es de ningún paquete sí se sigue podando.
	d.DB().Exec(`INSERT INTO script_pins(script_id, position) VALUES('lib-fantasma', 5)`)
	if _, err := s.SetPinned(bg, &v1.SetPinnedRequest{Id: mio.Id, Pinned: true}); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(pins(), "lib-fantasma") {
		t.Fatal("lib-fantasma debía podarse")
	}
}

// N1: un fijado retenido (script de un paquete ausente) no se ve en ListPinned, no cuenta para el tope y no estorba al
// reordenar los visibles; se conserva al final y vuelve a verse al instalar el paquete.
func TestFijadoRetenidoNoEstorbaAlReordenarNiCuentaParaElTope(t *testing.T) {
	d := servicetest.New(t)
	st, _, err := pack.Open(t.TempDir(), "dev", packtest.Keys(), pack.Base{})
	if err != nil {
		t.Fatal(err)
	}
	s := &svc{d: d, packs: st} // sin oom/ios-xe
	if _, err := d.DB().Exec(`INSERT INTO script_pins(script_id, position) VALUES('lib-l2-stp', 0)`); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := 0; i < dom.MaxFijados; i++ { // los visibles llenan el tope aunque haya un retenido guardado
		x := guardar(t, s, fmt.Sprintf("Fijado %d", i), "show clock")
		if _, err := s.SetPinned(bg, &v1.SetPinnedRequest{Id: x.Id, Pinned: true}); err != nil {
			t.Fatalf("el retenido no debe contar para el tope (fijado %d): %v", i, err)
		}
		ids = append(ids, x.Id)
	}
	lp, err := s.ListPinned(bg, &v1.ListPinnedRequest{})
	if err != nil || len(lp.Scripts) != dom.MaxFijados {
		t.Fatalf("los visibles: %d %v", len(lp.GetScripts()), err)
	}
	rev := slices.Clone(ids)
	slices.Reverse(rev)
	if _, err := s.ReorderPinned(bg, &v1.ReorderPinnedRequest{Ids: rev}); err != nil {
		t.Fatalf("reordenar los visibles: %v", err)
	}
	lp, _ = s.ListPinned(bg, &v1.ListPinnedRequest{})
	for i, x := range lp.Scripts {
		if x.Id != rev[i] {
			t.Fatalf("orden: %d %s", i, x.Id)
		}
	}
	// Se instala el paquete: el retenido sigue guardado y vuelve a verse, al final.
	if _, err := st.Install(packtest.IOSXE(t), false); err != nil {
		t.Fatal(err)
	}
	lp, _ = s.ListPinned(bg, &v1.ListPinnedRequest{})
	if n := len(lp.Scripts); n != dom.MaxFijados+1 || lp.Scripts[n-1].Id != "lib-l2-stp" {
		t.Fatalf("tras instalar: %d", n)
	}
	// Con el tope lleno (visibles) fijar otro sigue fallando.
	otro := guardar(t, s, "Uno más", "show clock")
	if _, err := s.SetPinned(bg, &v1.SetPinnedRequest{Id: otro.Id, Pinned: true}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("%v", err)
	}
}
