package scripts

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	"github.com/oom-netsec/MACUAHUITL/internal/store"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

var bg = context.Background()

func nuevoSvc(t *testing.T) (*svc, *servicetest.Deps) {
	t.Helper()
	d := servicetest.New(t)
	return &svc{d: d, packs: iosxe(t)}, d
}

// iosxe es un almacén de paquetes con oom/ios-xe instalado (firmado con la llave de pruebas): los playbooks que
// salieron del binario, y con ellos sus scripts lib-<id>, viven ahí.
func iosxe(t *testing.T) *pack.Store {
	t.Helper()
	st, _, err := pack.Open(t.TempDir(), "dev", packtest.Keys(), pack.Base{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Install(packtest.IOSXE(t), false); err != nil {
		t.Fatal(err)
	}
	return st
}

func codigo(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("código = %v (%v), quiero %v", status.Code(err), err, want)
	}
}

func guardar(t *testing.T, s *svc, name string, cmds ...string) *v1.Script {
	t.Helper()
	if len(cmds) == 0 {
		cmds = []string{"show version"}
	}
	r, err := s.SaveScript(bg, &v1.SaveScriptRequest{Script: &v1.Script{Name: name, Tech: "gestion", Platform: "ios-xe", Commands: cmds}})
	if err != nil {
		t.Fatalf("SaveScript(%q): %v", name, err)
	}
	return r.Script
}

func TestListaIncluyeBibliotecaYFiltra(t *testing.T) {
	s, _ := nuevoSvc(t)
	mio := guardar(t, s, "Mi OSPF", "show ip ospf neighbor")
	r, err := s.ListScripts(bg, &v1.ListScriptsRequest{})
	if err != nil || len(r.Scripts) < 60 {
		t.Fatalf("lista = %d err = %v", len(r.Scripts), err)
	}
	for i := 1; i < len(r.Scripts); i++ {
		if strings.ToLower(r.Scripts[i-1].Name) > strings.ToLower(r.Scripts[i].Name) {
			t.Fatalf("sin orden por nombre: %q > %q", r.Scripts[i-1].Name, r.Scripts[i].Name)
		}
	}
	filtra := func(req *v1.ListScriptsRequest) []*v1.Script {
		t.Helper()
		r, err := s.ListScripts(bg, req)
		if err != nil {
			t.Fatal(err)
		}
		return r.Scripts
	}
	if got := filtra(&v1.ListScriptsRequest{Text: "OSPF NEIGHBOR"}); len(got) == 0 || !contiene(got, mio.Id) {
		t.Fatalf("texto (en comandos, sin importar mayúsculas): %d", len(got))
	}
	for _, sc := range filtra(&v1.ListScriptsRequest{Tech: "etherchannel"}) {
		if sc.Tech != "etherchannel" {
			t.Errorf("tech: %s", sc.Tech)
		}
	}
	if got := filtra(&v1.ListScriptsRequest{Platform: "nx-os"}); len(got) != 0 {
		t.Errorf("nx-os no tiene scripts, hay %d", len(got))
	}
	mio2, _ := s.SaveScript(bg, &v1.SaveScriptRequest{Script: &v1.Script{Name: "Genérico", Tech: "otro", Platform: "cualquiera", Commands: []string{"show clock"}, Tags: []string{"mi-etiqueta"}}})
	if got := filtra(&v1.ListScriptsRequest{Platform: "nx-os"}); len(got) != 1 || got[0].Id != mio2.Script.Id {
		t.Errorf("con una plataforma también entran los «cualquiera»: %v", got)
	}
	if got := filtra(&v1.ListScriptsRequest{Tag: "mi-etiqueta"}); len(got) != 1 {
		t.Errorf("etiqueta: %d", len(got))
	}
	// read_only lo calcula el núcleo: el de configuración de la biblioteca no, el de show sí
	for _, sc := range filtra(&v1.ListScriptsRequest{Text: "vlan"}) {
		if sc.Id == "lib-cfg-vlan-acceso" && sc.ReadOnly {
			t.Error("lib-cfg-vlan-acceso no es read_only")
		}
	}
	if !contiene(filtra(&v1.ListScriptsRequest{}), "lib-l2-stp") {
		t.Error("falta lib-l2-stp")
	}
	if !get(t, s, "lib-l2-stp").ReadOnly || !get(t, s, mio.Id).ReadOnly {
		t.Error("los de show deben ser read_only")
	}
}

func contiene(l []*v1.Script, id string) bool {
	for _, x := range l {
		if x.Id == id {
			return true
		}
	}
	return false
}

func get(t *testing.T, s *svc, id string) *v1.Script {
	t.Helper()
	r, err := s.GetScript(bg, &v1.GetScriptRequest{Id: id})
	if err != nil {
		t.Fatalf("GetScript(%s): %v", id, err)
	}
	return r.Script
}

func TestGuardarCreaEditaYValida(t *testing.T) {
	s, d := nuevoSvc(t)
	a := guardar(t, s, "  Uno  ", "show clock")
	if a.Name != "Uno" || a.Origin != "usuario" || len(a.Id) != 32 || a.CreatedMs == 0 {
		t.Fatalf("creado = %v", a)
	}
	// editar conserva ID y fecha de creación
	b, err := s.SaveScript(bg, &v1.SaveScriptRequest{Script: &v1.Script{Id: a.Id, Name: "Uno", Tech: "l3", Platform: "ios", Commands: []string{"show ip route"}, Origin: "biblioteca"}})
	if err != nil || b.Script.Id != a.Id || b.Script.CreatedMs != a.CreatedMs || b.Script.Tech != "l3" || b.Script.Origin != "usuario" {
		t.Fatalf("editado = %v err = %v", b, err)
	}
	// biblioteca: ni editar ni crear con ese ID
	_, err = s.SaveScript(bg, &v1.SaveScriptRequest{Script: &v1.Script{Id: "lib-l2-stp", Name: "x", Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}}})
	codigo(t, err, codes.InvalidArgument)
	if !strings.Contains(err.Error(), "biblioteca") {
		t.Fatalf("el mensaje debe explicar que la biblioteca no se edita: %v", err)
	}
	// ID que no existe
	_, err = s.SaveScript(bg, &v1.SaveScriptRequest{Script: &v1.Script{Id: strings.Repeat("0", 32), Name: "x", Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}}})
	codigo(t, err, codes.NotFound)
	// reglas del dominio
	_, err = s.SaveScript(bg, &v1.SaveScriptRequest{Script: &v1.Script{Name: "malo", Tech: "voip", Platform: "ios-xe", Commands: []string{"show clock"}}})
	codigo(t, err, codes.InvalidArgument)
	_, err = s.SaveScript(bg, &v1.SaveScriptRequest{Script: &v1.Script{Name: "malo", Tech: "l2", Platform: "ios-xe", Commands: []string{"show cl\tock"}}})
	codigo(t, err, codes.InvalidArgument)
	// nombre repetido (sin importar mayúsculas), al crear y al editar
	_, err = s.SaveScript(bg, &v1.SaveScriptRequest{Script: &v1.Script{Name: "UNO", Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}}})
	codigo(t, err, codes.AlreadyExists)
	dos := guardar(t, s, "Dos")
	_, err = s.SaveScript(bg, &v1.SaveScriptRequest{Script: &v1.Script{Id: dos.Id, Name: "uno", Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}}})
	codigo(t, err, codes.AlreadyExists)
	_, err = s.SaveScript(bg, &v1.SaveScriptRequest{})
	codigo(t, err, codes.InvalidArgument)
	au := d.AuditText()
	for _, want := range []string{"scripts.crear", "scripts.editar", a.Id} {
		if !strings.Contains(au, want) {
			t.Errorf("auditoría sin %q", want)
		}
	}
}

func TestBorrarYBiblioteca(t *testing.T) {
	s, d := nuevoSvc(t)
	a := guardar(t, s, "Uno")
	if _, err := s.SetFavorite(bg, &v1.SetFavoriteRequest{Id: a.Id, Favorite: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteScript(bg, &v1.DeleteScriptRequest{Id: a.Id}); err != nil {
		t.Fatal(err)
	}
	_, err := s.GetScript(bg, &v1.GetScriptRequest{Id: a.Id})
	codigo(t, err, codes.NotFound)
	_, err = s.DeleteScript(bg, &v1.DeleteScriptRequest{Id: a.Id})
	codigo(t, err, codes.NotFound)
	_, err = s.DeleteScript(bg, &v1.DeleteScriptRequest{Id: "lib-l2-stp"})
	codigo(t, err, codes.InvalidArgument)
	var n int
	if err := d.DB().QueryRow(`SELECT count(*) FROM script_collection_items`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("el favorito del script borrado quedó: %d", n)
	}
	if !strings.Contains(d.AuditText(), "scripts.borrar") {
		t.Error("sin auditoría de borrado")
	}
}

func TestFavoritosDeBibliotecaYUsuario(t *testing.T) {
	s, d := nuevoSvc(t)
	a := guardar(t, s, "Uno")
	for _, id := range []string{a.Id, "lib-l2-stp"} {
		if _, err := s.SetFavorite(bg, &v1.SetFavoriteRequest{Id: id, Favorite: true}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SetFavorite(bg, &v1.SetFavoriteRequest{Id: a.Id, Favorite: true}); err != nil { // idempotente
		t.Fatal(err)
	}
	r, _ := s.ListScripts(bg, &v1.ListScriptsRequest{OnlyFavorites: true})
	if len(r.Scripts) != 2 || !r.Scripts[0].Favorite {
		t.Fatalf("favoritos = %v", r.Scripts)
	}
	if _, err := s.SetFavorite(bg, &v1.SetFavoriteRequest{Id: a.Id, Favorite: false}); err != nil {
		t.Fatal(err)
	}
	if r, _ = s.ListScripts(bg, &v1.ListScriptsRequest{OnlyFavorites: true}); len(r.Scripts) != 1 || r.Scripts[0].Id != "lib-l2-stp" {
		t.Fatalf("tras quitar: %v", r.Scripts)
	}
	if get(t, s, a.Id).Favorite || !get(t, s, "lib-l2-stp").Favorite {
		t.Error("GetScript no refleja el favorito")
	}
	_, err := s.SetFavorite(bg, &v1.SetFavoriteRequest{Id: "no-existe", Favorite: true})
	codigo(t, err, codes.NotFound)
	if !strings.Contains(d.AuditText(), "scripts.favorito") {
		t.Error("sin auditoría de favorito")
	}
}

func TestDuplicar(t *testing.T) {
	s, _ := nuevoSvc(t)
	a := guardar(t, s, "Uno", "show clock")
	c1, err := s.DuplicateScript(bg, &v1.DuplicateScriptRequest{Id: a.Id})
	if err != nil || c1.Script.Name != "Uno (copia)" || c1.Script.Id == a.Id || c1.Script.Origin != "usuario" || c1.Script.Commands[0] != "show clock" {
		t.Fatalf("copia = %v err = %v", c1, err)
	}
	if c2, _ := s.DuplicateScript(bg, &v1.DuplicateScriptRequest{Id: a.Id}); c2.Script.Name != "Uno (copia 2)" {
		t.Errorf("segunda copia = %q", c2.Script.Name)
	}
	// duplicar uno de la biblioteca da un script del usuario editable
	l, err := s.DuplicateScript(bg, &v1.DuplicateScriptRequest{Id: "lib-l2-stp"})
	if err != nil || l.Script.Origin != "usuario" || strings.HasPrefix(l.Script.Id, "lib-") {
		t.Fatalf("copia de biblioteca = %v err = %v", l, err)
	}
	l.Script.Description = "mía"
	if _, err := s.SaveScript(bg, &v1.SaveScriptRequest{Script: l.Script}); err != nil {
		t.Fatalf("editar la copia: %v", err)
	}
	_, err = s.DuplicateScript(bg, &v1.DuplicateScriptRequest{Id: "nada"})
	codigo(t, err, codes.NotFound)
}

func TestPersistenciaTrasReabrirElStore(t *testing.T) {
	d := servicetest.New(t)
	path := filepath.Join(t.TempDir(), "x.db")
	abrir := func() (*svc, *sql.DB) {
		db, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		return &svc{d: dbDeps{d, db}, packs: iosxe(t)}, db
	}
	s, db := abrir()
	a := guardar(t, s, "Persistente", "show clock")
	s.SetFavorite(bg, &v1.SetFavoriteRequest{Id: a.Id, Favorite: true})
	s.SetFavorite(bg, &v1.SetFavoriteRequest{Id: "lib-l2-stp", Favorite: true})
	db.Close()
	s, db = abrir()
	defer db.Close()
	g := get(t, s, a.Id)
	if g.Name != "Persistente" || !g.Favorite || g.Commands[0] != "show clock" || g.CreatedMs != a.CreatedMs {
		t.Fatalf("tras reabrir = %v", g)
	}
	if !get(t, s, "lib-l2-stp").Favorite {
		t.Error("el favorito de la biblioteca se perdió")
	}
}

// dbDeps cambia solo la base de datos de servicetest.Deps.
type dbDeps struct {
	*servicetest.Deps
	db *sql.DB
}

func (x dbDeps) DB() *sql.DB { return x.db }

// ---- export / import ----

func llena(t *testing.T, s *svc, n int) []string {
	t.Helper()
	var ids []string
	for i := 0; i < n; i++ {
		ids = append(ids, guardar(t, s, fmt.Sprintf("script %02d", i), fmt.Sprintf("show vlan id %d", i+1)).Id)
	}
	return ids
}

func exportar(t *testing.T, s *svc, path string, ids ...string) {
	t.Helper()
	if _, err := s.ExportScripts(bg, &v1.ExportScriptsRequest{Ids: ids, Path: path}); err != nil {
		t.Fatalf("export: %v", err)
	}
}

func TestExportImportIdaYVuelta15Importa8(t *testing.T) {
	a, da := nuevoSvc(t)
	ids := llena(t, a, 15)
	path := filepath.Join(t.TempDir(), "a.json")
	if _, err := a.SetFavorite(bg, &v1.SetFavoriteRequest{Id: ids[0], Favorite: true}); err != nil {
		t.Fatal(err)
	}
	r, err := a.ExportScripts(bg, &v1.ExportScriptsRequest{Ids: append(append([]string{}, ids[:8]...), "lib-l2-stp"), Path: path})
	if err != nil || r.Count != 9 {
		t.Fatalf("export = %v err = %v", r, err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("permisos = %v", fi.Mode().Perm())
	}
	if au := da.AuditText(); !strings.Contains(au, "scripts.exportar") || !strings.Contains(au, path) || !strings.Contains(au, "8") {
		t.Errorf("auditoría de export: %s", au)
	}

	b, db := nuevoSvc(t)
	for i := 0; i < 4; i++ {
		guardar(t, b, fmt.Sprintf("propio %d", i), "show clock")
	}
	p, err := b.PreviewImport(bg, &v1.PreviewImportRequest{Path: path})
	if err != nil || len(p.Items) != 9 || p.Token == "" || p.ExpiresMs == 0 {
		t.Fatalf("preview = %v err = %v", p, err)
	}
	for _, it := range p.Items {
		// la biblioteca es la misma en las dos instalaciones: el script lib-* llega como «igual» y no se copia
		if want := map[bool]string{true: "igual", false: "nuevo"}[it.Script.Id == "lib-l2-stp"]; it.State != want {
			t.Errorf("%s: %s, quiero %s", it.Script.Name, it.State, want)
		}
	}
	ap, err := b.ApplyImport(bg, &v1.ApplyImportRequest{Token: p.Token})
	if err != nil || ap.Created != 8 || ap.Skipped != 1 {
		t.Fatalf("apply = %v err = %v", ap, err)
	}
	l, _ := b.ListScripts(bg, &v1.ListScriptsRequest{})
	var usuarios, favoritos int
	for _, sc := range l.Scripts {
		if sc.Origin == "usuario" {
			usuarios++
		}
		if sc.Favorite {
			favoritos++
		}
	}
	if usuarios != 12 || favoritos != 0 {
		t.Fatalf("usuarios=%d favoritos=%d (4 propios + 8 importados; los favoritos no viajan)", usuarios, favoritos)
	}
	// el token se gastó
	_, err = b.ApplyImport(bg, &v1.ApplyImportRequest{Token: p.Token})
	codigo(t, err, codes.NotFound)
	if au := db.AuditText(); !strings.Contains(au, "scripts.importar") || !strings.Contains(au, path) {
		t.Errorf("auditoría de import: %s", au)
	}
	// importar otra vez el mismo archivo: todo igual
	p2, _ := b.PreviewImport(bg, &v1.PreviewImportRequest{Path: path})
	for _, it := range p2.Items {
		if it.State != "igual" {
			t.Errorf("segunda vez %s: %s", it.Script.Name, it.State)
		}
	}
}

func TestImportEstadosYDecisiones(t *testing.T) {
	a, _ := nuevoSvc(t)
	llena(t, a, 3)
	path := filepath.Join(t.TempDir(), "a.json")
	l, _ := a.ListScripts(bg, &v1.ListScriptsRequest{Text: "script 0"})
	var ids []string
	for _, sc := range l.Scripts {
		ids = append(ids, sc.Id)
	}
	exportar(t, a, path, ids...)

	b, _ := nuevoSvc(t)
	// mismo ID y contenido -> igual; mismo ID otro contenido -> conflicto_id; otro ID mismo nombre -> conflicto_nombre
	for _, sc := range l.Scripts {
		switch sc.Name {
		case "script 00":
			b.d.DB().Exec(`INSERT INTO scripts VALUES(?,?,?,?,?,?,?,?,?)`, sc.Id, sc.Name, sc.Tech, sc.Platform, sc.Description, `["show vlan id 1"]`, `[]`, time.UnixMilli(sc.CreatedMs).UTC().Format(time.RFC3339), time.UnixMilli(sc.UpdatedMs).UTC().Format(time.RFC3339))
		case "script 01":
			b.d.DB().Exec(`INSERT INTO scripts VALUES(?,?,?,?,?,?,?,?,?)`, sc.Id, sc.Name, sc.Tech, sc.Platform, sc.Description, `["show clock"]`, `[]`, time.UnixMilli(sc.CreatedMs).UTC().Format(time.RFC3339), time.UnixMilli(sc.UpdatedMs).UTC().Format(time.RFC3339))
		}
	}
	guardar(t, b, "script 02", "show clock")
	p, err := b.PreviewImport(bg, &v1.PreviewImportRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	est := map[string]string{}
	idDe := map[string]string{}
	for _, it := range p.Items {
		est[it.Script.Name], idDe[it.Script.Name] = it.State, it.Script.Id
	}
	if est["script 00"] != "igual" || est["script 01"] != "conflicto_id" || est["script 02"] != "conflicto_nombre" {
		t.Fatalf("estados = %v", est)
	}
	// falta una decisión: error y nada escrito; el token sigue vivo
	_, err = b.ApplyImport(bg, &v1.ApplyImportRequest{Token: p.Token, Decisions: []*v1.ImportDecision{{ScriptId: idDe["script 01"], Action: "reemplazar"}}})
	codigo(t, err, codes.InvalidArgument)
	if get(t, b, idDe["script 01"]).Commands[0] != "show clock" {
		t.Fatal("se escribió algo con una decisión faltante")
	}
	ap, err := b.ApplyImport(bg, &v1.ApplyImportRequest{Token: p.Token, Decisions: []*v1.ImportDecision{
		{ScriptId: idDe["script 01"], Action: "reemplazar"}, {ScriptId: idDe["script 02"], Action: "renombrar"}}})
	if err != nil || ap.Replaced != 1 || ap.Renamed != 1 || ap.Skipped != 1 || ap.Created != 0 {
		t.Fatalf("apply = %v err = %v", ap, err)
	}
	if get(t, b, idDe["script 01"]).Commands[0] != "show vlan id 2" {
		t.Error("reemplazar no cambió el contenido")
	}
	if r, _ := b.ListScripts(bg, &v1.ListScriptsRequest{Text: "script 02 (importado)"}); len(r.Scripts) != 1 {
		t.Errorf("renombrado: %d", len(r.Scripts))
	}
}

// Escenario del revisor: F1 (mismo ID que el guardado, otro nombre) y F2 (otro ID, el nombre del guardado)
// con «reemplazar» las dos: antes F1 se perdía en silencio.
func TestImportDosReemplazosSobreElMismoGuardado(t *testing.T) {
	s, _ := nuevoSvc(t)
	a := guardar(t, s, "N", "show version")
	f1 := dom.Script{ID: a.Id, Name: "M", Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}, Tags: []string{}, Origin: "usuario"}
	f2 := dom.Script{ID: dom.NewID(), Name: "N", Tech: "l2", Platform: "ios-xe", Commands: []string{"show users"}, Tags: []string{}, Origin: "usuario"}
	pr := previewDe(t, s, f1, f2)
	_, err := s.ApplyImport(bg, &v1.ApplyImportRequest{Token: pr.Token, Decisions: []*v1.ImportDecision{{ScriptId: f1.ID, Action: "reemplazar"}, {ScriptId: f2.ID, Action: "reemplazar"}}})
	codigo(t, err, codes.InvalidArgument)
	if g := get(t, s, a.Id); g.Name != "N" || g.Commands[0] != "show version" {
		t.Fatalf("se escribió algo: %v", g)
	}
	// la decisión inválida deja el token vivo para corregirla
	if _, err := s.ApplyImport(bg, &v1.ApplyImportRequest{Token: pr.Token, Decisions: []*v1.ImportDecision{{ScriptId: f1.ID, Action: "reemplazar"}, {ScriptId: f2.ID, Action: "renombrar"}}}); err != nil {
		t.Fatalf("reintento: %v", err)
	}
}

func previewDe(t *testing.T, s *svc, scs ...dom.Script) *v1.PreviewImportResponse {
	t.Helper()
	b, err := dom.Marshal(scs, s.clock())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "x.json")
	if err := service.WriteExport(context.Background(), p, b, false); err != nil {
		t.Fatal(err)
	}
	pr, err := s.PreviewImport(bg, &v1.PreviewImportRequest{Path: p})
	if err != nil {
		t.Fatal(err)
	}
	return pr
}

// Dos ApplyImport del mismo token a la vez: solo uno puede aplicarlo.
func TestImportMismoTokenEnParaleloSeAplicaUnaVez(t *testing.T) {
	s, _ := nuevoSvc(t)
	a := guardar(t, s, "Base", "show version")
	f := dom.Script{ID: a.Id, Name: "Base", Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}, Tags: []string{}, Origin: "usuario"}
	pr := previewDe(t, s, f)
	var wg sync.WaitGroup
	var ok, fallo int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ApplyImport(bg, &v1.ApplyImportRequest{Token: pr.Token, Decisions: []*v1.ImportDecision{{ScriptId: f.ID, Action: "renombrar"}}})
			if err == nil {
				atomic.AddInt32(&ok, 1)
			} else {
				atomic.AddInt32(&fallo, 1)
			}
		}()
	}
	wg.Wait()
	l, _ := s.ListScripts(bg, &v1.ListScriptsRequest{Text: "base"})
	n := 0
	for _, x := range l.Scripts {
		if x.Origin == "usuario" {
			n++
		}
	}
	if ok != 1 || fallo != 7 || n != 2 {
		t.Fatalf("aplicados=%d rechazados=%d scripts con «base»=%d (quiero 1, 7 y 2)", ok, fallo, n)
	}
}

func TestNombresDeLaBibliotecaEstanOcupados(t *testing.T) {
	s, _ := nuevoSvc(t)
	lib, _ := s.library()
	nombre := lib[0].Name
	_, err := s.SaveScript(bg, &v1.SaveScriptRequest{Script: &v1.Script{Name: strings.ToUpper(nombre), Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}}})
	codigo(t, err, codes.AlreadyExists)
	// editar un propio hacia el nombre de la biblioteca también
	a := guardar(t, s, "Mio", "show clock")
	_, err = s.SaveScript(bg, &v1.SaveScriptRequest{Script: &v1.Script{Id: a.Id, Name: nombre, Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}}})
	codigo(t, err, codes.AlreadyExists)
	// duplicar da un nombre libre aunque exista el «(copia)» en la biblioteca
	d, err := s.DuplicateScript(bg, &v1.DuplicateScriptRequest{Id: lib[0].ID})
	if err != nil || d.Script.Name != nombre+" (copia)" {
		t.Fatalf("dup = %v %v", d, err)
	}
	// importar un script del usuario con el nombre de uno de la biblioteca: conflicto contra la biblioteca
	f := dom.Script{ID: dom.NewID(), Name: nombre, Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}, Tags: []string{}, Origin: "usuario"}
	pr := previewDe(t, s, f)
	if it := pr.Items[0]; it.State != "conflicto_nombre" || it.ConflictsWith != lib[0].ID {
		t.Fatalf("item = %v", it)
	}
	_, err = s.ApplyImport(bg, &v1.ApplyImportRequest{Token: pr.Token, Decisions: []*v1.ImportDecision{{ScriptId: f.ID, Action: "reemplazar"}}})
	codigo(t, err, codes.InvalidArgument)
	if _, err := s.ApplyImport(bg, &v1.ApplyImportRequest{Token: pr.Token, Decisions: []*v1.ImportDecision{{ScriptId: f.ID, Action: "renombrar"}}}); err != nil {
		t.Fatal(err)
	}
}

// Un export de un script de la biblioteca ajena junto a uno propio con el mismo nombre ya no puede quedar imposible de reimportar.
func TestExportDeBibliotecaYPropiosSiempreSeReimporta(t *testing.T) {
	s, _ := nuevoSvc(t)
	ids := []string{"lib-l2-stp"}
	// un lib-* de otra instalación se importa como propio (nombre distinto del de la local) y se exporta junto a la biblioteca
	ajeno := dom.Script{ID: "lib-otro", Name: "Ajeno", Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}, Tags: []string{}, Origin: "biblioteca"}
	pr := previewDe(t, s, ajeno)
	if _, err := s.ApplyImport(bg, &v1.ApplyImportRequest{Token: pr.Token}); err != nil {
		t.Fatal(err)
	}
	l, _ := s.ListScripts(bg, &v1.ListScriptsRequest{Text: "ajeno"})
	for _, x := range l.Scripts {
		if x.Origin == "usuario" {
			ids = append(ids, x.Id)
		}
	}
	path := filepath.Join(t.TempDir(), "x.json")
	exportar(t, s, path, ids...)
	if _, err := s.PreviewImport(bg, &v1.PreviewImportRequest{Path: path}); err != nil {
		t.Fatalf("el export no se puede reimportar: %v", err)
	}
	// si una biblioteca nueva trajera un nombre ya usado por un propio, el export se niega en vez de escribir un archivo roto
	s.d.DB().Exec(`INSERT INTO scripts VALUES(?,?,?,?,?,?,?,?,?)`, dom.NewID(), "L2 · STP", "l2", "ios-xe", "", `["show clock"]`, `[]`, "2026-11-07T00:00:00Z", "2026-11-07T00:00:00Z")
	l, _ = s.ListScripts(bg, &v1.ListScriptsRequest{Text: "L2 · STP"})
	var dos []string
	for _, x := range l.Scripts {
		dos = append(dos, x.Id)
	}
	_, err := s.ExportScripts(bg, &v1.ExportScriptsRequest{Ids: dos, Path: filepath.Join(t.TempDir(), "y.json")})
	codigo(t, err, codes.InvalidArgument)
}

func TestExportRechazaLoQueElImportNoAceptaria(t *testing.T) {
	s, _ := nuevoSvc(t)
	cmds := make([]string, 200)
	for i := range cmds {
		cmds[i] = strings.Repeat("x", 512)
	}
	var ids []string
	raw, _ := json.Marshal(cmds)
	for i := 0; i < 60; i++ { // ~100 KB cada uno: pasan de 5 MB juntos (directo a la base, SaveScript tarda)
		id := dom.NewID()
		if _, err := s.d.DB().Exec(`INSERT INTO scripts VALUES(?,?,?,?,?,?,?,?,?)`, id, fmt.Sprintf("grande %02d", i), "l2", "ios-xe", "", string(raw), `[]`, "2026-11-07T00:00:00Z", "2026-11-07T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	path := filepath.Join(t.TempDir(), "g.json")
	_, err := s.ExportScripts(bg, &v1.ExportScriptsRequest{Ids: ids, Path: path})
	codigo(t, err, codes.InvalidArgument)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("se escribió un archivo que el import rechazaría")
	}
	exportar(t, s, path, ids[:10]...)
}

func TestImportTokenVencidoYDesconocido(t *testing.T) {
	a, _ := nuevoSvc(t)
	ids := llena(t, a, 1)
	path := filepath.Join(t.TempDir(), "a.json")
	exportar(t, a, path, ids...)
	b, _ := nuevoSvc(t)
	ahora := time.Now()
	b.now = func() time.Time { return ahora }
	p, err := b.PreviewImport(bg, &v1.PreviewImportRequest{Path: path})
	if err != nil || p.ExpiresMs != ahora.Add(10*time.Minute).UnixMilli() {
		t.Fatalf("preview = %v err = %v", p, err)
	}
	_, err = b.ApplyImport(bg, &v1.ApplyImportRequest{Token: "desconocido"})
	codigo(t, err, codes.NotFound)
	b.now = func() time.Time { return ahora.Add(10*time.Minute + time.Second) }
	_, err = b.ApplyImport(bg, &v1.ApplyImportRequest{Token: p.Token})
	codigo(t, err, codes.FailedPrecondition)
	// un token vencido se gasta: no reaparece
	b.now = func() time.Time { return ahora }
	_, err = b.ApplyImport(bg, &v1.ApplyImportRequest{Token: p.Token})
	codigo(t, err, codes.NotFound)
}

func TestImportRechazaArchivosMalos(t *testing.T) {
	a, _ := nuevoSvc(t)
	ids := llena(t, a, 2)
	dir := t.TempDir()
	buena := filepath.Join(dir, "a.json")
	exportar(t, a, buena, ids...)
	raw, _ := os.ReadFile(buena)
	b, _ := nuevoSvc(t)
	preview := func(path string) error {
		_, err := b.PreviewImport(bg, &v1.PreviewImportRequest{Path: path})
		return err
	}
	// un byte cambiado: error de suma
	mal := filepath.Join(dir, "mal.json")
	os.WriteFile(mal, []byte(strings.Replace(string(raw), "show vlan id 1", "show vlan id 7", 1)), 0o600)
	if err := preview(mal); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "suma") {
		t.Errorf("suma: %v", err)
	}
	// más de 5 MB (se rechaza antes de leerlo entero)
	grande := filepath.Join(dir, "grande.json")
	os.WriteFile(grande, make([]byte, 5<<20+1), 0o600)
	if err := preview(grande); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "5 MB") {
		t.Errorf("tamaño: %v", err)
	}
	// no regular: carpeta y FIFO (no se bloquea)
	if err := preview(dir); err == nil {
		t.Error("una carpeta debió fallar")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := sys.Mkfifo(fifo); err != nil {
		t.Fatal(err)
	}
	if err := preview(fifo); err == nil {
		t.Error("una FIFO debió fallar")
	}
	if err := preview("relativa.json"); status.Code(err) != codes.InvalidArgument {
		t.Errorf("ruta relativa: %v", err)
	}
	if err := preview(filepath.Join(dir, "no-existe.json")); err == nil {
		t.Error("archivo inexistente debió fallar")
	}
}

func TestExportNoSobrescribeNiSigueEnlaces(t *testing.T) {
	s, _ := nuevoSvc(t)
	ids := llena(t, s, 2)
	dir := t.TempDir()
	path := filepath.Join(dir, "a.json")
	exportar(t, s, path, ids[0])
	_, err := s.ExportScripts(bg, &v1.ExportScriptsRequest{Ids: ids, Path: path})
	codigo(t, err, codes.AlreadyExists)
	if raw, _ := os.ReadFile(path); strings.Contains(string(raw), "script 01") {
		t.Fatal("se sobrescribió sin overwrite")
	}
	if _, err := s.ExportScripts(bg, &v1.ExportScriptsRequest{Ids: ids, Path: path, Overwrite: true}); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), "script 01") {
		t.Fatal("overwrite no escribió")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("permisos tras overwrite = %v", fi.Mode().Perm())
	}
	// un enlace simbólico en la ruta: ni con overwrite se escribe en su destino
	victima := filepath.Join(dir, "victima.txt")
	os.WriteFile(victima, []byte("intacto"), 0o600)
	enlace := filepath.Join(dir, "enlace.json")
	os.Symlink(victima, enlace)
	for _, ow := range []bool{false, true} {
		if _, err := s.ExportScripts(bg, &v1.ExportScriptsRequest{Ids: ids, Path: enlace, Overwrite: ow}); err == nil {
			t.Errorf("enlace simbólico (overwrite=%v) debió fallar", ow)
		}
	}
	if raw, _ := os.ReadFile(victima); string(raw) != "intacto" {
		t.Fatalf("se escribió a través del enlace: %q", raw)
	}
	// otras entradas inválidas
	for nombre, req := range map[string]*v1.ExportScriptsRequest{
		"ruta relativa":  {Ids: ids, Path: "a.json"},
		"sin ids":        {Path: filepath.Join(dir, "b.json")},
		"id inexistente": {Ids: []string{"nada"}, Path: filepath.Join(dir, "c.json")},
		"carpeta":        {Ids: ids, Path: dir, Overwrite: true},
	} {
		if _, err := s.ExportScripts(bg, req); err == nil {
			t.Errorf("%s debió fallar", nombre)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "c.json")); err == nil {
		t.Error("un export fallido dejó archivo")
	}
}
