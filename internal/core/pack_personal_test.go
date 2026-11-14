package core

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/pack"
)

func (h *harness) saveScript(t *testing.T, name, plat string, cmds ...string) *v1.Script {
	t.Helper()
	r, err := v1.NewScriptsServiceClient(h.conn).SaveScript(ctx(t), &v1.SaveScriptRequest{Script: &v1.Script{Name: name, Tech: "l3", Platform: plat,
		Description: "d " + name, Commands: cmds, Tags: []string{"a", "b"}}})
	if err != nil {
		t.Fatal(err)
	}
	return r.Script
}

func (h *harness) userScripts(t *testing.T) map[string]*v1.Script {
	t.Helper()
	r, err := v1.NewScriptsServiceClient(h.conn).ListScripts(ctx(t), &v1.ListScriptsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]*v1.Script{}
	for _, s := range r.Scripts {
		if s.Origin == "usuario" {
			m[s.Name] = s
		}
	}
	return m
}

func (h *harness) userPlaybookFile(t *testing.T, file, id, plat string) {
	t.Helper()
	dir := filepath.Join(h.p.Config, "playbooks")
	os.MkdirAll(dir, 0o700)
	y := fmt.Sprintf("id: %s\nplatform: %s\nname: Mío %s\nname_en: Mine %s\ncommands:\n  - cmd: show clock\n    timeout: 2m\n", id, plat, id, id)
	if err := os.WriteFile(filepath.Join(dir, file), []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Review Focus 3: export → import ida y vuelta, en caliente. Los scripts vuelven idénticos y el playbook entra con su ID con prefijo.
func TestPackPersonalIdaYVuelta(t *testing.T) {
	h := newHarness(t, nil)
	a := h.saveScript(t, "Uno", "ios", "show version", "!comentario", "show clock")
	b := h.saveScript(t, "Dos", "cualquiera", "show ip route")
	h.userPlaybookFile(t, "mio.yaml", "mio", "ios-xe")
	h.userPlaybookFile(t, "nx.yaml", "nx", "nx-os")
	h.restart(t)
	pk := v1.NewPackServiceClient(h.conn)
	out := filepath.Join(t.TempDir(), "p.mpack")
	ex, err := pk.Export(ctx(t), &v1.PackServiceExportRequest{EditorName: "acme/mio", ScriptIds: []string{a.Id, b.Id}, IncludePlaybooks: true, Path: out})
	if err != nil {
		t.Fatal(err)
	}
	if ex.Scripts != 2 || ex.Playbooks != 1 || !slices.Equal(ex.OmittedPlaybooks, []string{"nx-os/nx"}) {
		t.Fatalf("%+v", ex)
	}
	if _, err := pk.Export(ctx(t), &v1.PackServiceExportRequest{EditorName: "acme/mio", ScriptIds: []string{a.Id}, Path: out}); err == nil {
		t.Fatal("pisó el export")
	}
	raw, _ := os.ReadFile(out)
	if vp, err := pack.Verify(raw, "dev", nil); err != nil || vp.Official {
		t.Fatal(err)
	}
	// Se borran los originales y se importa: vuelven idénticos.
	sc := v1.NewScriptsServiceClient(h.conn)
	for _, s := range []*v1.Script{a, b} {
		if _, err := sc.DeleteScript(ctx(t), &v1.DeleteScriptRequest{Id: s.Id}); err != nil {
			t.Fatal(err)
		}
	}
	os.Remove(filepath.Join(h.p.Config, "playbooks", "mio.yaml"))
	h.restart(t)
	pk = v1.NewPackServiceClient(h.conn)
	pv, err := pk.Import(ctx(t), &v1.PackServiceImportRequest{Path: out})
	if err != nil || pv.Applied || len(pv.Items) != 3 {
		t.Fatalf("%+v %v", pv, err)
	}
	if len(h.userScripts(t)) != 0 {
		t.Fatal("la vista previa escribió")
	}
	if slices.Contains(h.playbookIDs(t), "ios-xe/acme-mio") {
		t.Fatal("la vista previa escribió el playbook")
	}
	ap, err := pk.Import(ctx(t), withImportSum(t, &v1.PackServiceImportRequest{Path: out, Confirm: true}))
	if err != nil || !ap.Applied || ap.ScriptsCreated != 2 || ap.PlaybooksCreated != 1 || !slices.Equal(ap.PlaybookIds, []string{"ios-xe/acme-mio"}) {
		t.Fatalf("%+v %v", ap, err)
	}
	got := h.userScripts(t)
	for _, want := range []*v1.Script{a, b} {
		g := got[want.Name]
		if g == nil || g.Id == want.Id || g.Origin != "usuario" || g.Tech != want.Tech || g.Platform != want.Platform || !slices.Equal(g.Commands, want.Commands) || !slices.Equal(g.Tags, want.Tags) || g.Description != want.Description {
			t.Fatalf("%s: %+v vs %+v", want.Name, g, want)
		}
	}
	if !slices.Contains(h.playbookIDs(t), "ios-xe/acme-mio") { // en caliente, sin reiniciar
		t.Fatal("el playbook importado no está en el catálogo")
	}
	// Segundo import: lo igual se omite solo, lo del playbook pide decisión y nunca se sobrescribe.
	pv, _ = pk.Import(ctx(t), &v1.PackServiceImportRequest{Path: out})
	states := map[string]string{}
	for _, it := range pv.Items {
		states[it.Kind] = it.State
	}
	if states["script"] != "igual" || states["playbook"] != "conflicto_id" {
		t.Fatalf("%+v", pv.Items)
	}
	_, err = pk.Import(ctx(t), withImportSum(t, &v1.PackServiceImportRequest{Path: out, Confirm: true}))
	if r, _ := reasonOf(err); r != "pack.err.import.missing" {
		t.Fatalf("%v", err)
	}
	_, err = pk.Import(ctx(t), withImportSum(t, &v1.PackServiceImportRequest{Path: out, Confirm: true, Decisions: []*v1.PackImportDecision{{ItemId: "ios-xe/acme-mio", Action: "reemplazar"}}}))
	if r, _ := reasonOf(err); r != "pack.err.import.decision" {
		t.Fatalf("%v", err)
	}
	ap, err = pk.Import(ctx(t), withImportSum(t, &v1.PackServiceImportRequest{Path: out, Confirm: true, Decisions: []*v1.PackImportDecision{{ItemId: "ios-xe/acme-mio", Action: "renombrar"}}}))
	if err != nil || ap.PlaybooksRenamed != 1 || !slices.Equal(ap.PlaybookIds, []string{"ios-xe/acme-mio-2"}) {
		t.Fatalf("%+v %v", ap, err)
	}
	if !slices.Contains(h.playbookIDs(t), "ios-xe/acme-mio-2") {
		t.Fatal("el renombrado no está en el catálogo")
	}
	au := h.auditText(t)
	for _, w := range []string{"pack.export", "pack.import", "playbooks_renamed=1", "sha256="} {
		if !strings.Contains(au, w) {
			t.Errorf("auditoría sin %q:\n%s", w, au)
		}
	}
	// Y el .mpack exportado se instala como paquete de solo lectura con allow_unsigned (no sin él).
	if _, err := pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: out})); err == nil {
		t.Fatal("instaló sin confirmar")
	}
}

func TestPackPersonalExportInstalable(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	a := h.saveScript(t, "Uno", "ios", "show version")
	out := filepath.Join(t.TempDir(), "p.mpack")
	if _, err := pk.Export(ctx(t), &v1.PackServiceExportRequest{EditorName: "acme/mio", ScriptIds: []string{a.Id}, Path: out}); err != nil {
		t.Fatal(err)
	}
	r, err := pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: out, AllowUnsigned: true}))
	if err != nil || r.Pack.Official || r.Pack.ScriptCount != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	// Con el paquete instalado, el script ya está (mismo contenido y nombre): sale «igual» y no se duplica.
	pv, err := pk.Import(ctx(t), &v1.PackServiceImportRequest{Path: out})
	if err != nil || pv.Items[0].State != "igual" || !strings.HasPrefix(pv.Items[0].ConflictsWith, "lib-acme-") {
		t.Fatalf("%+v %v", pv, err)
	}
}

func TestPackPersonalExportRechazos(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	a := h.saveScript(t, "Uno", "ios", "show version")
	out := filepath.Join(t.TempDir(), "p.mpack")
	cases := []struct {
		name   string
		req    *v1.PackServiceExportRequest
		reason string
	}{
		{"oom", &v1.PackServiceExportRequest{EditorName: "oom/x", ScriptIds: []string{a.Id}, Path: out}, "pack.err.editor.reserved"},
		{"vacío", &v1.PackServiceExportRequest{EditorName: "acme/x", Path: out}, "pack.err.export.empty"},
		{"script de biblioteca", &v1.PackServiceExportRequest{EditorName: "acme/x", ScriptIds: []string{"lib-tac-baseline"}, Path: out}, "scripts.svc.not_found"},
		{"ruta relativa", &v1.PackServiceExportRequest{EditorName: "acme/x", ScriptIds: []string{a.Id}, Path: "x.mpack"}, "file.err.path_abs"},
	}
	for _, c := range cases {
		_, err := pk.Export(ctx(t), c.req)
		if r, _ := reasonOf(err); r != c.reason {
			t.Errorf("%s: %q %v", c.name, r, err)
		}
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("escribió un export rechazado")
	}
}

func hostile(t *testing.T, mod func(map[string][]byte)) string {
	t.Helper()
	f := map[string][]byte{
		"manifest.yaml":            []byte("id: acme/evil\nversion: 1.0.0\nmin_core: 0.3.0\nname: E\nname_en: E\ndescription: d\ndescription_en: d\nplatforms: [ios-xe]\nauthor: a\nlicense: MIT\n"),
		"README.md":                []byte("x"),
		"playbooks/acme-evil.yaml": []byte("id: acme-evil\nplatform: ios-xe\nname: Evil\nname_en: Evil\ncommands:\n  - cmd: show clock\n"),
	}
	mod(f)
	z, err := pack.Zip(f)
	if err != nil {
		t.Fatal(err)
	}
	return writeMpack(t, z)
}

// Review Focus 4: un .mpack hostil importado no tapa la base, lo movido ni lo instalado, ni escribe fuera de <config>/playbooks.
func TestPackImportHostil(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	pb := func(id string) string {
		return "id: " + id + "\nplatform: ios-xe\nname: Evil\nname_en: Evil\ncommands:\n  - cmd: show clock\n"
	}
	cases := map[string]struct {
		mod    func(map[string][]byte)
		reason string
	}{
		"ID de la base": {func(f map[string][]byte) {
			delete(f, "playbooks/acme-evil.yaml")
			f["playbooks/tac-baseline.yaml"] = []byte(pb("tac-baseline"))
		}, "pack.err.id.prefix"},
		"ID movido": {func(f map[string][]byte) {
			delete(f, "playbooks/acme-evil.yaml")
			f["playbooks/l2-stp.yaml"] = []byte(pb("l2-stp"))
		}, "pack.err.id.prefix"},
		"editor movido": {func(f map[string][]byte) {
			f["manifest.yaml"] = []byte(strings.Replace(string(f["manifest.yaml"]), "acme/evil", "l2/evil", 1))
		}, "pack.err.id.prefix"},
		"ruta con ..":   {func(f map[string][]byte) { f["playbooks/../../escape.yaml"] = []byte(pb("escape")) }, "pack.err.zip.path"},
		"ruta absoluta": {func(f map[string][]byte) { f["/tmp/escape.yaml"] = []byte(pb("escape")) }, "pack.err.zip.path"},
		"nombre raro":   {func(f map[string][]byte) { f["playbooks/a b;x.yaml"] = []byte(pb("escape")) }, "pack.err.zip.path"},
		"comando de cambio": {func(f map[string][]byte) {
			f["playbooks/acme-evil.yaml"] = []byte(strings.Replace(pb("acme-evil"), "show clock", "reload", 1))
		}, "pack.err.playbook.denied"},
	}
	for name, c := range cases {
		_, err := pk.Import(ctx(t), withImportSum(t, &v1.PackServiceImportRequest{Path: hostile(t, c.mod), Confirm: true}))
		if r, _ := reasonOf(err); r != c.reason {
			t.Errorf("%s: %q %v", name, r, err)
		}
	}
	if es, _ := os.ReadDir(filepath.Join(h.p.Config, "playbooks")); len(es) != 0 {
		t.Fatalf("escribió: %v", es)
	}
	for _, f := range []string{"escape.yaml", filepath.Join("..", "escape.yaml")} {
		if _, err := os.Stat(filepath.Join(h.p.Config, "playbooks", f)); err == nil {
			t.Fatal("salió de la carpeta")
		}
	}
	// Choque con un paquete instalado del mismo editor: pide decisión; nunca lo tapa.
	if _, err := pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: hostile(t, func(map[string][]byte) {}), AllowUnsigned: true})); err != nil {
		t.Fatal(err)
	}
	other := hostile(t, func(f map[string][]byte) {
		f["manifest.yaml"] = []byte(strings.Replace(string(f["manifest.yaml"]), "acme/evil", "acme/otro", 1))
	})
	pv, err := pk.Import(ctx(t), &v1.PackServiceImportRequest{Path: other})
	if err != nil || len(pv.Items) != 1 || pv.Items[0].State != "conflicto_id" || pv.Items[0].ConflictsWith != "acme/evil" {
		t.Fatalf("%+v %v", pv, err)
	}
	if _, err := pk.Import(ctx(t), withImportSum(t, &v1.PackServiceImportRequest{Path: other, Confirm: true})); err == nil {
		t.Fatal("aplicó un choque sin decisión")
	}
	if es, _ := os.ReadDir(filepath.Join(h.p.Config, "playbooks")); len(es) != 0 {
		t.Fatalf("escribió: %v", es)
	}
	// Enlace simbólico en la carpeta de playbooks: no desvía la escritura.
	fuera := t.TempDir()
	dir := filepath.Join(h.p.Config, "playbooks")
	os.MkdirAll(dir, 0o700)
	if err := os.Symlink(filepath.Join(fuera, "robado.yaml"), filepath.Join(dir, "acme-evil.yaml")); err != nil {
		t.Fatal(err)
	}
	pv, _ = pk.Import(ctx(t), &v1.PackServiceImportRequest{Path: other})
	if pv.Items[0].State != "conflicto_id" {
		t.Fatalf("%+v", pv.Items)
	}
	pk.Import(ctx(t), withImportSum(t, &v1.PackServiceImportRequest{Path: other, Confirm: true, Decisions: []*v1.PackImportDecision{{ItemId: "ios-xe/acme-evil", Action: "omitir"}}}))
	if es, _ := os.ReadDir(fuera); len(es) != 0 {
		t.Fatalf("escribió por el enlace: %v", es)
	}
}

// Review Focus 5: recargar el catálogo al importar mientras se listan playbooks y se arma otro catálogo no corre carreras.
func TestPackImportRecargaConcurrente(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					h.playbookIDs(t)
				}
			}
		}()
	}
	for i := range 4 {
		p := hostile(t, func(f map[string][]byte) {
			delete(f, "playbooks/acme-evil.yaml")
			id := fmt.Sprintf("acme-p%d", i)
			f["playbooks/"+id+".yaml"] = []byte("id: " + id + "\nplatform: ios\nname: P\nname_en: P\ncommands:\n  - cmd: show clock\n")
			f["manifest.yaml"] = []byte(strings.Replace(string(f["manifest.yaml"]), "[ios-xe]", "[ios]", 1))
		})
		if _, err := pk.Import(ctx(t), withImportSum(t, &v1.PackServiceImportRequest{Path: p, Confirm: true})); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if !slices.Contains(h.playbookIDs(t), "ios/acme-p3") {
		t.Fatal("falta el último")
	}
}

// Importar nunca reemplaza un script: con el mismo nombre y otro contenido solo se renombra u omite.
func TestPackImportNuncaReemplazaScripts(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	a := h.saveScript(t, "Uno", "ios", "show version")
	out := filepath.Join(t.TempDir(), "p.mpack")
	if _, err := pk.Export(ctx(t), &v1.PackServiceExportRequest{EditorName: "acme/mio", ScriptIds: []string{a.Id}, Path: out}); err != nil {
		t.Fatal(err)
	}
	sc := v1.NewScriptsServiceClient(h.conn)
	a.Commands = []string{"show clock"}
	if _, err := sc.SaveScript(ctx(t), &v1.SaveScriptRequest{Script: a}); err != nil {
		t.Fatal(err)
	}
	pv, err := pk.Import(ctx(t), &v1.PackServiceImportRequest{Path: out})
	if err != nil || pv.Items[0].State != "conflicto_nombre" {
		t.Fatalf("%+v %v", pv, err)
	}
	_, err = pk.Import(ctx(t), withImportSum(t, &v1.PackServiceImportRequest{Path: out, Confirm: true, Decisions: []*v1.PackImportDecision{{ItemId: pv.Items[0].Id, Action: "reemplazar"}}}))
	if r, _ := reasonOf(err); r != "pack.err.import.decision" {
		t.Fatalf("%v", err)
	}
	if got := h.userScripts(t)["Uno"]; got.Commands[0] != "show clock" || len(h.userScripts(t)) != 1 {
		t.Fatal("tocó el script")
	}
	ap, err := pk.Import(ctx(t), withImportSum(t, &v1.PackServiceImportRequest{Path: out, Confirm: true, Decisions: []*v1.PackImportDecision{{ItemId: pv.Items[0].Id, Action: "renombrar"}}}))
	if err != nil || ap.ScriptsRenamed != 1 || len(h.userScripts(t)) != 2 || h.userScripts(t)["Uno"].Commands[0] != "show clock" {
		t.Fatalf("%+v %v", ap, err)
	}
}

// Dos imports a la vez con playbooks distintos: los dos quedan en el catálogo (leer, guardar y armar van bajo un solo lock).
func TestPackImportsConcurrentesConservanTodo(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	mk := func(id string) string {
		return hostile(t, func(f map[string][]byte) {
			delete(f, "playbooks/acme-evil.yaml")
			f["playbooks/"+id+".yaml"] = []byte("id: " + id + "\nplatform: ios\nname: P\nname_en: P\ncommands:\n  - cmd: show clock\n")
			f["manifest.yaml"] = []byte(strings.Replace(string(f["manifest.yaml"]), "[ios-xe]", "[ios]", 1))
		})
	}
	for i := range 15 {
		a, b := mk(fmt.Sprintf("acme-a%d", i)), mk(fmt.Sprintf("acme-b%d", i))
		var wg sync.WaitGroup
		for _, p := range []string{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := pk.Import(ctx(t), withImportSum(t, &v1.PackServiceImportRequest{Path: p, Confirm: true})); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		ids := h.playbookIDs(t)
		if !slices.Contains(ids, fmt.Sprintf("ios/acme-a%d", i)) || !slices.Contains(ids, fmt.Sprintf("ios/acme-b%d", i)) {
			t.Fatalf("ronda %d: falta un playbook importado", i)
		}
	}
}

// La vista previa se ata a lo que se aplica: si el archivo cambió entre las dos llamadas, no se aplica nada.
func TestPackImportSha256AtaLaVistaPrevia(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	path := hostile(t, func(map[string][]byte) {})
	pv, err := pk.Import(ctx(t), &v1.PackServiceImportRequest{Path: path})
	if err != nil || len(pv.Sha256) != 64 {
		t.Fatalf("%+v %v", pv, err)
	}
	_, err = pk.Import(ctx(t), &v1.PackServiceImportRequest{Path: path, Confirm: true, Sha256: strings.Repeat("0", 64)})
	if r, _ := reasonOf(err); r != "pack.err.import.changed" {
		t.Fatalf("%v", err)
	}
	if es, _ := os.ReadDir(filepath.Join(h.p.Config, "playbooks")); len(es) != 0 {
		t.Fatal("aplicó con otra suma")
	}
	if _, err := pk.Import(ctx(t), &v1.PackServiceImportRequest{Path: path, Confirm: true, Sha256: pv.Sha256}); err != nil {
		t.Fatal(err)
	}
}

// Solo playbooks (0 scripts) se exporta; con 0 de todo, no.
func TestPackExportSoloPlaybooks(t *testing.T) {
	h := newHarness(t, nil)
	h.userPlaybookFile(t, "mio.yaml", "mio", "ios-xe")
	h.restart(t)
	pk := v1.NewPackServiceClient(h.conn)
	r, err := pk.Export(ctx(t), &v1.PackServiceExportRequest{EditorName: "acme/mio", IncludePlaybooks: true, Path: filepath.Join(t.TempDir(), "p.mpack")})
	if err != nil || r.Playbooks != 1 || r.Scripts != 0 {
		t.Fatalf("%+v %v", r, err)
	}
}

// Orden de candados: el almacén de paquetes primero y la base después, en Install y en Import. Con un Install dentro
// del almacén, un Import no debe quedarse con el bloqueo de escritura de la base (haría fallar al Install por busy_timeout).
func TestPackImportNoTomaLaBaseAntesDelAlmacen(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	a := h.saveScript(t, "Uno", "ios", "show version")
	out := filepath.Join(t.TempDir(), "p.mpack")
	if _, err := pk.Export(ctx(t), &v1.PackServiceExportRequest{EditorName: "acme/mio", ScriptIds: []string{a.Id}, Path: out}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	inside, release, installed := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := h.core.packs.InstallWith(raw, true, func(*pack.Pack, string) error { close(inside); <-release; return nil }, nil)
		installed <- err
	}()
	<-inside // Install tiene el almacén
	imp := hostile(t, func(f map[string][]byte) {
		delete(f, "playbooks/acme-evil.yaml")
		f["playbooks/acme-p.yaml"] = []byte("id: acme-p\nplatform: ios\nname: P\nname_en: P\ncommands:\n  - cmd: show clock\n")
		f["manifest.yaml"] = []byte(strings.Replace(string(f["manifest.yaml"]), "[ios-xe]", "[ios]", 1))
	})
	done := make(chan error, 1)
	go func() {
		_, err := pk.Import(ctx(t), &v1.PackServiceImportRequest{Path: imp, Confirm: true})
		done <- err
	}()
	time.Sleep(300 * time.Millisecond) // el Import espera el almacén
	start := time.Now()
	if _, err := h.core.db.Exec(`CREATE TABLE IF NOT EXISTS zz_candados(x)`); err != nil || time.Since(start) > time.Second {
		t.Errorf("el Import retiene la base mientras espera el almacén: %v tras %v", err, time.Since(start))
	}
	close(release)
	if err := <-installed; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
