package core

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/pack"
	"github.com/oom-netsec/MACUAHUITL/internal/pack/packtest"
)

func writeMpack(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.mpack")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (h *harness) playbookIDs(t *testing.T) []string {
	t.Helper()
	r, err := h.patrol.ListPlaybooks(ctx(t), &v1.ListPlaybooksRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, p := range r.Playbooks {
		ids = append(ids, p.Id)
	}
	return ids
}

func (h *harness) scriptIDs(t *testing.T) []string {
	t.Helper()
	r, err := v1.NewScriptsServiceClient(h.conn).ListScripts(ctx(t), &v1.ListScriptsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range r.Scripts {
		ids = append(ids, s.Id)
	}
	return ids
}

// installIOSXE instala oom/ios-xe por el servicio, como lo haría «mctl pack install».
func (h *harness) installIOSXE(t *testing.T) {
	t.Helper()
	if _, err := v1.NewPackServiceClient(h.conn).Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: writeMpack(t, packtest.IOSXE(t))})); err != nil {
		t.Fatal(err)
	}
}

// Ida y vuelta en caliente: instalar suma playbooks y scripts sin reiniciar; quitar los quita, con sus favoritos.
func TestPackIdaYVueltaEnCaliente(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	if slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") || slices.Contains(h.scriptIDs(t), "lib-l2-stp") {
		t.Fatal("sin el paquete no debe estar ios-xe/l2-stp")
	}
	if !slices.Contains(h.playbookIDs(t), "ios-xe/tac-baseline") || !slices.Contains(h.scriptIDs(t), "lib-tac-baseline") {
		t.Fatal("el contenido base sigue embebido")
	}
	h.installIOSXE(t)
	if !slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") || !slices.Contains(h.scriptIDs(t), "lib-l2-stp") {
		t.Fatal("instalar no sumó el contenido")
	}
	l, err := pk.List(ctx(t), &v1.PackServiceListRequest{})
	if err != nil || len(l.Packs) != 1 || l.Packs[0].Id != "oom/ios-xe" || !l.Packs[0].Official || l.Packs[0].PlaybookCount < 50 {
		t.Fatalf("%+v %v", l, err)
	}
	sh, err := pk.Show(ctx(t), &v1.PackServiceShowRequest{Id: "oom/ios-xe"})
	if err != nil || !strings.Contains(sh.Readme, "mctl pack install") || !slices.Contains(sh.PlaybookIds, "ios-xe/l2-stp") || !slices.Contains(sh.ScriptIds, "lib-l2-stp") {
		t.Fatalf("show: %v", err)
	}
	// Un favorito del script del paquete se va con el paquete.
	sc := v1.NewScriptsServiceClient(h.conn)
	if _, err := sc.SetFavorite(ctx(t), &v1.SetFavoriteRequest{Id: "lib-l2-stp", Favorite: true}); err != nil {
		t.Fatal(err)
	}
	rm, err := pk.Remove(ctx(t), &v1.PackServiceRemoveRequest{Id: "oom/ios-xe"})
	if err != nil || rm.FavoritesRemoved != 1 {
		t.Fatalf("%+v %v", rm, err)
	}
	if slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") || slices.Contains(h.scriptIDs(t), "lib-l2-stp") {
		t.Fatal("quitar no sacó el contenido")
	}
	var n int
	h.core.db.QueryRow(`SELECT count(*) FROM script_collection_items WHERE script_id = 'lib-l2-stp'`).Scan(&n)
	if n != 0 {
		t.Fatal("el favorito quedó")
	}
	_, err = pk.Remove(ctx(t), &v1.PackServiceRemoveRequest{Id: "oom/ios-xe"})
	if r, _ := reasonOf(err); r != "pack.err.not_found" {
		t.Fatalf("%v", err)
	}
	au := h.auditText(t)
	for _, want := range []string{`"action":"pack.install"`, `origin=official`, `"action":"pack.remove"`, `favorites_removed=1`, `version=1.1.0`} {
		if !strings.Contains(au, want) {
			t.Errorf("la auditoría no trae %s:\n%s", want, au)
		}
	}
}

// pack.missing de punta a punta: sin el paquete, un trabajo con un playbook movido falla con el motivo estable;
// cualquier otro ID inexistente sigue con el error de siempre; tras instalar, el mismo trabajo arma.
func TestPackMissingDePuntaAPunta(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	mk := func(id string) error {
		s := h.spec(cred)
		s.CustomCommands, s.PlaybookIds = "", []string{id}
		_, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: s})
		return err
	}
	err := mk("ios-xe/plat-flash-fs")
	r, md := reasonOf(err)
	if r != "pack.missing" || md["playbook"] != "ios-xe/plat-flash-fs" || md["pack"] != "oom/ios-xe" {
		t.Fatalf("%q %v %v", r, md, err)
	}
	if !strings.Contains(err.Error(), "oom/ios-xe") {
		t.Fatalf("el texto debe decir qué paquete instalar: %v", err)
	}
	err = mk("ios-xe/no-existe")
	if r, _ := reasonOf(err); r != "patrol.field.no_playbook" || !strings.Contains(err.Error(), "ios-xe/no-existe no existe") {
		t.Fatalf("%v", err)
	}
	h.installIOSXE(t)
	if err := mk("ios-xe/plat-flash-fs"); err != nil {
		t.Fatal(err)
	}
}

// Un paquete de terceros quitado también deja su motivo (se anota en la base) y la lista de movidos no interviene.
func TestPackMissingDeUnPaqueteQuitado(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	files := map[string][]byte{
		"manifest.yaml":         []byte("id: acme/demo\nversion: 1.0.0\nmin_core: 0.3.0\nname: Demo\nname_en: Demo\ndescription: d\ndescription_en: d\nplatforms: [ios-xe]\nauthor: a\nlicense: MIT\n"),
		"README.md":             []byte("x"),
		"playbooks/acme-a.yaml": []byte("id: acme-a\nplatform: ios-xe\nname: \"Acme · A\"\nname_en: \"Acme · A\"\ncommands:\n  - cmd: show clock\n"),
	}
	zb, err := pack.Zip(files)
	if err != nil {
		t.Fatal(err)
	}
	pk := v1.NewPackServiceClient(h.conn)
	p := writeMpack(t, zb)
	_, err = pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: p}))
	if r, _ := reasonOf(err); r != "pack.err.unsigned" {
		t.Fatalf("sin confirmar: %v", err)
	}
	if _, err := pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: p, AllowUnsigned: true})); err != nil {
		t.Fatal(err)
	}
	if _, err := pk.Remove(ctx(t), &v1.PackServiceRemoveRequest{Id: "acme/demo"}); err != nil {
		t.Fatal(err)
	}
	s := h.spec(cred)
	s.CustomCommands, s.PlaybookIds = "", []string{"ios-xe/acme-a"}
	_, err = h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: s})
	if r, md := reasonOf(err); r != "pack.missing" || md["pack"] != "acme/demo" {
		t.Fatalf("%q %v %v", r, md, err)
	}
	au := h.auditText(t)
	if !strings.Contains(au, "id=acme/demo version=1.0.0") || !strings.Contains(au, "origin=third-party") || !strings.Contains(au, "reason=unsigned") || !strings.Contains(au, `"action":"pack.rejected"`) {
		t.Fatalf("auditoría:\n%s", au)
	}
}

// Un trabajo creado conserva el catálogo que tenía: quitar el paquete después no le quita los playbooks.
func TestPackTrabajoConservaSuCatalogo(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	h.installIOSXE(t)
	s := h.spec(cred)
	s.CustomCommands, s.PlaybookIds = "", []string{"ios-xe/plat-flash-fs"}
	cj, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: s})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v1.NewPackServiceClient(h.conn).Remove(ctx(t), &v1.PackServiceRemoveRequest{Id: "oom/ios-xe"}); err != nil {
		t.Fatal(err)
	}
	j, err := h.core.getJob(cj.JobId)
	if err != nil {
		t.Fatal(err)
	}
	has := func(pbs []string) bool { return slices.Contains(pbs, "ios-xe/plat-flash-fs") }
	var mine []string
	for _, p := range h.core.deps(j).Playbooks {
		mine = append(mine, p.ID)
	}
	if !has(mine) {
		t.Fatal("el trabajo perdió su playbook")
	}
	if has(h.playbookIDs(t)) {
		t.Fatal("el catálogo vigente debía perderlo")
	}
}

// Al arrancar se revalida: un archivo alterado en disco omite el paquete, se audita en inglés y el núcleo sigue.
func TestPackAlteradoSeOmiteAlArrancar(t *testing.T) {
	h := newHarness(t, nil)
	h.installIOSXE(t)
	if err := os.WriteFile(filepath.Join(h.p.Data, "packs", "oom", "ios-xe", "README.md"), []byte("alterado"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.restart(t)
	if slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") {
		t.Fatal("el paquete alterado quedó cargado")
	}
	if !slices.Contains(h.playbookIDs(t), "ios-xe/tac-baseline") {
		t.Fatal("el núcleo debe seguir con el contenido base")
	}
	au := h.auditText(t)
	if !strings.Contains(au, `"action":"pack.rejected"`) || !strings.Contains(au, "reason=index.mismatch") || !strings.Contains(au, "stage=startup") {
		t.Fatalf("auditoría:\n%s", au)
	}
}

// Los .tmp-* que dejó un cierre a medias se limpian al arrancar, y un paquete válido sobrevive al reinicio.
func TestPackSobreviveAlReinicio(t *testing.T) {
	h := newHarness(t, nil)
	h.installIOSXE(t)
	os.MkdirAll(filepath.Join(h.p.Data, "packs", ".tmp-viejo"), 0o700)
	h.restart(t)
	if !slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") {
		t.Fatal("el paquete no sobrevivió al reinicio")
	}
	if _, err := os.Stat(filepath.Join(h.p.Data, "packs", ".tmp-viejo")); !os.IsNotExist(err) {
		t.Fatal("no se limpió .tmp")
	}
}

// Un paquete rechazado no deja ni la ruta absoluta del usuario en la metadata del error: solo en la auditoría, tal como la pasó.
func TestPackRechazoNoFiltraRutas(t *testing.T) {
	h := newHarness(t, nil)
	p := writeMpack(t, []byte("no es un zip"))
	_, err := v1.NewPackServiceClient(h.conn).Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: p}))
	r, md := reasonOf(err)
	if r != "pack.err.zip.invalid" {
		t.Fatalf("%v", err)
	}
	for k, v := range md {
		if strings.Contains(v, filepath.Dir(p)) {
			t.Errorf("la metadata %s trae la ruta: %q", k, v)
		}
	}
	if au := h.auditText(t); !strings.Contains(au, "reason=zip.invalid") || !strings.Contains(au, `sha256=`) {
		t.Fatalf("auditoría:\n%s", au)
	}
}

// Precedencia: base < paquetes < <config>/playbooks. Un playbook del usuario con el ID de uno del paquete lo tapa
// (la lista lo marca en shadowed) y no cuenta como choque.
func TestPackPrecedenciaYTapados(t *testing.T) {
	h := newHarness(t, nil)
	h.installIOSXE(t)
	dir := filepath.Join(h.p.Config, "playbooks")
	os.MkdirAll(dir, 0o700)
	y := "id: l2-stp\nplatform: ios-xe\nname: Mío · STP\ncommands:\n  - cmd: show clock\n"
	if err := os.WriteFile(filepath.Join(dir, "mio.yaml"), []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	h.restart(t)
	r, err := h.patrol.ListPlaybooks(ctx(t), &v1.ListPlaybooksRequest{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range r.Playbooks {
		if p.Id == "ios-xe/l2-stp" {
			n++
			if p.Name != "Mío · STP" {
				t.Fatalf("debía ganar el del usuario: %+v", p)
			}
		}
	}
	if n != 1 {
		t.Fatalf("el ID sale %d veces", n)
	}
	l, err := v1.NewPackServiceClient(h.conn).List(ctx(t), &v1.PackServiceListRequest{})
	if err != nil || len(l.Packs) != 1 || !slices.Equal(l.Packs[0].Shadowed, []string{"ios-xe/l2-stp"}) {
		t.Fatalf("%+v %v", l, err)
	}
}

// La ruta debe ser absoluta (como en los demás servicios de archivos); el rechazo por versión audita el id y la versión reales.
func TestPackRutaRelativaYAuditoriaDeRechazos(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	if _, err := pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: "x.mpack"})); err == nil || !strings.Contains(err.Error(), "absoluta") {
		t.Fatalf("%v", err)
	}
	h.installIOSXE(t)
	_, err := pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: writeMpack(t, packtest.IOSXE(t))}))
	if r, _ := reasonOf(err); r != "pack.err.version" {
		t.Fatalf("%v", err)
	}
	if au := h.auditText(t); !strings.Contains(au, "id=oom/ios-xe version=1.1.0") || !strings.Contains(au, "reason=version") {
		t.Fatalf("auditoría:\n%s", au)
	}
}

// C1 de punta a punta: un tercero no ocupa un ID movido a oom/ios-xe aunque el paquete oficial no esté instalado.
func TestPackTerceroNoOcupaIDsMovidos(t *testing.T) {
	h := newHarness(t, nil)
	files := map[string][]byte{
		"manifest.yaml":         []byte("id: l2/evil\nversion: 1.0.0\nmin_core: 0.3.0\nname: E\nname_en: E\ndescription: d\ndescription_en: d\nplatforms: [ios-xe]\nauthor: a\nlicense: MIT\n"),
		"README.md":             []byte("x"),
		"playbooks/l2-stp.yaml": []byte("id: l2-stp\nplatform: ios-xe\nname: \"Evil\"\nname_en: \"Evil\"\ncommands:\n  - cmd: show clock\n"),
	}
	zb, err := pack.Zip(files)
	if err != nil {
		t.Fatal(err)
	}
	_, err = v1.NewPackServiceClient(h.conn).Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: writeMpack(t, zb), AllowUnsigned: true}))
	if r, _ := reasonOf(err); r != "pack.err.editor.reserved" {
		t.Fatalf("%v", err)
	}
	if slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") {
		t.Fatal("el tercero ocupó ios-xe/l2-stp")
	}
}

// ioSXEVersion es oom/ios-xe del repo con otra versión, firmado con la llave de pruebas.
func ioSXEVersion(t *testing.T, v string, sin ...string) []byte {
	t.Helper()
	files, err := pack.ReadSource(filepath.Join(packtest.RepoDir(), "packs", "ios-xe"))
	if err != nil {
		t.Fatal(err)
	}
	m := string(files["manifest.yaml"])
	files["manifest.yaml"] = []byte(strings.Replace(m, "version: 1.1.0", "version: "+v, 1))
	for _, f := range sin { // archivos de playbook que esta versión ya no trae
		delete(files, f)
	}
	pack.Sign(files, packtest.Private())
	b, err := pack.Zip(files)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Fase 32b: un ID oculto sale de ListPlaybooks y de la biblioteca (con su lib-<id>), pero un trabajo lo sigue
// resolviendo; actualizar el paquete conserva lo oculto y quitarlo borra la elección.
func TestPackOcultarNoCambiaLoQueResuelve(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	h.installIOSXE(t)
	pk := v1.NewPackServiceClient(h.conn)
	sc := v1.NewScriptsServiceClient(h.conn)
	if _, err := sc.SetFavorite(ctx(t), &v1.SetFavoriteRequest{Id: "lib-l2-stp", Favorite: true}); err != nil {
		t.Fatal(err)
	}
	r, err := pk.SetItems(ctx(t), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe", Hide: []string{"ios-xe/l2-stp", "lib-plat-flash-fs"}})
	if err != nil || !slices.Equal(r.Pack.Hidden, []string{"ios-xe/l2-stp", "lib-plat-flash-fs"}) {
		t.Fatalf("%+v %v", r, err)
	}
	if slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") || slices.Contains(h.scriptIDs(t), "lib-l2-stp") {
		t.Fatal("el playbook oculto (o su lib-) sigue en las listas")
	}
	if slices.Contains(h.scriptIDs(t), "lib-plat-flash-fs") || !slices.Contains(h.playbookIDs(t), "ios-xe/plat-flash-fs") {
		t.Fatal("ocultar un script no debe ocultar su playbook, y sí al script")
	}
	if !slices.Contains(h.playbookIDs(t), "ios-xe/l1-poe") {
		t.Fatal("lo no oculto debe seguir")
	}
	// El trabajo que pide el ID oculto se arma (Review Focus 1).
	s := h.spec(cred)
	s.CustomCommands, s.PlaybookIds = "", []string{"ios-xe/l2-stp"}
	if _, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: s}); err != nil {
		t.Fatalf("un ID oculto debe seguir resolviéndose: %v", err)
	}
	// La colección lo conserva y lo marca oculto.
	gc, err := sc.GetCollection(ctx(t), &v1.GetCollectionRequest{Id: "favoritos"})
	if err != nil || !slices.Contains(gc.Collection.ScriptIds, "lib-l2-stp") || !slices.Equal(gc.Collection.HiddenScriptIds, []string{"lib-l2-stp"}) {
		t.Fatalf("%+v %v", gc, err)
	}
	// get del script oculto sigue (resolución por ID).
	if _, err := v1.NewScriptsServiceClient(h.conn).GetScript(ctx(t), &v1.GetScriptRequest{Id: "lib-l2-stp"}); err != nil {
		t.Fatal(err)
	}
	// Show y List informan lo oculto.
	sh, err := pk.Show(ctx(t), &v1.PackServiceShowRequest{Id: "oom/ios-xe"})
	if err != nil || len(sh.Pack.Hidden) != 2 {
		t.Fatalf("%+v %v", sh, err)
	}
	// Elementos ajenos o contradictorios: pack.err.item.
	for _, bad := range []*v1.PackServiceSetItemsRequest{
		{PackId: "oom/ios-xe", Hide: []string{"ios-xe/no-existe"}},
		{PackId: "oom/ios-xe", Hide: []string{"ios-xe/l1-poe"}, Show: []string{"ios-xe/l1-poe"}},
	} {
		if _, err := pk.SetItems(ctx(t), bad); err == nil {
			t.Fatal("debía fallar")
		} else if r, _ := reasonOf(err); r != "pack.err.item" {
			t.Fatalf("%v", err)
		}
	}
	// Actualizar: lo oculto se conserva; reinstalar nuevo ID entra visible.
	if _, err := pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: writeMpack(t, ioSXEVersion(t, "1.1.1"))})); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") {
		t.Fatal("la versión nueva perdió lo oculto")
	}
	// Mostrar de nuevo.
	if _, err := pk.SetItems(ctx(t), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe", Show: []string{"ios-xe/l2-stp"}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") || !slices.Contains(h.scriptIDs(t), "lib-l2-stp") {
		t.Fatal("mostrar no devolvió el playbook")
	}
	// Quitar el paquete borra la elección (lib-plat-flash-fs seguía oculto).
	if _, err := pk.Remove(ctx(t), &v1.PackServiceRemoveRequest{Id: "oom/ios-xe"}); err != nil {
		t.Fatal(err)
	}
	var n int
	h.core.db.QueryRow(`SELECT count(*) FROM pack_hidden`).Scan(&n)
	if n != 0 {
		t.Fatalf("quedaron %d elecciones", n)
	}
	h.installIOSXE(t)
	if !slices.Contains(h.scriptIDs(t), "lib-plat-flash-fs") {
		t.Fatal("reinstalar tras quitar debe entrar todo visible")
	}
	if au := h.auditText(t); !strings.Contains(au, `"action":"pack.items"`) {
		t.Fatalf("falta la auditoría pack.items:\n%s", au)
	}
}

// Install acepta hide[]: lo ignora si el paquete no lo trae y ocultar al instalar no impide resolver el ID.
func TestPackInstalarConHide(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	r, err := pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: writeMpack(t, packtest.IOSXE(t)), Hide: []string{"ios-xe/l2-stp", "ios-xe/nope"}}))
	if err != nil || !slices.Equal(r.Pack.Hidden, []string{"ios-xe/l2-stp"}) {
		t.Fatalf("%+v %v", r, err)
	}
	if slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") {
		t.Fatal("hide al instalar no se aplicó")
	}
}

// Concurrencia (Review Focus 5): ocultar y mostrar mientras se listan los playbooks y se instala el paquete.
func TestPackOcultarConcurrente(t *testing.T) {
	h := newHarness(t, nil)
	h.installIOSXE(t)
	pk := v1.NewPackServiceClient(h.conn)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				pk.SetItems(ctx(t), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe", Hide: []string{"ios-xe/l2-stp"}})
				pk.SetItems(ctx(t), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe", Show: []string{"ios-xe/l2-stp"}})
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := h.patrol.ListPlaybooks(ctx(t), &v1.ListPlaybooksRequest{}); err != nil {
					t.Error(err)
				}
				h.core.rebuildCatalog()
			}
		}()
	}
	wg.Wait()
}

// Fase 32b: copiar un script de un paquete (también oculto) a «Mis scripts»: ID nuevo, editable, nombre libre, y
// sobrevive a quitar el paquete. Lo que no es de un paquete se rechaza.
func TestPackCopiarAMisScripts(t *testing.T) {
	h := newHarness(t, nil)
	h.installIOSXE(t)
	sc := v1.NewScriptsServiceClient(h.conn)
	orig, err := sc.GetScript(ctx(t), &v1.GetScriptRequest{Id: "lib-l2-stp"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v1.NewPackServiceClient(h.conn).SetItems(ctx(t), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe", Hide: []string{"ios-xe/l2-stp"}}); err != nil {
		t.Fatal(err)
	}
	c, err := sc.CopyFromPack(ctx(t), &v1.CopyFromPackRequest{Id: "lib-l2-stp"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Script.Id == "lib-l2-stp" || c.Script.Origin != "usuario" || c.Script.Name != orig.Script.Name+" (copia)" || !slices.Equal(c.Script.Commands, orig.Script.Commands) {
		t.Fatalf("copia = %+v", c.Script)
	}
	c2, err := sc.CopyFromPack(ctx(t), &v1.CopyFromPackRequest{Id: "lib-l2-stp"})
	if err != nil || c2.Script.Name != orig.Script.Name+" (copia 2)" {
		t.Fatalf("segunda copia = %+v %v", c2, err)
	}
	// Editable.
	e := c.Script
	e.Description = "mi nota"
	if _, err := sc.SaveScript(ctx(t), &v1.SaveScriptRequest{Script: e}); err != nil {
		t.Fatalf("la copia debe ser editable: %v", err)
	}
	// Con el paquete instalado, ni uno de la base ni uno del usuario se copian por aquí.
	for _, id := range []string{"lib-tac-baseline", c.Script.Id} {
		if _, err := sc.CopyFromPack(ctx(t), &v1.CopyFromPackRequest{Id: id}); err == nil {
			t.Fatalf("%s no es de un paquete instalado", id)
		}
	}
	// Quitar el paquete no borra la copia.
	if _, err := v1.NewPackServiceClient(h.conn).Remove(ctx(t), &v1.PackServiceRemoveRequest{Id: "oom/ios-xe"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.scriptIDs(t), c.Script.Id) {
		t.Fatal("quitar el paquete borró la copia")
	}
	if au := h.auditText(t); !strings.Contains(au, `"action":"scripts.copy"`) {
		t.Fatalf("falta scripts.copy:\n%s", au)
	}
}

// Inspect valida como Install pero no instala nada ni audita la instalación.
func TestPackInspectNoInstala(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	path := writeMpack(t, packtest.IOSXE(t))
	r, err := pk.Inspect(ctx(t), &v1.PackServiceInspectRequest{Path: path})
	if err != nil || r.Pack.Id != "oom/ios-xe" || !r.Pack.Official || r.ReplacedVersion != "" ||
		!slices.Contains(r.PlaybookIds, "ios-xe/l2-stp") || !slices.Contains(r.ScriptIds, "lib-l2-stp") {
		t.Fatalf("%+v %v", r, err)
	}
	if l, _ := pk.List(ctx(t), &v1.PackServiceListRequest{}); len(l.Packs) != 0 {
		t.Fatal("Inspect instaló")
	}
	if slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") {
		t.Fatal("Inspect cambió el catálogo")
	}
	if au := h.auditText(t); strings.Contains(au, "pack.install") || strings.Contains(au, "pack.rejected") {
		t.Fatalf("Inspect no audita:\n%s", au)
	}
	// Con una versión instalada dice cuál reemplazaría; la igual da el mismo error que Install.
	h.installIOSXE(t)
	r, err = pk.Inspect(ctx(t), &v1.PackServiceInspectRequest{Path: writeMpack(t, ioSXEVersion(t, "1.1.1"))})
	if err != nil || r.ReplacedVersion != "1.1.0" {
		t.Fatalf("%+v %v", r, err)
	}
	_, ei := pk.Inspect(ctx(t), &v1.PackServiceInspectRequest{Path: path})
	_, ein := pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: path}))
	ri, _ := reasonOf(ei)
	rn, _ := reasonOf(ein)
	if ri != "pack.err.version" || ri != rn {
		t.Fatalf("inspect %v / install %v", ei, ein)
	}
	// Un archivo que no es zip: el mismo error.
	bad := writeMpack(t, []byte("no soy un zip"))
	_, ei = pk.Inspect(ctx(t), &v1.PackServiceInspectRequest{Path: bad})
	_, ein = pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: bad}))
	ri, _ = reasonOf(ei)
	rn, _ = reasonOf(ein)
	if ri == "" || ri != rn {
		t.Fatalf("inspect %v / install %v", ei, ein)
	}
}

// Un fijado cuyo script está oculto no cuenta para el tope ni estorba al reordenar los visibles.
func TestPackFijadoOcultoNoEstorba(t *testing.T) {
	h := newHarness(t, nil)
	h.installIOSXE(t)
	sc := v1.NewScriptsServiceClient(h.conn)
	if _, err := sc.SetPinned(ctx(t), &v1.SetPinnedRequest{Id: "lib-l2-stp", Pinned: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := v1.NewPackServiceClient(h.conn).SetItems(ctx(t), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe", Hide: []string{"ios-xe/l2-stp"}}); err != nil {
		t.Fatal(err)
	}
	vis := []string{"lib-tac-baseline", "lib-l1-poe", "lib-l1-flapping", "lib-cpu-alta", "lib-flota"}
	for _, id := range vis { // 5 visibles = el tope, con el oculto fuera de la cuenta
		if _, err := sc.SetPinned(ctx(t), &v1.SetPinnedRequest{Id: id, Pinned: true}); err != nil {
			t.Fatalf("fijar %s: %v", id, err)
		}
	}
	if _, err := sc.SetPinned(ctx(t), &v1.SetPinnedRequest{Id: "lib-l1-err-disabled", Pinned: true}); err == nil {
		t.Fatal("el sexto visible debía pasar el tope")
	}
	rev := []string{vis[4], vis[3], vis[2], vis[1], vis[0]}
	if _, err := sc.ReorderPinned(ctx(t), &v1.ReorderPinnedRequest{Ids: rev}); err != nil {
		t.Fatalf("reordenar los visibles: %v", err)
	}
	lp, err := sc.ListPinned(ctx(t), &v1.ListPinnedRequest{})
	if err != nil || len(lp.Scripts) != 5 || lp.Scripts[0].Id != vis[4] {
		t.Fatalf("%+v %v", lp, err)
	}
	// Se puede desfijar el oculto.
	if _, err := sc.SetPinned(ctx(t), &v1.SetPinnedRequest{Id: "lib-l2-stp", Pinned: false}); err != nil {
		t.Fatal(err)
	}
}

// Ocultar un playbook del paquete que uno de <config>/playbooks tapa no oculta el del usuario ni su lib-; copiar
// copia el script del paquete.
func TestPackOcultarNoTapaAlDelUsuario(t *testing.T) {
	h := newHarness(t, nil)
	h.installIOSXE(t)
	dir := filepath.Join(h.p.Config, "playbooks")
	os.MkdirAll(dir, 0o700)
	y := "id: l2-stp\nplatform: ios-xe\nname: Mío · STP\ncommands:\n  - cmd: show clock\n"
	if err := os.WriteFile(filepath.Join(dir, "mio.yaml"), []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	h.restart(t)
	if _, err := v1.NewPackServiceClient(h.conn).SetItems(ctx(t), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe", Hide: []string{"ios-xe/l2-stp"}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") || !slices.Contains(h.scriptIDs(t), "lib-l2-stp") {
		t.Fatal("ocultar el del paquete ocultó el del usuario o su lib-")
	}
	c, err := v1.NewScriptsServiceClient(h.conn).CopyFromPack(ctx(t), &v1.CopyFromPackRequest{Id: "lib-l2-stp"})
	if err != nil || strings.Contains(c.Script.Name, "Mío") || !slices.Contains(c.Script.Commands, "show spanning-tree summary") {
		t.Fatalf("debía copiar el script del paquete: %+v %v", c, err)
	}
}

// Las filas de IDs que una versión quitó no se heredan: si una versión posterior lo vuelve a traer entra visible; y
// una instalación nueva no hereda filas viejas.
func TestPackOcultosNoSeHeredan(t *testing.T) {
	h := newHarness(t, nil)
	h.installIOSXE(t)
	pk := v1.NewPackServiceClient(h.conn)
	if _, err := pk.SetItems(ctx(t), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe", Hide: []string{"ios-xe/l1-poe"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: writeMpack(t, ioSXEVersion(t, "1.1.1", "playbooks/l1-poe.yaml"))})); err != nil {
		t.Fatal(err)
	}
	var n int
	h.core.db.QueryRow(`SELECT count(*) FROM pack_hidden`).Scan(&n)
	if n != 0 {
		t.Fatalf("la v2 sin el ID debía borrar su fila: %d", n)
	}
	if _, err := pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: writeMpack(t, ioSXEVersion(t, "1.1.2"))})); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.playbookIDs(t), "ios-xe/l1-poe") {
		t.Fatal("el ID que vuelve en la v3 debía entrar visible")
	}
	// Quitar el paquete borra su elección: reinstalar no la hereda.
	if _, err := pk.SetItems(ctx(t), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe", Hide: []string{"ios-xe/l1-poe"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := pk.Remove(ctx(t), &v1.PackServiceRemoveRequest{Id: "oom/ios-xe"}); err != nil {
		t.Fatal(err)
	}
	h.installIOSXE(t)
	if !slices.Contains(h.playbookIDs(t), "ios-xe/l1-poe") {
		t.Fatal("reinstalar heredó lo oculto")
	}
}

// SetItems sin nada que cambiar da pack.err.item y no audita; repetir lo mismo tampoco audita.
func TestPackSetItemsAuditaSoloCambios(t *testing.T) {
	h := newHarness(t, nil)
	h.installIOSXE(t)
	pk := v1.NewPackServiceClient(h.conn)
	for lang, want := range map[string]string{"": "indica al menos un elemento para ocultar o mostrar", "es": "indica al menos un elemento para ocultar o mostrar",
		"en": "give at least one item to hide or show"} {
		_, err := pk.SetItems(con(t, lang), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe"})
		if err == nil {
			t.Fatal("hide y show vacíos debían fallar")
		}
		if r, _ := reasonOf(err); r != "pack.err.items_empty" || status.Convert(err).Message() != want {
			t.Fatalf("%q: %v", lang, err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := pk.SetItems(ctx(t), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe", Hide: []string{"ios-xe/l1-poe"}}); err != nil {
			t.Fatal(err)
		}
	}
	pk.SetItems(ctx(t), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe", Show: []string{"ios-xe/l1-flapping"}}) // no estaba oculto
	if got := strings.Count(h.auditText(t), `"action":"pack.items"`); got != 1 {
		t.Fatalf("pack.items = %d, want 1", got)
	}
}

// Un paquete que la revalidación omitió al arrancar (sin pasar por Remove) y se reinstala conserva lo oculto.
func TestPackOmitidoAlArrancarConservaOcultos(t *testing.T) {
	h := newHarness(t, nil)
	h.installIOSXE(t)
	if _, err := v1.NewPackServiceClient(h.conn).SetItems(ctx(t), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe", Hide: []string{"ios-xe/l1-poe"}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.p.Data, "packs", "oom", "ios-xe", "README.md"), []byte("alterado"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.restart(t)
	h.installIOSXE(t)
	if slices.Contains(h.playbookIDs(t), "ios-xe/l1-poe") {
		t.Fatal("la elección se perdió por la revalidación al arrancar")
	}
}

// replace_hidden: hide es el conjunto exacto; sin él se conserva lo oculto y hide suma.
func TestPackInstallReplaceHidden(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	if _, err := pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: writeMpack(t, packtest.IOSXE(t)), Hide: []string{"ios-xe/l2-stp"}})); err != nil {
		t.Fatal(err)
	}
	// Sin replace_hidden: se conserva y suma.
	r, err := pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: writeMpack(t, ioSXEVersion(t, "1.1.1")), Hide: []string{"ios-xe/l1-poe"}}))
	if err != nil || !slices.Equal(r.Pack.Hidden, []string{"ios-xe/l1-poe", "ios-xe/l2-stp"}) {
		t.Fatalf("%+v %v", r, err)
	}
	// Con replace_hidden y hide vacío: nada oculto.
	r, err = pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: writeMpack(t, ioSXEVersion(t, "1.1.2")), ReplaceHidden: true}))
	if err != nil || len(r.Pack.Hidden) != 0 || !slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") {
		t.Fatalf("%+v %v", r, err)
	}
	// Con replace_hidden y hide: exactamente eso.
	r, err = pk.Install(ctx(t), withSum(t, &v1.PackServiceInstallRequest{Path: writeMpack(t, ioSXEVersion(t, "1.1.3")), Hide: []string{"ios-xe/l1-poe"}, ReplaceHidden: true}))
	if err != nil || !slices.Equal(r.Pack.Hidden, []string{"ios-xe/l1-poe"}) {
		t.Fatalf("%+v %v", r, err)
	}
}

// SaveCollection y SetCollectionScripts también marcan los scripts ocultos.
func TestPackColeccionesMarcanOcultosAlGuardar(t *testing.T) {
	h := newHarness(t, nil)
	h.installIOSXE(t)
	sc := v1.NewScriptsServiceClient(h.conn)
	if _, err := v1.NewPackServiceClient(h.conn).SetItems(ctx(t), &v1.PackServiceSetItemsRequest{PackId: "oom/ios-xe", Hide: []string{"ios-xe/l2-stp"}}); err != nil {
		t.Fatal(err)
	}
	r, err := sc.SetCollectionScripts(ctx(t), &v1.SetCollectionScriptsRequest{Id: "favoritos", ScriptIds: []string{"lib-l2-stp", "lib-tac-baseline"}})
	if err != nil || !slices.Equal(r.Collection.HiddenScriptIds, []string{"lib-l2-stp"}) {
		t.Fatalf("%+v %v", r, err)
	}
	sv, err := sc.SaveCollection(ctx(t), &v1.SaveCollectionRequest{Collection: &v1.Collection{Id: "favoritos", Name: "Favoritos"}})
	if err != nil || !slices.Equal(sv.Collection.HiddenScriptIds, []string{"lib-l2-stp"}) {
		t.Fatalf("%+v %v", sv, err)
	}
}
