package core

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
	if _, err := v1.NewPackServiceClient(h.conn).Install(ctx(t), &v1.PackServiceInstallRequest{Path: writeMpack(t, packtest.IOSXE(t))}); err != nil {
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
	_, err = pk.Install(ctx(t), &v1.PackServiceInstallRequest{Path: p})
	if r, _ := reasonOf(err); r != "pack.err.unsigned" {
		t.Fatalf("sin confirmar: %v", err)
	}
	if _, err := pk.Install(ctx(t), &v1.PackServiceInstallRequest{Path: p, AllowUnsigned: true}); err != nil {
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
	_, err := v1.NewPackServiceClient(h.conn).Install(ctx(t), &v1.PackServiceInstallRequest{Path: p})
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
	if _, err := pk.Install(ctx(t), &v1.PackServiceInstallRequest{Path: "x.mpack"}); err == nil || !strings.Contains(err.Error(), "absoluta") {
		t.Fatalf("%v", err)
	}
	h.installIOSXE(t)
	_, err := pk.Install(ctx(t), &v1.PackServiceInstallRequest{Path: writeMpack(t, packtest.IOSXE(t))})
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
	_, err = v1.NewPackServiceClient(h.conn).Install(ctx(t), &v1.PackServiceInstallRequest{Path: writeMpack(t, zb), AllowUnsigned: true})
	if r, _ := reasonOf(err); r != "pack.err.editor.reserved" {
		t.Fatalf("%v", err)
	}
	if slices.Contains(h.playbookIDs(t), "ios-xe/l2-stp") {
		t.Fatal("el tercero ocupó ios-xe/l2-stp")
	}
}
