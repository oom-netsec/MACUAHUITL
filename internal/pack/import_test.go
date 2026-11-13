package pack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/scripts"
)

func exported(t *testing.T, id string, pbs ...playbook.Playbook) *Pack {
	t.Helper()
	in := exportIn([]scripts.Script{userScript("Uno", "ios", "show version")}, pbs)
	in.ID = id
	r, err := Export(in)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Verify(r.Data, "v0.3.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ls(t *testing.T, dir string) []string {
	t.Helper()
	es, _ := os.ReadDir(dir)
	var n []string
	for _, e := range es {
		n = append(n, e.Name())
	}
	return n
}

func TestImportEscribeSoloEnLaCarpeta(t *testing.T) {
	s, _ := openStore(t, t.TempDir(), nil, Base{})
	dir := filepath.Join(t.TempDir(), "playbooks")
	p := exported(t, "acme/mio", userPB("ios", "uno", "show clock"), userPB("ios-xe", "dos", "show version"))
	plan := s.PlanPlaybooks(p, dir, nil)
	if len(plan) != 2 || plan[0].State != scripts.Nuevo || plan[0].File != "acme-dos.yaml" {
		t.Fatalf("%+v", plan)
	}
	w, err := s.ImportPlaybooks(p, dir, nil, nil)
	if err != nil || w.Created != 2 || len(w.Written) != 2 {
		t.Fatal(err, w)
	}
	if got := strings.Join(ls(t, dir), ","); got != "acme-dos.yaml,acme-uno.yaml" {
		t.Fatal(got)
	}
	// Lo escrito vuelve a cargar con el mismo ID con prefijo.
	pbs, err := playbook.Load(os.DirFS(dir))
	if err != nil || len(pbs) != 2 || !strings.HasPrefix(pbs[0].ID, "ios-xe/acme-") {
		t.Fatal(err, pbs)
	}
}

func TestImportChoqueNoSobrescribe(t *testing.T) {
	s, _ := openStore(t, t.TempDir(), nil, Base{})
	dir := t.TempDir()
	old := []byte("# mío\n")
	os.WriteFile(filepath.Join(dir, "acme-uno.yaml"), old, 0o600) // archivo con otro ID
	p := exported(t, "acme/mio", userPB("ios", "uno", "show clock"))
	plan := s.PlanPlaybooks(p, dir, map[string]bool{})
	if plan[0].State != scripts.ConflictoID {
		t.Fatalf("%+v", plan)
	}
	if _, err := s.ImportPlaybooks(p, dir, nil, nil); Reason(err) != "import.missing" {
		t.Fatal(err)
	}
	if _, err := s.ImportPlaybooks(p, dir, nil, map[string]string{"ios/acme-uno": scripts.Reemplazar}); Reason(err) != "import.decision" {
		t.Fatal(err)
	}
	w, err := s.ImportPlaybooks(p, dir, nil, map[string]string{"ios/acme-uno": scripts.Omitir})
	if err != nil || w.Skipped != 1 || len(w.Written) != 0 {
		t.Fatal(err, w)
	}
	w, err = s.ImportPlaybooks(p, dir, nil, map[string]string{"ios/acme-uno": scripts.Renombrar})
	if err != nil || w.Renamed != 1 || w.Written[0] != "ios/acme-uno-2" {
		t.Fatal(err, w)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "acme-uno.yaml")); string(b) != string(old) {
		t.Fatal("pisó el archivo existente")
	}
	// Un ID de playbook del usuario (en otro archivo) también es choque.
	dir2 := t.TempDir()
	plan = s.PlanPlaybooks(p, dir2, map[string]bool{"ios/acme-uno": true})
	if plan[0].State != scripts.ConflictoID || plan[0].With != "user" {
		t.Fatalf("%+v", plan)
	}
}

func TestImportChocaConInstaladosYBase(t *testing.T) {
	s, _ := openStore(t, t.TempDir(), nil, Base{PlaybookIDs: []string{"ios/acme-uno"}})
	inst := exported(t, "acme/uno", userPB("ios-xe", "otro", "show clock"))
	if _, err := s.Install(zipOf(t, inst), true); err != nil {
		t.Fatal(err)
	}
	// Mismo editor, otro paquete: el prefijo es el mismo, así que el ID instalado sigue siendo ajeno.
	p := exported(t, "acme/dos", userPB("ios-xe", "otro", "show version"), userPB("ios", "uno", "show clock"))
	plan := s.PlanPlaybooks(p, t.TempDir(), nil)
	by := map[string]PlaybookPlan{}
	for _, it := range plan {
		by[it.ID] = it
	}
	if by["ios-xe/acme-otro"].State != scripts.ConflictoID || by["ios-xe/acme-otro"].With != "acme/uno" ||
		by["ios/acme-uno"].State != scripts.ConflictoID || by["ios/acme-uno"].With != "base" {
		t.Fatalf("%+v", plan)
	}
	// Renombrar nunca cae en un ID de la base ni de un instalado.
	dir := t.TempDir()
	w, err := s.ImportPlaybooks(p, dir, nil, map[string]string{"ios-xe/acme-otro": scripts.Renombrar, "ios/acme-uno": scripts.Renombrar})
	if err != nil || strings.Join(w.Written, ",") != "ios-xe/acme-otro-2,ios/acme-uno-2" {
		t.Fatal(err, w)
	}
}

func zipOf(t *testing.T, p *Pack) []byte {
	t.Helper()
	return mustZip(t, p.files)
}

func TestImportDecisionDeIDQueNoEstaEsError(t *testing.T) {
	s, _ := openStore(t, t.TempDir(), nil, Base{})
	p := exported(t, "acme/mio", userPB("ios", "uno", "show clock"))
	dir := t.TempDir()
	if _, err := s.ImportPlaybooks(p, dir, nil, map[string]string{"ios/otro": scripts.Omitir}); Reason(err) != "import.decision" {
		t.Fatal(err)
	}
	if len(ls(t, dir)) != 0 {
		t.Fatal("escribió")
	}
}

// Un enlace simbólico que apunta fuera de la carpeta no desvía la escritura: es un archivo existente.
func TestImportEnlaceNoDesvia(t *testing.T) {
	s, _ := openStore(t, t.TempDir(), nil, Base{})
	dir, fuera := t.TempDir(), t.TempDir()
	if err := os.Symlink(filepath.Join(fuera, "robado.yaml"), filepath.Join(dir, "acme-uno.yaml")); err != nil {
		t.Fatal(err)
	}
	p := exported(t, "acme/mio", userPB("ios", "uno", "show clock"))
	if plan := s.PlanPlaybooks(p, dir, nil); plan[0].State != scripts.ConflictoID {
		t.Fatalf("%+v", plan)
	}
	// Aunque la decisión no llegara (carrera), Publish (enlace sin sobrescribir) no escribe por el enlace.
	done, err := writePlaybooks(dir, map[string][]byte{"acme-uno.yaml": []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&PlaybookResult{files: done}).Publish(dir); Reason(err) != "import.exists" {
		t.Fatal(err)
	}
	if len(ls(t, fuera)) != 0 {
		t.Fatal("escribió fuera")
	}
	if got := strings.Join(ls(t, dir), ","); got != "acme-uno.yaml" { // solo el enlace ajeno: sin temporales
		t.Fatal(got)
	}
}

// Un .mpack hostil nunca llega a escribir: lo frena Verify o VerifyImport.
func TestVerifyImportHostil(t *testing.T) {
	s, _ := openStore(t, t.TempDir(), nil, Base{ReservedPlaybooks: []string{"ios-xe/l2-stp"}})
	base := func() map[string][]byte {
		f := goodFiles()
		f["manifest.yaml"] = []byte(strings.Replace(goodManifest, "oom/demo", "acme/demo", 1))
		setPB(f, strings.Replace(goodPlaybook, "oom-stp", "acme-stp", 1))
		return f
	}
	mut := map[string]func(map[string][]byte){
		"id de la base sin prefijo": func(f map[string][]byte) { setPB(f, strings.Replace(goodPlaybook, "oom-stp", "tac-baseline", 1)) },
		"id movido":                 func(f map[string][]byte) { setPB(f, strings.Replace(goodPlaybook, "oom-stp", "l2-stp", 1)) },
		"editor movido": func(f map[string][]byte) {
			f["manifest.yaml"] = []byte(strings.Replace(goodManifest, "oom/demo", "l2/demo", 1))
		},
		"editor oom":    func(f map[string][]byte) {},
		"ruta con ..":   func(f map[string][]byte) { f["playbooks/../../x.yaml"] = []byte("x") },
		"ruta absoluta": func(f map[string][]byte) { f["/etc/x.yaml"] = []byte("x") },
		"subcarpeta":    func(f map[string][]byte) { f["playbooks/a/b.yaml"] = []byte("x") },
		"nombre raro":   func(f map[string][]byte) { f["playbooks/A B;rm.yaml"] = []byte("x") },
		"backslash":     func(f map[string][]byte) { f["playbooks\\x.yaml"] = []byte("x") },
		"id con barra":  func(f map[string][]byte) { setPB(f, strings.Replace(goodPlaybook, "oom-stp", "acme-../x", 1)) },
	}
	mut["editor oom"] = func(f map[string][]byte) {
		f["manifest.yaml"] = []byte(goodManifest)
		setPB(f, goodPlaybook)
	}
	for name, m := range mut {
		f := base()
		m(f)
		z, err := Zip(f)
		if err != nil {
			t.Fatal(name, err)
		}
		if p, err := s.VerifyImport(z); err == nil {
			t.Errorf("%s: se aceptó (%v)", name, p.ID)
		}
	}
}

func TestVerifyImportRechazaOficial(t *testing.T) {
	pub, priv := testKey(t)
	s, _ := openStore(t, t.TempDir(), pub, Base{})
	z := signedZip(t, priv, nil)
	if _, err := s.VerifyImport(z); Reason(err) != "import.official" {
		t.Fatal(err)
	}
}

func TestImportReservadosYRenombradoSinChoques(t *testing.T) {
	s, _ := openStore(t, t.TempDir(), nil, Base{ReservedPlaybooks: []string{"ios/acme-uno"}})
	// El paquete ya trae un «-2»: el renombrado no puede tomar el ID de otro playbook del mismo archivo.
	p := exported(t, "acme/mio", userPB("ios", "uno", "show clock"), userPB("ios", "uno-2", "show version"))
	plan := s.PlanPlaybooks(p, t.TempDir(), nil)
	if plan[0].ID != "ios/acme-uno" || plan[0].With != "reserved" || plan[1].State != scripts.Nuevo {
		t.Fatalf("%+v", plan)
	}
	w, err := s.ImportPlaybooks(p, t.TempDir(), nil, map[string]string{"ios/acme-uno": scripts.Renombrar})
	if err != nil || strings.Join(w.Written, ",") != "ios/acme-uno-3,ios/acme-uno-2" {
		t.Fatal(err, w)
	}
}
