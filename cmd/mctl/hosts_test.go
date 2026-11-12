package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/core"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

var hostIDRe = regexp.MustCompile(`(?:creado|guardado) ([0-9a-f]{32}) `)

func addHost(t *testing.T, name, addr string, extra ...string) string {
	t.Helper()
	out := must(t, "", append([]string{"hosts", "add", name, "--address", addr, "--platform", "ios-xe"}, extra...)...)
	m := hostIDRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("add: %q", out)
	}
	return m[1]
}

func TestHostsAddListEditRm(t *testing.T) {
	e := startCore(t)
	dd := filepath.Join(e.out, "j1", "SW1_10.0.0.1")
	os.MkdirAll(dd, 0o700)
	os.WriteFile(filepath.Join(dd, "r001.txt"), []byte("===== 2026-11-06T10:00:00Z · show clock =====\n"), 0o600)

	id := addHost(t, "SW-CORE", "10.0.0.1", "--folder", "Lab", "--tag", "core", "--tag", "dc-1", "--notes", "piso 2")
	addHost(t, "AP-1", "ap1.lab", "--port", "2222", "--folder", "Oficina")
	out := must(t, "", "hosts", "list")
	for _, want := range []string{"ID", "NOMBRE", "SW-CORE", "10.0.0.1", "Lab", "core,dc-1", "AP-1", "ap1.lab", "2222"} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en:\n%s", want, out)
		}
	}
	if out := must(t, "", "hosts", "list", "--folder", "lab"); strings.Contains(out, "AP-1") || !strings.Contains(out, "SW-CORE") {
		t.Errorf("--folder:\n%s", out)
	}
	if out := must(t, "", "hosts", "list", "--tag", "dc-1", "ap"); strings.Contains(out, "SW-CORE") || strings.Contains(out, "AP-1") {
		t.Errorf("--tag y texto:\n%s", out)
	}
	if out := must(t, "", "hosts", "list", "--json"); !strings.Contains(out, `"credentialId"`) || !strings.Contains(out, `"folder"`) {
		t.Errorf("--json:\n%s", out)
	}
	// el host se fusiona con la evidencia: una sola fila en `devices`, con las dos fuentes
	if out := must(t, "", "devices", "10.0.0.1"); strings.Count(out, "10.0.0.1") != 1 || !strings.Contains(out, "flota,manual") || !strings.Contains(out, "SW-CORE") {
		t.Errorf("devices:\n%s", out)
	}
	// edit solo cambia lo pasado; --tag reemplaza las etiquetas
	must(t, "", "hosts", "edit", id, "--notes", "piso 3", "--tag", "acceso", "--port", "2200")
	out = must(t, "", "hosts", "list")
	if !strings.Contains(out, "2200") || !strings.Contains(out, "acceso") || strings.Contains(out, "core,") || !strings.Contains(out, "Lab") || !strings.Contains(out, "SW-CORE") {
		t.Errorf("edit:\n%s", out)
	}
	must(t, "", "hosts", "edit", id, "--folder", "")
	if out := must(t, "", "hosts", "list", "--folder", "lab"); strings.Contains(out, "SW-CORE") {
		t.Errorf("--folder \"\" debe quitar la carpeta:\n%s", out)
	}
	for _, args := range [][]string{
		{"add", "sin-dir"}, {"add", "x", "--address", "admin@10.0.0.9"}, {"add", "x", "--address", "10.0.0.9", "--platform", "junos"},
		{"add", "SW-CORE", "--address", "10.0.0.7"}, {"add", "otro", "--address", "10.0.0.1", "--port", "2200"}, {"add", "--address", "10.0.0.8"},
		{"edit", "nada", "--notes", "x"}, {"edit"}, {"rm", "nada"}, {"rm"}, {"list", "a", "b"},
	} {
		if _, err := mctl(t, "", append([]string{"hosts"}, args...)...); err == nil {
			t.Errorf("hosts %v debió fallar", args)
		}
	}
	must(t, "", "hosts", "rm", id)
	if out := must(t, "", "hosts", "list"); strings.Contains(out, "SW-CORE") {
		t.Errorf("rm:\n%s", out)
	}
	// la evidencia sigue ahí
	if out := must(t, "", "devices", "10.0.0.1"); !strings.Contains(out, "SW1") || strings.Contains(out, "manual") {
		t.Errorf("tras rm:\n%s", out)
	}
}

func TestHostsCredencialPorReferencia(t *testing.T) {
	var cid string
	startCoreWith(t, func(p core.Paths) {
		vault.MinMemoryKiB = 8192
		os.MkdirAll(p.Data, 0o700)
		v, err := vault.Create(filepath.Join(p.Data, "vault.mcv"), []byte("maestra"), vault.Params{MemoryKiB: 8192, Iterations: 1, Threads: 1})
		if err != nil {
			t.Fatal(err)
		}
		if cid, err = v.Put(vault.Credential{Label: "admin lab", Username: "admin", Password: secret.New([]byte("pw-secreto")), Enable: secret.New([]byte("en-secreto"))}); err != nil {
			t.Fatal(err)
		}
		v.LockAll()
	})
	must(t, "maestra\n", "vault", "unlock")
	addHost(t, "SW-1", "10.0.0.1", "--cred", cid)
	if out := must(t, "", "hosts", "list"); !strings.Contains(out, "admin lab") {
		t.Errorf("la etiqueta debe verse:\n%s", out)
	}
	if _, err := mctl(t, "", "hosts", "add", "SW-2", "--address", "10.0.0.2", "--cred", strings.Repeat("0", 32)); err == nil {
		t.Error("una credencial inexistente debe fallar")
	}
	// export: la etiqueta viaja, el id y los secretos no
	path := filepath.Join(t.TempDir(), "hosts.json")
	must(t, "", "hosts", "export", "--out", path)
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"credential_label":"admin lab"`) || strings.Contains(string(b), cid) || strings.Contains(string(b), "secreto") {
		t.Fatalf("export: %s", b)
	}
	must(t, "", "hosts", "edit", hostIDOf(t, "SW-1"), "--cred", "")
	if out := must(t, "", "hosts", "list"); strings.Contains(out, "admin lab") {
		t.Errorf("--cred \"\" debe quitarla:\n%s", out)
	}
	// al importar sobre la misma bóveda la etiqueta se resuelve al id local
	out := must(t, "", "hosts", "import", path, "--all=reemplazar")
	if !strings.Contains(out, "1 reemplazados") {
		t.Fatalf("import:\n%s", out)
	}
	if out := must(t, "", "hosts", "list"); !strings.Contains(out, "admin lab") {
		t.Errorf("la credencial debió volver:\n%s", out)
	}
}

func hostIDOf(t *testing.T, name string) string {
	t.Helper()
	for _, ln := range strings.Split(must(t, "", "hosts", "list"), "\n") {
		if f := strings.Fields(ln); len(f) > 1 && f[1] == name {
			return f[0]
		}
	}
	t.Fatalf("no hay host %q", name)
	return ""
}

func TestHostsExportImportDePuntaAPunta(t *testing.T) {
	startCore(t)
	addHost(t, "Uno", "10.0.0.1", "--tag", "a")
	addHost(t, "Dos", "10.0.0.2")
	path := filepath.Join(t.TempDir(), "hosts.json")
	if out := must(t, "", "hosts", "export", "--out", path); !strings.Contains(out, "exportados 2") {
		t.Fatalf("export: %q", out)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("modo = %v", fi.Mode())
	}
	if _, err := mctl(t, "", "hosts", "export", "--out", path); err == nil {
		t.Fatal("export sin --overwrite sobre un archivo existente debe fallar")
	}
	must(t, "", "hosts", "export", "--out", path, "--overwrite", hostIDOf(t, "Uno"))
	if b, _ := os.ReadFile(path); strings.Contains(string(b), `"Dos"`) {
		t.Fatalf("export por id incluyó otro host: %s", b)
	}
	must(t, "", "hosts", "export", "--out", path, "--overwrite")

	// lo mismo que ya está guardado: todo «igual»
	out := must(t, "", "hosts", "import", path)
	if strings.Count(out, "igual") != 2 || !strings.Contains(out, "0 nuevos") {
		t.Fatalf("import:\n%s", out)
	}
	// «Uno» difiere en la dirección:puerto igual → conflicto; sin decisión no se importa nada
	must(t, "", "hosts", "edit", hostIDOf(t, "Uno"), "--notes", "cambió")
	_, err := mctl(t, "", "hosts", "import", path)
	if err == nil || !strings.Contains(err.Error(), "no se importó nada") || !strings.Contains(err.Error(), "10.0.0.1:22") {
		t.Fatalf("sin decisión: %v", err)
	}
	if out := must(t, "", "hosts", "import", path, "--preview"); !strings.Contains(out, "conflicto") || strings.Contains(out, "importados") {
		t.Fatalf("--preview:\n%s", out)
	}
	must(t, "", "hosts", "import", path, "--decision", "10.0.0.1:22=reemplazar")
	if out := must(t, "", "hosts", "list", "--json"); strings.Contains(out, "cambió") {
		t.Fatalf("reemplazar no restauró:\n%s", out)
	}
	must(t, "", "hosts", "edit", hostIDOf(t, "Uno"), "--notes", "otra vez")
	if out := must(t, "", "hosts", "import", path, "--all=omitir"); !strings.Contains(out, "2 omitidos") {
		t.Fatalf("--all=omitir:\n%s", out)
	}
	// un conflicto de nombre se puede renombrar
	must(t, "", "hosts", "rm", hostIDOf(t, "Dos"))
	addHost(t, "Dos", "10.0.0.99")
	if out := must(t, "", "hosts", "import", path, "--decision", "10.0.0.2:22=renombrar", "--all=omitir"); !strings.Contains(out, "1 renombrados") {
		t.Fatalf("renombrar:\n%s", out)
	}
	if out := must(t, "", "hosts", "list"); !strings.Contains(out, "Dos (importado)") {
		t.Fatalf("falta el renombrado:\n%s", out)
	}
	// un byte cambiado da error de suma
	b, _ := os.ReadFile(path)
	mal := filepath.Join(t.TempDir(), "mal.json")
	os.WriteFile(mal, []byte(strings.Replace(string(b), "10.0.0.2", "10.0.0.3", 1)), 0o600)
	if _, err := mctl(t, "", "hosts", "import", mal); err == nil || !strings.Contains(err.Error(), "suma") {
		t.Fatalf("suma: %v", err)
	}
	for _, args := range [][]string{{"import", path, "--decision", "malformada"}, {"import", path, "--all=fusionar"}, {"import"}, {"export"}} {
		if _, err := mctl(t, "", append([]string{"hosts"}, args...)...); err == nil {
			t.Errorf("%v debió fallar", args)
		}
	}
	if _, err := mctl(t, "", "hosts", "import", filepath.Join(t.TempDir(), "no-existe.json")); err == nil {
		t.Error("archivo inexistente debe fallar")
	}
}

func TestHostsCSVYErroresPorLinea(t *testing.T) {
	startCore(t)
	addHost(t, "Uno", "10.0.0.1")
	dir := t.TempDir()
	csv := filepath.Join(dir, "h.csv")
	if out := must(t, "", "hosts", "export", "--out", csv); !strings.Contains(out, "exportados 1") {
		t.Fatalf("export csv: %q", out)
	}
	if b, _ := os.ReadFile(csv); !strings.HasPrefix(string(b), "\xef\xbb\xbfname,address,port,platform,folder,tags,credential_label,notes\n") {
		t.Fatalf("csv: %s", b)
	}
	if _, err := mctl(t, "", "hosts", "export", "--out", filepath.Join(dir, "h.txt")); err == nil {
		t.Fatal("sin extensión ni --format debe fallar")
	}
	must(t, "", "hosts", "export", "--out", filepath.Join(dir, "h.txt"), "--format", "csv")

	mix := filepath.Join(dir, "mix.csv")
	os.WriteFile(mix, []byte("name,address,port,platform,folder,tags,credential_label,notes\n"+
		"Nuevo,10.0.0.5,22,ios,,a;b,,\n"+
		"Mala,admin@10.0.0.6,22,ios,,,,\n"+
		"corta,10.0.0.7\n"+
		"Uno,10.0.0.1,22,ios-xe,,,,\n"), 0o600)
	out := must(t, "", "hosts", "import", mix, "--preview")
	for _, want := range []string{"línea 3: address:", "línea 4: ", "nuevo", "igual", "2 filas inválidas"} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en:\n%s", want, out)
		}
	}
	if strings.Contains(out, "importados") {
		t.Fatalf("--preview importó:\n%s", out)
	}
	out = must(t, "", "hosts", "import", mix)
	if !strings.Contains(out, "importados: 1 nuevos, 0 reemplazados, 0 renombrados, 3 omitidos") || !strings.Contains(out, "2 inválidos") {
		t.Fatalf("import:\n%s", out)
	}
	if out := must(t, "", "hosts", "list"); !strings.Contains(out, "Nuevo") || strings.Contains(out, "Mala") {
		t.Fatalf("list:\n%s", out)
	}
	// --format fuerza el formato aunque la extensión diga otra cosa
	if _, err := mctl(t, "", "hosts", "import", mix, "--format", "json"); err == nil {
		t.Fatal("un CSV leído como JSON debe fallar")
	}
	if _, err := mctl(t, "", "hosts", "import", mix, "--format", "xml"); err == nil {
		t.Fatal("formato desconocido debe fallar")
	}
}

func TestHostsPlantilla(t *testing.T) {
	startCore(t)
	dir := t.TempDir()
	for _, f := range []string{"csv", "json"} {
		out := must(t, "", "hosts", "template", "--format", f)
		ruta := filepath.Join(dir, "plantilla."+f)
		os.WriteFile(ruta, []byte(out), 0o600)
		pv := must(t, "", "hosts", "import", ruta, "--preview")
		if strings.Count(pv, "nuevo") != 3 || strings.Contains(pv, "inválid") || strings.Contains(pv, "conflicto") {
			t.Fatalf("la plantilla %s no pasa limpia:\n%s", f, pv)
		}
		if f == "csv" && !strings.HasPrefix(out, "\xef\xbb\xbfname,address,port,platform,folder,tags,credential_label,notes\n") {
			t.Fatalf("csv:\n%s", out)
		}
		if f == "json" && strings.Contains(out, "sha256") {
			t.Fatalf("json con suma:\n%s", out)
		}
	}
	campos := must(t, "", "hosts", "template", "--fields")
	for _, w := range []string{"NOMBRE", "OBLIGATORIO", "name", "credential_label", "lista", "entero", "SW-CORE"} {
		if !strings.Contains(campos, w) {
			t.Errorf("falta %q en:\n%s", w, campos)
		}
	}
	for _, args := range [][]string{{"template"}, {"template", "--format", "xml"}, {"template", "x", "--format", "csv"}} {
		if _, err := mctl(t, "", append([]string{"hosts"}, args...)...); err == nil {
			t.Errorf("%v debió fallar", args)
		}
	}
}

// hosts list y edit leen los hosts con sus valores: la plataforma que Patrol detectó no se les pega al editar.
func TestHostsEditNoFijaLoDescubierto(t *testing.T) {
	e := startCore(t)
	job := filepath.Join(e.out, "j1")
	os.MkdirAll(filepath.Join(job, "SW1_10.0.0.1"), 0o700)
	os.WriteFile(filepath.Join(job, "SW1_10.0.0.1", "r001.txt"), []byte("===== 2026-11-06T10:00:00Z · show clock =====\n"), 0o600)
	os.WriteFile(filepath.Join(job, "manifest.json"), []byte(`{"started_at":"2026-11-06T09:00:00Z","ended_at":"2026-11-06T09:00:00Z","devices":[{"Target":{"Address":"10.0.0.1"},"Hostname":"SW1","Platform":"ios-xe","State":"completed"}]}`), 0o600)
	id := hostIDRe.FindStringSubmatch(must(t, "", "hosts", "add", "ñandú", "--address", "10.0.0.1"))[1]
	must(t, "", "hosts", "add", "Ñu", "--address", "10.0.0.7")
	if out := must(t, "", "devices", "10.0.0.1"); !strings.Contains(out, "ios-xe") {
		t.Fatalf("devices sí muestra lo detectado:\n%s", out)
	}
	out := must(t, "", "hosts", "list")
	if strings.Contains(out, "ios-xe") || strings.Index(out, "ñandú") > strings.Index(out, "Ñu") {
		t.Fatalf("hosts list (sin plataforma, por nombre):\n%s", out)
	}
	must(t, "", "hosts", "edit", id, "--notes", "nuevas")
	if out := must(t, "", "hosts", "list", "--json"); strings.Contains(out, "ios-xe") || !strings.Contains(out, "nuevas") {
		t.Fatalf("edit fijó la plataforma descubierta:\n%s", out)
	}
	if out := must(t, "", "hosts", "list", "ios-xe"); strings.Contains(out, "ñandú") {
		t.Fatalf("el texto busca solo en los valores del host:\n%s", out)
	}
}
