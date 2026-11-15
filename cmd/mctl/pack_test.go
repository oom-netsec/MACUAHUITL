package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	dompack "github.com/oom-netsec/MACUAHUITL/internal/pack"
	"github.com/oom-netsec/MACUAHUITL/internal/pack/packtest"
)

func TestPackListShowRemoveInstall(t *testing.T) {
	startCore(t) // el arnés ya instaló oom/ios-xe firmado con la llave de pruebas
	if out := must(t, "", "pack", "list"); !strings.Contains(out, "oom/ios-xe  "+versionIOSXE(t)+"  oficial") {
		t.Fatalf("list: %q", out)
	}
	if out := must(t, "", "pack", "show", "oom/ios-xe"); !strings.Contains(out, "licencia: Apache-2.0") || !strings.Contains(out, "mctl pack install") {
		t.Fatalf("show: %q", out)
	}
	if out := must(t, "", "pack", "remove", "oom/ios-xe"); !strings.Contains(out, "quitado: oom/ios-xe") {
		t.Fatalf("remove: %q", out)
	}
	if out := must(t, "", "pack", "list"); !strings.Contains(out, "no hay paquetes instalados") {
		t.Fatalf("list vacío: %q", out)
	}
	if _, err := mctl(t, "", "pack", "show", "oom/ios-xe"); err == nil || !strings.Contains(err.Error(), "oom/ios-xe") {
		t.Fatalf("show de uno que no está: %v", err)
	}
	f := filepath.Join(t.TempDir(), "oom-ios-xe.mpack")
	if err := os.WriteFile(f, packtest.IOSXE(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := must(t, "", "pack", "install", f); !strings.Contains(out, "instalado: oom/ios-xe") {
		t.Fatalf("install: %q", out)
	}
	if _, err := mctl(t, "", "pack", "install", f); err == nil {
		t.Fatal("la misma versión no se reinstala")
	}
	if _, err := mctl(t, "", "pack", "install"); err == nil || !strings.Contains(err.Error(), "uso:") {
		t.Fatalf("sin archivo: %v", err)
	}
}

// versionIOSXE lee la versión de packs/ios-xe/manifest.yaml para no fijarla en la prueba.
func versionIOSXE(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../packs/ios-xe/manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^version: (\S+)$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("el manifiesto no trae versión")
	}
	return string(m[1])
}

// pack export / pack import de punta a punta: el paquete personal sale sin firma y vuelve a «Mis scripts».
func TestPackExportImport(t *testing.T) {
	startCore(t)
	out := must(t, "show version\nshow clock\n", "scripts", "add", "Mi script", "--tech", "l2", "--platform", "ios-xe", "--tag", "prueba")
	id := regexp.MustCompile(`[0-9a-f]{32}`).FindString(out)
	if id == "" {
		t.Fatalf("add: %q", out)
	}
	f := filepath.Join(t.TempDir(), "mio.mpack")
	if _, err := mctl(t, "", "pack", "export", "acme/mio", id); err == nil {
		t.Fatal("sin --out debe fallar")
	}
	if _, err := mctl(t, "", "pack", "export", "oom/mio", id, "--out", f); err == nil {
		t.Fatal("oom está reservado")
	}
	if o := must(t, "", "pack", "export", "acme/mio", id, "--out", f); !strings.Contains(o, "exportado acme/mio") || !strings.Contains(o, "sin firma") {
		t.Fatalf("export: %q", o)
	}
	if _, err := mctl(t, "", "pack", "export", "acme/mio", id, "--out", f); err == nil {
		t.Fatal("pisó el archivo")
	}
	must(t, "", "scripts", "rm", id)
	if o := must(t, "", "pack", "import", f, "--preview"); !strings.Contains(o, "new") || strings.Contains(o, "importados") {
		t.Fatalf("preview: %q", o)
	}
	if o := must(t, "", "pack", "import", f); !strings.Contains(o, "scripts 1 nuevos") {
		t.Fatalf("import: %q", o)
	}
	if o := must(t, "", "scripts", "list", "Mi script"); !strings.Contains(o, "Mi script") {
		t.Fatalf("list: %q", o)
	}
	// Sin decisión para un conflicto no se importa nada; con --all=renombrar entra con otro nombre.
	if o := must(t, "", "pack", "import", f); !strings.Contains(o, "same") {
		t.Fatalf("segundo import: %q", o)
	}
	if _, err := mctl(t, "", "pack", "import", f, "--decision", "x=reemplazar"); err == nil {
		t.Fatal("reemplazar no existe aquí")
	}
	if _, err := mctl(t, "", "pack", "import", f, "--decision", "ninguno=omitir"); err == nil || !strings.Contains(err.Error(), "ninguno") {
		t.Fatalf("una decisión de un ID que no está debe fallar: %v", err)
	}
	if _, err := mctl(t, "", "pack", "import"); err == nil || !strings.Contains(err.Error(), "uso:") {
		t.Fatalf("sin archivo: %v", err)
	}
	// El mismo archivo se instala como paquete de solo lectura con --allow-unsigned.
	if _, err := mctl(t, "", "pack", "install", f); err == nil {
		t.Fatal("sin --allow-unsigned")
	}
	if o := must(t, "", "pack", "install", f, "--allow-unsigned"); !strings.Contains(o, "instalado: acme/mio") {
		t.Fatalf("install: %q", o)
	}
}

// mctl no lee sin tope ni se cuelga con un archivo que no es regular (dispositivo, FIFO): lo rechaza antes de hablar con el núcleo.
func TestPackInstallRechazaArchivoNoRegular(t *testing.T) {
	startCore(t)
	done := make(chan error, 1)
	go func() { _, err := mctl(t, "", "pack", "install", "/dev/zero"); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("aceptó /dev/zero")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("se colgó leyendo /dev/zero")
	}
}

// mctl pack export/import salen en inglés con --lang en, sin líneas mezcladas; en español con el idioma por omisión de las pruebas.
func TestPackExportImportEnIngles(t *testing.T) {
	startCore(t)
	id := regexp.MustCompile(`[0-9a-f]{32}`).FindString(must(t, "show clock\n", "scripts", "add", "Mi script", "--tech", "l2", "--platform", "ios-xe"))
	f := filepath.Join(t.TempDir(), "mio.mpack")
	has(t, "export en", enMust(t, "", "pack", "export", "acme/mio", id, "--out", f), "exported acme/mio", "unsigned, to "+f, "sha256 ")
	must(t, "", "scripts", "rm", id)
	must(t, "show version\n", "scripts", "add", "Mi script", "--tech", "l2", "--platform", "ios-xe") // mismo nombre, otro contenido
	has(t, "preview en", enMust(t, "", "pack", "import", f, "--preview"), "KIND", "NAME", "STATE", "CONFLICTS WITH", "name_conflict")
	_, err := en(t, "", "pack", "import", f)
	if err == nil || !strings.Contains(err.Error(), "nothing imported: 1 conflict(s) need a decision") {
		t.Fatalf("sin decidir: %v", err)
	}
	if _, err := en(t, "", "pack", "import", f, "--decision", "x=reemplazar"); err == nil || !strings.Contains(err.Error(), `invalid decision "x=reemplazar"`) || strings.Contains(err.Error(), "uso") {
		t.Fatalf("decisión inválida: %v", err)
	}
	if _, err := en(t, "", "pack", "import", f, "--decision", "ninguno=omitir"); err == nil || !strings.Contains(err.Error(), `"ninguno", which is not in the pack`) {
		t.Fatalf("decisión de un ID ausente: %v", err)
	}
	if _, err := mctl(t, "", "pack", "import", f, "--decision", "x=reemplazar"); err == nil || !strings.Contains(err.Error(), `decisión inválida "x=reemplazar"`) {
		t.Fatalf("decisión inválida es: %v", err)
	}
	has(t, "import en", enMust(t, "", "pack", "import", f, "--all=omitir"), "imported: scripts 0 new, 0 renamed, 1 skipped; playbooks 0 new, 0 renamed, 0 skipped")
}

// Un oficial que quitaría paquetes de terceros pregunta; sin respuesta (stdin no interactivo) falla y no toca nada;
// con --yes o un «s» procede.
func TestPackInstallPideConfirmarLosApartados(t *testing.T) {
	startCore(t)
	must(t, "", "pack", "remove", "oom/ios-xe")
	src, err := os.ReadFile("../../packs/ios-xe/playbooks/l2-stp.yaml")
	if err != nil {
		t.Fatal(err)
	}
	name := regexp.MustCompile(`(?m)^name: (.+)$`).FindSubmatch(src)[1]
	files := map[string][]byte{
		"manifest.yaml":           []byte("id: acme/demo\nversion: 1.0.0\nmin_core: 0.3.0\nname: A\nname_en: A\ndescription: d\ndescription_en: d\nplatforms: [ios-xe]\nauthor: a\nlicense: MIT\n"),
		"README.md":               []byte("x"),
		"playbooks/acme-stp.yaml": []byte("id: acme-stp\nplatform: ios-xe\nname: " + string(name) + "\nname_en: \"Acme only\"\ncommands:\n  - cmd: show clock\n"),
	}
	zb, err := dompack.Zip(files)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	third, off := filepath.Join(dir, "acme.mpack"), filepath.Join(dir, "oom.mpack")
	os.WriteFile(third, zb, 0o600)
	os.WriteFile(off, packtest.IOSXE(t), 0o600)
	must(t, "", "pack", "install", "--allow-unsigned", third)
	if out, err := mctl(t, "", "pack", "install", off); err == nil || !strings.Contains(err.Error(), "--yes") || !strings.Contains(out, "acme/demo") {
		t.Fatalf("sin confirmar: %v\n%s", err, out)
	}
	if out := must(t, "", "pack", "list"); !strings.Contains(out, "acme/demo") || strings.Contains(out, "oom/ios-xe") {
		t.Fatalf("tocó el almacén: %q", out)
	}
	if _, err := mctl(t, "n\n", "pack", "install", off); err == nil {
		t.Fatal("una negativa no instala")
	}
	if out := must(t, "s\n", "pack", "install", off); !strings.Contains(out, "instalado: oom/ios-xe") {
		t.Fatalf("con «s»: %q", out)
	}
	if out := must(t, "", "pack", "list"); strings.Contains(out, "acme/demo") {
		t.Fatalf("el apartado sigue: %q", out)
	}
	must(t, "", "pack", "remove", "oom/ios-xe")
	must(t, "", "pack", "install", "--allow-unsigned", third)
	if out := must(t, "", "pack", "install", "--yes", off); !strings.Contains(out, "instalado: oom/ios-xe") {
		t.Fatalf("--yes: %q", out)
	}
}
