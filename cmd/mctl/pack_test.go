package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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
	if o := must(t, "", "pack", "import", f, "--preview"); !strings.Contains(o, "nuevo") || strings.Contains(o, "importados") {
		t.Fatalf("preview: %q", o)
	}
	if o := must(t, "", "pack", "import", f); !strings.Contains(o, "scripts 1 nuevos") {
		t.Fatalf("import: %q", o)
	}
	if o := must(t, "", "scripts", "list", "Mi script"); !strings.Contains(o, "Mi script") {
		t.Fatalf("list: %q", o)
	}
	// Sin decisión para un conflicto no se importa nada; con --all=renombrar entra con otro nombre.
	if o := must(t, "", "pack", "import", f); !strings.Contains(o, "igual") {
		t.Fatalf("segundo import: %q", o)
	}
	if _, err := mctl(t, "", "pack", "import", f, "--decision", "x=reemplazar"); err == nil {
		t.Fatal("reemplazar no existe aquí")
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
