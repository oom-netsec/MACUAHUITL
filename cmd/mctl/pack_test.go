package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/pack/packtest"
)

func TestPackListShowRemoveInstall(t *testing.T) {
	startCore(t) // el arnés ya instaló oom/ios-xe firmado con la llave de pruebas
	if out := must(t, "", "pack", "list"); !strings.Contains(out, "oom/ios-xe  1.0.0  oficial") {
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
