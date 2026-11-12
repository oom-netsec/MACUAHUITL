package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigClean(t *testing.T) {
	startCore(t)
	src, _ := filepath.Abs("../../internal/cleaner/testdata/sucia.txt")
	out, err := mctl(t, "", "config", "clean", src)
	if err != nil || !strings.Contains(out, "2 líneas vacías quitadas") || !strings.Contains(out, "5 HUÉRFANAS") {
		t.Fatalf("informe = %q %v", out, err)
	}
	dst := filepath.Join(t.TempDir(), "limpia.txt")
	if out, err = mctl(t, "", "config", "clean", src, "-o", dst, "--sort"); err != nil || !strings.Contains(out, "escrito "+dst) {
		t.Fatalf("con -o = %q %v", out, err)
	}
	b, err := os.ReadFile(dst)
	if err != nil || strings.Contains(string(b), "SW1   ") || !strings.Contains(string(b), "! HUERFANA: ACL IN-FALTA") {
		t.Fatalf("salida %v:\n%s", err, b)
	}
	if st, _ := os.Stat(dst); st.Mode().Perm() != 0o600 {
		t.Errorf("permisos %v", st.Mode())
	}
	if out, err = mctl(t, "", "config", "clean", src, "--json"); err != nil || !strings.HasPrefix(out, "{") {
		t.Fatalf("json = %q %v", out, err)
	}
	if _, err = mctl(t, "", "config", "clean", src, "-o", src); err == nil || !strings.Contains(err.Error(), "no sobrescribe") {
		t.Fatalf("sobrescribir el original: %v", err)
	}
	if _, err = mctl(t, "", "config", "clean"); err == nil {
		t.Fatal("sin archivo")
	}
	if _, err = mctl(t, "", "config", "clean", filepath.Join(t.TempDir(), "nada.txt")); err == nil {
		t.Fatal("archivo inexistente")
	}
}

// -o nunca toca un archivo que ya existe: ni el original por enlace simbólico o duro, ni otro con sus permisos.
func TestConfigCleanSalidaNoSobrescribe(t *testing.T) {
	startCore(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "orig.txt")
	const orig = "hostname SW1   \n\n\n!\n!\n"
	if err := os.WriteFile(src, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	existente := filepath.Join(dir, "existente.txt")
	if err := os.WriteFile(existente, []byte("mio"), 0o644); err != nil {
		t.Fatal(err)
	}
	sym, hard := filepath.Join(dir, "sym.txt"), filepath.Join(dir, "hard.txt")
	if err := os.Symlink(src, sym); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(src, hard); err != nil {
		t.Fatal(err)
	}
	for _, dst := range []string{sym, hard, existente, filepath.Join(dir, "colgante.txt")} {
		if dst == filepath.Join(dir, "colgante.txt") {
			if err := os.Symlink(filepath.Join(dir, "no-existe"), dst); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := mctl(t, "", "config", "clean", src, "-o", dst); err == nil {
			t.Errorf("-o %s no falló", dst)
		}
	}
	if b, _ := os.ReadFile(src); string(b) != orig {
		t.Errorf("original modificado: %q", b)
	}
	if b, _ := os.ReadFile(existente); string(b) != "mio" {
		t.Errorf("existente modificado: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "no-existe")); err == nil {
		t.Error("el enlace colgante creó su destino")
	}
	nuevo := filepath.Join(dir, "nuevo.txt")
	if _, err := mctl(t, "", "config", "clean", src, "-o", nuevo); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(nuevo); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("nuevo: %v %v", st, err)
	}
}
