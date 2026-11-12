package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestBackupCommands(t *testing.T) {
	e := startCore(t)
	must(t, "maestra\nmaestra\n", "vault", "create")
	cred := strings.TrimSpace(must(t, "pw-lab\nen-lab\n", "cred", "add", "--label", "lab", "--user", "admin"))
	ap := netip.MustParseAddrPort(e.target)
	dev := fmt.Sprintf("%s:%d", ap.Addr(), ap.Port())
	if _, err := mctl(t, "", "backup", "run", "--cred", cred); err == nil || !strings.Contains(err.Error(), "uso: mctl backup run") {
		t.Fatalf("sin equipos: %v", err)
	}
	if _, err := mctl(t, "", "backup", "run", "-d", dev, "--cred", cred, "--every", "1m"); err == nil {
		t.Fatal("intervalo sin rondas aceptado")
	}
	out, err := mctl(t, "", "backup", "run", "-d", dev, "--cred", cred)
	if err == nil || !strings.Contains(out, "mctl job logintest") {
		t.Fatalf("sin huella = %q %v", out, err)
	}
	job := regexp.MustCompile(`trabajo ([0-9a-f]+)`).FindStringSubmatch(out)[1]
	lt, _ := mctl(t, "", "job", "logintest", job)
	fp := regexp.MustCompile(`SHA256:\S+`).FindString(lt)
	out = must(t, "", "backup", "run", "-d", dev, "--cred", cred, "--accept", fp)
	if !strings.Contains(out, "1 respaldo(s) guardado(s)") {
		t.Fatalf("run = %q", out)
	}
	out = must(t, "", "backup", "list")
	id := regexp.MustCompile(`\S+/\d{8}T\d{6}Z-running`).FindString(out)
	if id == "" || !strings.Contains(out, "enmascarado") || !strings.Contains(out, "AVISO") {
		t.Fatalf("list = %q", out)
	}
	if out = must(t, "", "backup", "list", "--json"); !strings.HasPrefix(out, "{") {
		t.Fatalf("list --json = %q", out)
	}
	if _, err := mctl(t, "", "backup", "list", "../.."); err == nil {
		t.Fatal("nombre con .. aceptado")
	}
	if out = must(t, "", "backup", "export", id); !strings.Contains(out, "hostname SW-LAB-01") {
		t.Fatalf("export = %q", out)
	}
	dst := filepath.Join(t.TempDir(), "r.cfg")
	must(t, "", "backup", "export", id, "-o", dst)
	if st, err := os.Stat(dst); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("archivo %v %v", st, err)
	}
	if _, err := mctl(t, "", "backup", "export", id, "-o", dst); err == nil {
		t.Fatal("pisó un archivo existente")
	}
	// Contra el running actual: toma otro respaldo y compara. El simulador no cambia entre tomas.
	d, err := mctl(t, "", "backup", "diff", id, "--now", "-d", dev, "--cred", cred)
	if err != nil {
		t.Fatalf("diff --now = %q %v", d, err)
	}
	if !strings.Contains(d, "sin diferencias") {
		t.Fatalf("diff --now = %q", d)
	}
	if _, err := mctl(t, "", "backup", "diff", id); err == nil {
		t.Fatal("diff con un solo ID")
	}
}
