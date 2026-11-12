package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFleetCommands(t *testing.T) {
	startCore(t)
	dir, _ := filepath.Abs("../../internal/fleet/testdata/outputs")
	d := []string{"--dir", dir}
	run := func(args ...string) string {
		t.Helper()
		out, err := mctl(t, "", append(args, d...)...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return out
	}
	if out := run("find", "AA:BB:CC:00:0A:01"); !strings.Contains(out, "ACC1") || !strings.Contains(out, "Gi1/0/5") || !strings.Contains(out, "hace") {
		t.Errorf("find: %s", out)
	}
	if out := run("trace", "10.1.10.20"); !strings.Contains(out, "Puerto de acceso: ACC1 Gi1/0/5") {
		t.Errorf("trace: %s", out)
	}
	svg := filepath.Join(t.TempDir(), "p.svg")
	if out := run("path", "10.1.10.20", "10.1.20.50", "--svg", svg); !strings.Contains(out, "LLEGÓ") {
		t.Errorf("path: %s", out)
	}
	if b, err := os.ReadFile(svg); err != nil || !strings.HasPrefix(string(b), "<svg") {
		t.Errorf("svg %v", err)
	}
	if out := run("health", "interfaces", "--json"); !strings.Contains(out, `"severity":"critica"`) {
		t.Errorf("health: %s", out)
	}
	if out := run("fleet", "summary"); !strings.Contains(out, "DIST1") || !strings.Contains(out, "DATO VIEJO") {
		t.Errorf("summary: %s", out)
	}
	if out := run("fleet", "flash", "--need", "1G"); !strings.Contains(out, "NO CABE") {
		t.Errorf("flash: %s", out)
	}
	if out := run("fleet", "inventory", "--csv"); !strings.HasPrefix(out, "Equipo,Tipo") {
		t.Errorf("csv: %s", out)
	}
	if out := run("fleet", "inventory", "--md"); !strings.Contains(out, "| --- |") {
		t.Errorf("md: %s", out)
	}
	if _, err := mctl(t, "", "find"); err == nil {
		t.Error("find sin argumento")
	}
	if _, err := mctl(t, "", "fleet", "flash", "--need", "mucho", "--dir", dir); err == nil {
		t.Error("tamaño inválido")
	}
	if _, err := mctl(t, "", "find", "x", "--dir", t.TempDir()); err == nil {
		t.Error("carpeta sin salidas")
	}
}
