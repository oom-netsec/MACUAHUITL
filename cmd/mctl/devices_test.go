package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevicesList(t *testing.T) {
	e := startCore(t)
	dd := filepath.Join(e.out, "j1", "SW1_10.0.0.1")
	os.MkdirAll(dd, 0o700)
	os.WriteFile(filepath.Join(dd, "r001.txt"), []byte("===== 2026-11-06T10:00:00Z · show clock =====\n"), 0o600)
	os.MkdirAll(filepath.Join(e.out, "respaldos", "SW9"), 0o700)
	os.WriteFile(filepath.Join(e.out, "respaldos", "SW9", "20261105T080000Z-running.cfg"), []byte("x"), 0o600)
	out := must(t, "", "devices")
	for _, want := range []string{"DIRECCIÓN", "10.0.0.1", "SW1", "flota", "SW9", "respaldos"} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en:\n%s", want, out)
		}
	}
	if out := must(t, "", "devices", "sw9"); strings.Contains(out, "SW1") || !strings.Contains(out, "SW9") {
		t.Fatalf("filtro:\n%s", out)
	}
	if out := must(t, "", "devices", "--json"); !strings.Contains(out, `"lastSeenMs"`) {
		t.Fatalf("json:\n%s", out)
	}
	if _, err := mctl(t, "", "devices", "a", "b"); err == nil {
		t.Fatal("dos textos deben fallar")
	}
}
