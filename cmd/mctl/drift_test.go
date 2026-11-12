package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDriftCommand(t *testing.T) {
	startCore(t)
	dir := t.TempDir()
	d := filepath.Join(dir, "SW1_192.0.2.1")
	os.MkdirAll(d, 0o755)
	for i, n := range []string{"ronda1.txt", "ronda2.txt"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "drift", "testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(d, []string{"r001_20261106-100000.txt", "r002_20261106-110000.txt"}[i])
		os.WriteFile(f, append([]byte("===== 2026-11-06T10:00:00Z · show running-config =====\n"), b...), 0o600)
	}
	out, err := mctl(t, "", "drift", dir)
	if err != nil || !strings.Contains(out, "SW1_192.0.2.1: 8 cambios") || !strings.Contains(out, "+ description PC-01-NUEVA") || strings.Contains(out, "+ ntp clock-period") {
		t.Fatalf("drift = %q %v", out, err)
	}
	if out, err = mctl(t, "", "drift", dir, "--json", "--round", "2"); err != nil || !strings.HasPrefix(out, "{") {
		t.Fatalf("drift --json = %q %v", out, err)
	}
	if _, err = mctl(t, "", "drift"); err == nil {
		t.Fatal("sin carpeta")
	}
	if _, err = mctl(t, "", "drift", dir, "--round", "1"); err == nil {
		t.Fatal("la ronda 1 no tiene anterior")
	}
}
