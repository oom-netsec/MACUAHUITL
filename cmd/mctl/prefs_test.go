package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrefsShowYSet(t *testing.T) {
	e := startCore(t)
	out, err := mctl(t, "", "prefs", "show")
	if err != nil || !strings.Contains(out, "carpeta de salidas: "+e.out+" (de fábrica)") || !strings.Contains(out, "rotar_mb: de fábrica") {
		t.Fatalf("show = %q %v", out, err)
	}
	// el núcleo de la prueba tiene HOME y carpetas reales: la carpeta nueva va en un temporal 0700
	// junto a las pruebas: /tmp es de todos y la validación no lo acepta como ancestro
	nueva, err := os.MkdirTemp(".", "salidas-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(nueva) })
	nueva, _ = filepath.Abs(nueva)
	out, err = mctl(t, "", "prefs", "set", "--outputs", nueva, "--rotate-mb", "10", "--format", "jsonl")
	if err != nil || !strings.Contains(out, "carpeta de salidas: "+nueva) || !strings.Contains(out, "rotar_mb: 10") || !strings.Contains(out, "no se mueven") {
		t.Fatalf("set = %q %v", out, err)
	}
	// set cambia solo lo que se pide: la carpeta y el formato siguen
	out, err = mctl(t, "", "prefs", "set", "--max-files", "5")
	if err != nil || !strings.Contains(out, "carpeta de salidas: "+nueva) || !strings.Contains(out, "formato: jsonl") || !strings.Contains(out, "max_archivos: 5") || strings.Contains(out, "no se mueven") {
		t.Fatalf("set parcial = %q %v", out, err)
	}
	if out, err = mctl(t, "", "prefs", "show", "--json"); err != nil || !strings.Contains(out, `"outputs_dir_effective"`) || !strings.Contains(out, nueva) {
		t.Fatalf("json = %q %v", out, err)
	}
	// --outputs "" vuelve a la de fábrica
	if out, err = mctl(t, "", "prefs", "set", "--outputs", ""); err != nil || !strings.Contains(out, "(de fábrica)") {
		t.Fatalf("reset = %q %v", out, err)
	}
	// errores del núcleo con su código; rangos fuera de 32 bits en el cliente
	if _, err = mctl(t, "", "prefs", "set", "--outputs", "relativa"); err == nil || !strings.Contains(err.Error(), "prefs.outputs.relativa") {
		t.Fatalf("relativa: %v", err)
	}
	if _, err = mctl(t, "", "prefs", "set", "--rotate-mb", "5000"); err == nil {
		t.Fatal("rango")
	}
	if _, err = mctl(t, "", "prefs", "set", "--rotate-mb", "99999999999"); err == nil || !strings.Contains(err.Error(), "fuera de rango") {
		t.Fatalf("32 bits: %v", err)
	}
	if _, err = mctl(t, "", "prefs", "set"); err == nil {
		t.Fatal("set sin banderas debía dar uso")
	}
	if _, err = mctl(t, "", "prefs", "show", "extra"); err == nil {
		t.Fatal("show con argumentos")
	}
}
