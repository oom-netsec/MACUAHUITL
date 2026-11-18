package vault

import (
	"os"
	"strings"
	"testing"
)

// Un fallo al escribir el .bak ya traía «vault: » del propio writeAtomicOpt y persist lo repetía:
// «vault: respaldo: vault: rename …». Ningún camino de error debe repetir el prefijo.
func TestVaultSinTartamudeo(t *testing.T) {
	v, p := newVault(t)
	if err := os.Mkdir(p+".bak", 0o700); err != nil { // el .bak es una carpeta: el rename falla
		t.Fatal(err)
	}
	_, err := v.Put(cred("core", "pw", "en"))
	if err == nil {
		t.Fatal("debe fallar")
	}
	if strings.Contains(err.Error(), "vault: respaldo: vault:") || strings.Count(err.Error(), "vault:") != 1 {
		t.Fatalf("tartamudeo: %v", err)
	}
	if _, err := Open(p + ".no"); err == nil || strings.Count(err.Error(), "vault:") != 1 {
		t.Fatalf("Open inexistente: %v", err)
	}
	if err := os.WriteFile(p+".mal", []byte("basura"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p + ".mal"); err == nil || strings.Count(err.Error(), "vault:") > 1 {
		t.Fatalf("Open corrupta: %v", err)
	}
	if _, err := OpenBackup(p+".no", pw("frase-larga-1234")); err == nil || strings.Count(err.Error(), "vault:") != 1 {
		t.Fatalf("OpenBackup inexistente: %v", err)
	}
}
