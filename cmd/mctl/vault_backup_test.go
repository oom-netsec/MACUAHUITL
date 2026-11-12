package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Respaldo cifrado de la bóveda de punta a punta: las frases entran por stdin (nunca por argumentos) y ni la salida ni la auditoría traen
// secretos, usuarios ni frases.
func TestCredBackupExportImportPuntaAPunta(t *testing.T) {
	startCore(t)
	must(t, "maestra\nmaestra\n", "vault", "create")
	must(t, "PW-SECRETO\nEN-SECRETO\n", "cred", "add", "--label", "core", "--user", "USR-CORE")
	must(t, "PW-DOS\n", "cred", "add", "--label", "borde", "--user", "USR-BORDE", "--no-enable")
	ruta := filepath.Join(t.TempDir(), "r.mcvault")
	salidas := []string{}
	nota := func(s string) string { salidas = append(salidas, s); return s }

	// Sin --yes (y sin terminal) no exporta; con frases distintas entre sí tampoco.
	if out, err := mctl(t, "frase-respaldo-1\nfrase-respaldo-1\n", "cred", "backup", "export", ruta); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("sin --yes: %v %q", err, out)
	}
	if _, err := mctl(t, "frase-respaldo-1\notra-frase-larga\n", "cred", "backup", "export", ruta, "--yes"); err == nil || !strings.Contains(err.Error(), "no coinciden") {
		t.Fatalf("frases distintas: %v", err)
	}
	if _, err := mctl(t, "corta\ncorta\n", "cred", "backup", "export", ruta, "--yes"); err == nil {
		t.Fatal("aceptó una frase corta")
	}
	if _, err := mctl(t, "maestra\nmaestra\n", "cred", "backup", "export", ruta, "--yes"); err == nil {
		t.Fatal("aceptó la maestra")
	}
	if _, err := os.Stat(ruta); err == nil {
		t.Fatal("dejó un archivo tras los rechazos")
	}
	out := nota(must(t, "frase-respaldo-1\nfrase-respaldo-1\n", "cred", "backup", "export", ruta, "--yes"))
	if !strings.Contains(out, "2 credenciales") || !strings.Contains(out, ruta) {
		t.Fatalf("export: %q", out)
	}
	if fi, err := os.Stat(ruta); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("archivo: %v %v", fi, err)
	}
	if _, err := mctl(t, "frase-respaldo-1\nfrase-respaldo-1\n", "cred", "backup", "export", ruta, "--yes"); err == nil {
		t.Fatal("pisó el archivo sin --overwrite")
	}
	must(t, "frase-respaldo-1\nfrase-respaldo-1\n", "cred", "backup", "export", ruta, "--yes", "--overwrite")

	// Importar sobre la misma bóveda: todo igual.
	out = nota(must(t, "frase-respaldo-1\n", "cred", "backup", "import", ruta))
	if strings.Count(out, "igual") < 2 || !strings.Contains(out, "2 iguales") {
		t.Fatalf("import igual:\n%s", out)
	}
	if strings.Contains(out, "USR-") {
		t.Fatalf("la salida trae el usuario:\n%s", out)
	}
	// Frase incorrecta y archivo ajeno.
	if _, err := mctl(t, "frase-incorrecta-1\n", "cred", "backup", "import", ruta); err == nil || !strings.Contains(err.Error(), "frase del respaldo") {
		t.Fatalf("frase incorrecta: %v", err)
	}
	ajeno := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(ajeno, []byte(strings.Repeat("hola mundo, no soy un respaldo\n", 8)), 0o600)
	if _, err := mctl(t, "frase-respaldo-1\n", "cred", "backup", "import", ajeno); err == nil || !strings.Contains(err.Error(), "no es un respaldo de bóveda de MACUAHUITL") {
		t.Fatalf("ajeno: %v", err)
	}

	// Cambia "core" y borra "borde": una queda en conflicto y la otra es nueva.
	var idCore, idBorde string
	for _, l := range strings.Split(must(t, "", "cred", "list"), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[1] == "core" {
			idCore = f[0]
		}
		if len(f) >= 2 && f[1] == "borde" {
			idBorde = f[0]
		}
	}
	must(t, "", "cred", "rm", idBorde)
	must(t, "", "cred", "rm", idCore)
	must(t, "OTRO-PW\n", "cred", "add", "--label", "core", "--user", "USR-CORE", "--no-enable")
	out, err := mctl(t, "frase-respaldo-1\n", "cred", "backup", "import", ruta, "--preview")
	nota(out)
	if err != nil || !strings.Contains(out, "conflicto_etiqueta") || !strings.Contains(out, "nueva") {
		t.Fatalf("preview: %v\n%s", err, out)
	}
	if n := strings.Count(must(t, "", "cred", "list"), "\n"); n != 1 {
		t.Fatalf("--preview cambió la bóveda (%d líneas)", n)
	}
	// Sin decisión para el conflicto no se importa nada.
	if out, err := mctl(t, "frase-respaldo-1\n", "cred", "backup", "import", ruta); err == nil || !strings.Contains(err.Error(), "no se importó nada") {
		t.Fatalf("sin decisión: %v\n%s", err, out)
	}
	if n := strings.Count(must(t, "", "cred", "list"), "\n"); n != 1 {
		t.Fatal("importó algo sin decidir el conflicto")
	}
	out = nota(must(t, "frase-respaldo-1\n", "cred", "backup", "import", ruta, "--decision", "core=renombrar"))
	if !strings.Contains(out, "1 nuevas") || !strings.Contains(out, "1 renombradas") {
		t.Fatalf("import: %q", out)
	}
	if l := must(t, "", "cred", "list"); !strings.Contains(l, "core (importada)") || !strings.Contains(l, "borde") {
		t.Fatalf("lista:\n%s", l)
	}
	if _, err := mctl(t, "frase-respaldo-1\n", "cred", "backup", "import", ruta, "--all=fusionar"); err == nil {
		t.Fatal("aceptó una acción desconocida")
	}

	// Ni los secretos, usuarios ni frases en lo impreso ni en la auditoría.
	todo := strings.Join(salidas, "\n") + must(t, "", "audit", "export")
	for _, p := range []string{"PW-SECRETO", "EN-SECRETO", "PW-DOS", "OTRO-PW", "USR-", "frase-respaldo-1", "frase-incorrecta-1"} {
		if strings.Contains(todo, p) {
			t.Fatalf("aparece %q:\n%s", p, todo)
		}
	}
	for _, a := range []string{"vault.respaldo.exportar", "vault.respaldo.importar"} {
		if !strings.Contains(todo, a) {
			t.Fatalf("la auditoría no trae %s", a)
		}
	}
}
