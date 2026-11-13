package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Fase 30e: dispositivos, libreta de hosts y snippets; con --lang en los mensajes propios salen en inglés y el núcleo
// manda las plantillas en inglés; sin --lang, lo de siempre.
func TestIdiomaDispositivosYSnippets(t *testing.T) {
	startCore(t)
	dir := t.TempDir()
	csv := filepath.Join(dir, "h.csv")
	os.WriteFile(csv, []byte("name,address,port,platform,folder,tags,credential_label,notes\nSW-X,10.0.0.9,x,,,,,\n"), 0o600)
	runLang(t, []langCase{
		{"devices", []string{"devices"}, "DIRECCIÓN", "ADDRESS"},
		{"hosts list", []string{"hosts", "list"}, "ETIQUETAS", "TAGS"},
		{"hosts campos", []string{"hosts", "template", "--fields"}, "OBLIGATORIO", "REQUIRED"},
		{"hosts tope", []string{"hosts", "template", "--fields"}, "hasta 1000 hosts y 5 MB por archivo", "up to 1000 hosts and 5 MB per file"},
		{"hosts id", []string{"hosts", "edit", "zz", "--name", "n"}, `no hay un host de la libreta con id "zz"`, `there is no address-book host with id "zz"`},
		{"hosts all", []string{"hosts", "import", csv, "--all", "x"}, `--all="x": use renombrar, reemplazar u omitir`, `--all="x": use renombrar, reemplazar or omitir`},
		{"hosts filas", []string{"hosts", "import", csv, "--preview"}, "1 filas inválidas: no se importan y cuentan como omitidas", "1 invalid rows: they are not imported and count as skipped"},
		{"hosts fila", []string{"hosts", "import", csv, "--preview"}, `línea 2: port: "x" no es un número entero`, `line 2: port: "x" is not an integer`},
		{"snippet vlan", []string{"snippet", "vlan", "10.0.0.1", "9999", "--cred", "x"}, `VLAN "9999": las VLAN van de 1 a 4094`, `VLAN "9999": VLANs go from 1 to 4094`},
		{"snippet lista", []string{"snippet", "list"}, "Crear, nombrar o borrar una VLAN", "Create, name or delete a VLAN"},
		{"snippet campos", []string{"snippet", "list"}, "(obligatorio)", "(required)"},
		{"snippet set", []string{"snippet", "run", "10.0.0.1", "vlan", "--cred", "x", "--set", "id"}, `--set "id": usa campo=valor`, `--set "id": use field=value`},
	})
}
