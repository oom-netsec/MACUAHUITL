package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var idRe = regexp.MustCompile(`creado ([0-9a-f]{32}) `)

func addScript(t *testing.T, name, cmds string) string {
	t.Helper()
	out := must(t, cmds, "scripts", "add", name, "--tech", "l2", "--platform", "ios-xe", "--tag", "prueba")
	m := idRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("add: %q", out)
	}
	return m[1]
}

func TestScriptsListShowAddEditRmFavDup(t *testing.T) {
	startCore(t)
	out := must(t, "", "scripts", "list")
	for _, want := range []string{"ID", "lib-l2-stp", "L2 · STP", "lectura", "configura", "biblioteca"} {
		if !strings.Contains(out, want) {
			t.Errorf("list sin %q", want)
		}
	}
	id := addScript(t, "Mi VLAN", "show vlan brief\r\n\r\nshow interfaces trunk\n")
	if out := must(t, "", "scripts", "list", "mi vlan"); !strings.Contains(out, id) || strings.Contains(out, "lib-") {
		t.Errorf("filtro por texto:\n%s", out)
	}
	out = must(t, "", "scripts", "show", id)
	if !strings.Contains(out, "show vlan brief\nshow interfaces trunk\n") || !strings.Contains(out, "prueba") || !strings.Contains(out, "lectura") {
		t.Errorf("show:\n%s", out)
	}
	if out := must(t, "", "scripts", "show", id, "--json"); !regexp.MustCompile(`"readOnly":\s+true`).MatchString(out) {
		t.Errorf("show --json:\n%s", out)
	}
	// edit solo cambia lo pasado y --file reemplaza los comandos
	cmdFile := filepath.Join(t.TempDir(), "c.txt")
	os.WriteFile(cmdFile, []byte("configure terminal\nvlan 20\n"), 0o600)
	must(t, "", "scripts", "edit", id, "--desc", "nueva", "--file", cmdFile)
	out = must(t, "", "scripts", "show", id)
	if !strings.Contains(out, "nueva") || !strings.Contains(out, "vlan 20") || !strings.Contains(out, "configura") || !strings.Contains(out, "prueba") {
		t.Errorf("edit:\n%s", out)
	}
	// favoritos de usuario y de biblioteca
	must(t, "", "scripts", "fav", id)
	must(t, "", "scripts", "fav", "lib-l2-stp")
	if out := must(t, "", "scripts", "list", "--fav"); !strings.Contains(out, id) || !strings.Contains(out, "lib-l2-stp") {
		t.Errorf("--fav:\n%s", out)
	}
	must(t, "", "scripts", "fav", id, "--off")
	if out := must(t, "", "scripts", "list", "--fav"); strings.Contains(out, id) {
		t.Errorf("--off:\n%s", out)
	}
	if out := must(t, "", "scripts", "dup", "lib-l2-stp"); !strings.Contains(out, "L2 · STP (copia)") {
		t.Errorf("dup:\n%s", out)
	}
	must(t, "", "scripts", "rm", id)
	if _, err := mctl(t, "", "scripts", "show", id); err == nil {
		t.Error("show de un script borrado debe fallar")
	}
	if _, err := mctl(t, "", "scripts", "rm", "lib-l2-stp"); err == nil {
		t.Error("rm de la biblioteca debe fallar")
	}
	if _, err := mctl(t, "", "scripts", "edit", "lib-l2-stp", "--desc", "x"); err == nil {
		t.Error("edit de la biblioteca debe fallar")
	}
	if _, err := mctl(t, "show clock\n", "scripts", "add", "malo", "--tech", "voip", "--platform", "ios-xe"); err == nil {
		t.Error("tech inválida debe fallar")
	}
	if _, err := mctl(t, "", "scripts", "add", "vacio", "--tech", "l2", "--platform", "ios-xe"); err == nil {
		t.Error("sin comandos debe fallar")
	}
}

func TestScriptsExportImportDePuntaAPunta(t *testing.T) {
	startCore(t)
	a := addScript(t, "Uno", "show clock\n")
	b := addScript(t, "Dos", "show version\n")
	path := filepath.Join(t.TempDir(), "out.json")
	out := must(t, "", "scripts", "export", "--out", path, a, b, "lib-l2-stp")
	if !strings.Contains(out, "exportados 3") {
		t.Fatalf("export: %q", out)
	}
	if _, err := mctl(t, "", "scripts", "export", "--out", path, a); err == nil {
		t.Fatal("export sin --overwrite sobre un archivo existente debe fallar")
	}
	must(t, "", "scripts", "export", "--out", path, "--overwrite", a, b, "lib-l2-stp")

	// con los mismos scripts ya guardados todo es «igual»; el de la biblioteca también (es la misma biblioteca local)
	out = must(t, "", "scripts", "import", path)
	if strings.Count(out, "igual") != 3 || !strings.Contains(out, "0 nuevos") {
		t.Fatalf("import:\n%s", out)
	}
	// ahora «Uno» difiere: conflicto_id, y sin decisión no se importa nada
	must(t, "", "scripts", "edit", a, "--desc", "cambió")
	_, err := mctl(t, "", "scripts", "import", path)
	if err == nil || !strings.Contains(err.Error(), "no se importó nada") || !strings.Contains(err.Error(), a) {
		t.Fatalf("sin decisión: %v", err)
	}
	if out := must(t, "", "scripts", "import", path, "--preview"); !strings.Contains(out, "conflicto_id") || strings.Contains(out, "importados") {
		t.Fatalf("--preview:\n%s", out)
	}
	if out := must(t, "", "scripts", "show", a); !strings.Contains(out, "cambió") {
		t.Fatalf("se importó algo sin decisión:\n%s", out)
	}
	must(t, "", "scripts", "import", path, "--decision", a+"=reemplazar")
	if out := must(t, "", "scripts", "show", a); strings.Contains(out, "cambió") {
		t.Fatalf("reemplazar no restauró:\n%s", out)
	}
	must(t, "", "scripts", "edit", a, "--desc", "otra vez")
	if out := must(t, "", "scripts", "import", path, "--all=omitir"); !strings.Contains(out, "3 omitidos") {
		t.Fatalf("--all=omitir:\n%s", out)
	}
	for _, args := range [][]string{{"import", path, "--decision", "malformada"}, {"import", path, "--all=fusionar"}, {"import"}, {"export", a}} {
		if _, err := mctl(t, "", append([]string{"scripts"}, args...)...); err == nil {
			t.Errorf("%v debió fallar", args)
		}
	}
	if _, err := mctl(t, "", "scripts", "import", filepath.Join(t.TempDir(), "no-existe.json")); err == nil {
		t.Error("archivo inexistente debe fallar")
	}
}

var colRe = regexp.MustCompile(`creada ([0-9a-f]{32}) `)

func addCol(t *testing.T, name string) string {
	t.Helper()
	m := colRe.FindStringSubmatch(must(t, "", "scripts", "col", "add", name))
	if m == nil {
		t.Fatalf("col add %q sin ID", name)
	}
	return m[1]
}

func TestScriptsColeccionesDePuntaAPunta(t *testing.T) {
	startCore(t)
	out := must(t, "", "scripts", "col", "list")
	if !strings.Contains(out, "favoritos") || !strings.Contains(out, "Favoritos") {
		t.Fatalf("col list inicial:\n%s", out)
	}
	a := addScript(t, "Uno", "show clock\n")
	b := addScript(t, "Dos", "show version\n")
	c := addCol(t, "Redes")
	must(t, "", "scripts", "col", "edit", c, "--desc", "mis redes")
	must(t, "", "scripts", "col", "set", c, b, "lib-l2-stp", a)
	out = must(t, "", "scripts", "col", "show", c)
	if !strings.Contains(out, "Redes") || !strings.Contains(out, "mis redes") || !strings.Contains(out, "Dos") || !strings.Contains(out, "L2 · STP") ||
		strings.Index(out, "Dos") > strings.Index(out, "L2 · STP") || strings.Index(out, "L2 · STP") > strings.Index(out, "Uno") {
		t.Errorf("col show (orden b, lib, a):\n%s", out)
	}
	if out := must(t, "", "scripts", "col", "show", c, "--json"); !strings.Contains(out, `"scriptIds"`) {
		t.Errorf("col show --json:\n%s", out)
	}
	// --add y --rm parten de lo que hay
	must(t, "", "scripts", "col", "set", c, "--rm", b, "--add", "lib-cfg-vlan-acceso")
	out = must(t, "", "scripts", "col", "show", c)
	if strings.Contains(out, "Dos") || !strings.Contains(out, "VLAN y puerto de acceso") || !strings.Contains(out, "Uno") {
		t.Errorf("col set --add/--rm:\n%s", out)
	}
	// agregar uno que ya está no lo repite
	must(t, "", "scripts", "col", "set", c, "--add", a)
	if out := must(t, "", "scripts", "col", "show", c); strings.Count(out, a) != 1 {
		t.Errorf("--add repetido:\n%s", out)
	}
	// favoritos y el atajo fav comparten colección
	must(t, "", "scripts", "fav", a)
	if out := must(t, "", "scripts", "col", "show", "favoritos"); !strings.Contains(out, "Uno") {
		t.Errorf("favoritos:\n%s", out)
	}
	if _, err := mctl(t, "", "scripts", "col", "rm", "favoritos"); err == nil {
		t.Error("borrar favoritos debe fallar")
	}
	if _, err := mctl(t, "", "scripts", "col", "edit", "favoritos", "--name", "Otro"); err == nil {
		t.Error("renombrar favoritos debe fallar")
	}
	// orden
	must(t, "", "scripts", "col", "order", c, "favoritos")
	if out := must(t, "", "scripts", "col", "list"); strings.Index(out, "Redes") > strings.Index(out, "Favoritos") {
		t.Errorf("col order:\n%s", out)
	}
	if _, err := mctl(t, "", "scripts", "col", "order", c); err == nil {
		t.Error("un orden incompleto debe fallar")
	}
	must(t, "", "scripts", "col", "rm", c)
	if _, err := mctl(t, "", "scripts", "col", "show", c); err == nil {
		t.Error("show de una borrada debe fallar")
	}
	for _, args := range [][]string{{"col"}, {"col", "frob"}, {"col", "add"}, {"col", "set"}, {"col", "show"}, {"col", "export", "x"}, {"col", "import"}} {
		if _, err := mctl(t, "", append([]string{"scripts"}, args...)...); err == nil {
			t.Errorf("%v debió fallar", args)
		}
	}
}

func TestScriptsPinFijaDesfijaYOrdena(t *testing.T) {
	startCore(t)
	var ids []string
	for _, n := range []string{"A", "B", "C", "D", "E", "F"} {
		ids = append(ids, addScript(t, n, "show clock\n"))
	}
	if out := must(t, "", "scripts", "pin"); strings.Contains(out, ids[0]) {
		t.Errorf("sin fijados:\n%s", out)
	}
	for _, id := range ids[:5] {
		must(t, "", "scripts", "pin", id)
	}
	_, err := mctl(t, "", "scripts", "pin", ids[5])
	if err == nil || !strings.Contains(err.Error(), "5") {
		t.Fatalf("el sexto debe fallar con el motivo: %v", err)
	}
	must(t, "", "scripts", "pin", "--order", ids[4], ids[3], ids[2], ids[1], ids[0])
	out := must(t, "", "scripts", "pin")
	if strings.Index(out, ids[4]) > strings.Index(out, ids[0]) || !strings.Contains(out, "E") {
		t.Errorf("orden de fijados:\n%s", out)
	}
	if _, err := mctl(t, "", "scripts", "pin", "--order", ids[0]); err == nil {
		t.Error("un orden incompleto debe fallar")
	}
	must(t, "", "scripts", "pin", ids[0], "--off")
	must(t, "", "scripts", "pin", ids[5])
	if out := must(t, "", "scripts", "show", ids[5]); !strings.Contains(out, "fijado") {
		t.Errorf("show sin la marca de fijado:\n%s", out)
	}
	if _, err := mctl(t, "", "scripts", "pin", ids[0], ids[1]); err == nil {
		t.Error("dos IDs deben fallar")
	}
	if _, err := mctl(t, "", "scripts", "pin", "--off"); err == nil {
		t.Error("--off sin ID debe fallar")
	}
}

func TestScriptsColeccionesExportImportDePuntaAPunta(t *testing.T) {
	startCore(t)
	a := addScript(t, "Uno", "show clock\n")
	b := addScript(t, "Dos", "show version\n")
	c := addCol(t, "Kit")
	must(t, "", "scripts", "col", "set", c, a, "lib-l2-stp", b)
	path := filepath.Join(t.TempDir(), "kit.json")
	out := must(t, "", "scripts", "col", "export", "--out", path, c)
	if !strings.Contains(out, "exportadas 1 colecciones y 2 scripts") {
		t.Fatalf("export: %q", out)
	}
	if _, err := mctl(t, "", "scripts", "col", "export", "--out", path, c); err == nil {
		t.Fatal("export sin --overwrite sobre un archivo existente debe fallar")
	}
	must(t, "", "scripts", "col", "export", "--out", path, "--overwrite", c)
	// con lo mismo guardado todo es «igual»
	out = must(t, "", "scripts", "col", "import", path)
	if strings.Count(out, "igual") != 3 || !strings.Contains(out, "0 nuevas") {
		t.Fatalf("import igual:\n%s", out)
	}
	// la colección cambia y sin decisión no se importa nada
	must(t, "", "scripts", "col", "set", c, a)
	must(t, "", "scripts", "col", "edit", c, "--desc", "cambió")
	_, err := mctl(t, "", "scripts", "col", "import", path)
	if err == nil || !strings.Contains(err.Error(), "no se importó nada") || !strings.Contains(err.Error(), c) {
		t.Fatalf("sin decisión: %v", err)
	}
	if out := must(t, "", "scripts", "col", "import", path, "--preview"); !strings.Contains(out, "conflicto_id") || strings.Contains(out, "importadas") {
		t.Fatalf("--preview:\n%s", out)
	}
	if out := must(t, "", "scripts", "col", "show", c); !strings.Contains(out, "cambió") {
		t.Fatalf("se importó algo sin decisión:\n%s", out)
	}
	must(t, "", "scripts", "col", "import", path, "--decision", c+"=reemplazar")
	if out := must(t, "", "scripts", "col", "show", c); strings.Contains(out, "cambió") || !strings.Contains(out, "Dos") {
		t.Fatalf("reemplazar no restauró:\n%s", out)
	}
	// una decisión por ID de script también se enruta, y --all cubre los conflictos
	must(t, "", "scripts", "edit", a, "--desc", "otra")
	must(t, "", "scripts", "col", "edit", c, "--desc", "otra")
	if out := must(t, "", "scripts", "col", "import", path, "--all=omitir"); !strings.Contains(out, "1 omitidas") || !strings.Contains(out, "2 omitidos") {
		t.Fatalf("--all=omitir:\n%s", out)
	}
	must(t, "", "scripts", "col", "import", path, "--decision", a+"=reemplazar", "--decision", c+"=omitir")
	if out := must(t, "", "scripts", "show", a); strings.Contains(out, "otra") {
		t.Fatalf("la decisión del script no se aplicó:\n%s", out)
	}
	for _, args := range [][]string{{"col", "import", path, "--decision", "malformada"}, {"col", "import", path, "--decision", "ajeno=omitir", "--all=omitir"}, {"col", "import", path, "--all=fusionar"}, {"col", "export", "--out", path, "no-existe", "--overwrite"}} {
		if _, err := mctl(t, "", append([]string{"scripts"}, args...)...); err == nil {
			t.Errorf("%v debió fallar", args)
		}
	}
	if _, err := mctl(t, "", "scripts", "col", "import", filepath.Join(t.TempDir(), "no.json")); err == nil {
		t.Error("archivo inexistente debe fallar")
	}
}

func TestScriptsTemplateSeImportaTalCual(t *testing.T) {
	startCore(t)
	dir := t.TempDir()
	for _, c := range []struct{ kind, estado string }{{"scripts", "nuevo"}, {"colecciones", "nueva"}} {
		out := must(t, "", "scripts", "template", "--kind", c.kind)
		if strings.Contains(out, "sha256") || !strings.Contains(out, `"formato": "macuahuitl-`+c.kind+`"`) {
			t.Fatalf("template %s:\n%s", c.kind, out)
		}
		path := filepath.Join(dir, c.kind+".json")
		os.WriteFile(path, []byte(out), 0o600)
		args := []string{"scripts", "import", path}
		if c.kind == "colecciones" {
			args = []string{"scripts", "col", "import", path}
		}
		prev := must(t, "", append(args, "--preview")...)
		if !strings.Contains(prev, "archivo sin suma de verificación") || strings.Contains(prev, "conflicto") || !strings.Contains(prev, c.estado) {
			t.Errorf("%s preview:\n%s", c.kind, prev)
		}
		if res := must(t, "", args...); !strings.Contains(res, "importad") {
			t.Errorf("%s import:\n%s", c.kind, res)
		}
	}
	// sin --kind es el de scripts
	if out := must(t, "", "scripts", "template"); !strings.Contains(out, "macuahuitl-scripts") {
		t.Errorf("por omisión:\n%s", out)
	}
	// --fields describe los campos
	out := must(t, "", "scripts", "template", "--fields")
	for _, want := range []string{"CAMPO", "scripts[].name", "sí", "no", "sha256", "formato"} {
		if !strings.Contains(out, want) {
			t.Errorf("--fields sin %q:\n%s", want, out)
		}
	}
	if !regexp.MustCompile(`(?m)^sha256\s+texto\s+no\s`).MatchString(out) || !regexp.MustCompile(`(?m)^formato\s+texto\s+sí\s`).MatchString(out) {
		t.Errorf("--fields: obligatorio:\n%s", out)
	}
	if out := must(t, "", "scripts", "template", "--kind", "colecciones", "--fields"); !strings.Contains(out, "colecciones[].script_ids") {
		t.Errorf("--fields colecciones:\n%s", out)
	}
	for _, args := range [][]string{{"template", "--kind", "otra"}, {"template", "x"}} {
		if _, err := mctl(t, "", append([]string{"scripts"}, args...)...); err == nil {
			t.Errorf("%v debió fallar", args)
		}
	}
}
