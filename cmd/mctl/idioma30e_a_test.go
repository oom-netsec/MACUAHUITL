package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
)

// Fase 30e (mctl, parte A): con --lang en los mensajes propios de mctl salen en inglés; sin él, el es de siempre.

// en corre mctl con --lang en y restaura el idioma al terminar.
func en(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	t.Cleanup(func() { cli.SetLang("") })
	return mctl(t, stdin, append([]string{"--lang", "en"}, args...)...)
}

func enMust(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	out, err := en(t, stdin, args...)
	if err != nil {
		t.Fatalf("mctl --lang en %v: %v\n%s", args, err, out)
	}
	return out
}

// has revisa que out traiga todas las frases (con su variante es o en).
func has(t *testing.T, what, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("%s: falta %q en:\n%s", what, w, out)
		}
	}
}

func errHas(t *testing.T, what string, err error, wants ...string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: debió fallar", what)
		return
	}
	has(t, what, err.Error(), wants...)
}

func TestIdioma30eScripts(t *testing.T) {
	startCore(t)
	out := enMust(t, "show vlan brief\n", "scripts", "add", "Mi VLAN", "--tech", "l2", "--platform", "ios-xe", "--tag", "prueba")
	m := regexp.MustCompile(`created ([0-9a-f]{32}) \(Mi VLAN\)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("add: %q", out)
	}
	id := m[1]
	list := enMust(t, "", "scripts", "list")
	has(t, "list en", list, "TECHNOLOGY", "MODE", "read", "configure")
	has(t, "list es", must(t, "", "scripts", "list"), "TECNOLOGÍA", "lectura", "configura")
	show := enMust(t, "", "scripts", "show", id)
	has(t, "show en", show, "tags: prueba", "created: ", "edited: ")
	has(t, "show es", must(t, "", "scripts", "show", id), "etiquetas: prueba", "creado: ", "editado: ")
	has(t, "pin en", enMust(t, "", "scripts", "pin", id), "pinned: "+id)
	has(t, "show fijado en", enMust(t, "", "scripts", "show", id), " · pinned")
	has(t, "show fijado es", must(t, "", "scripts", "show", id), " · fijado")
	has(t, "pin list en", enMust(t, "", "scripts", "pin"), "NAME", "MODE", id)
	has(t, "pin list es", must(t, "", "scripts", "pin"), "NOMBRE", "MODO")
	has(t, "unpin en", enMust(t, "", "scripts", "pin", id, "--off"), "unpinned: "+id)
	has(t, "pin es", must(t, "", "scripts", "pin", id), "fijado: "+id)
	has(t, "pin order en", enMust(t, "", "scripts", "pin", "--order", id), "pinned order saved")
	has(t, "pin order es", must(t, "", "scripts", "pin", "--order", id), "orden de fijados guardado")
	must(t, "", "scripts", "pin", id, "--off")
	has(t, "fav en", enMust(t, "", "scripts", "fav", id), "favorite: "+id)
	has(t, "fav off en", enMust(t, "", "scripts", "fav", id, "--off"), "favorite removed: "+id)
	has(t, "fav es", must(t, "", "scripts", "fav", id), "favorito: "+id)
	must(t, "", "scripts", "fav", id, "--off")
	has(t, "dup en", enMust(t, "", "scripts", "dup", "lib-l2-stp"), "created ")
	has(t, "edit en", enMust(t, "", "scripts", "edit", id, "--desc", "x"), "saved "+id)
	has(t, "edit es", must(t, "", "scripts", "edit", id, "--desc", "y"), "guardado "+id)

	// export / import
	path := filepath.Join(t.TempDir(), "out.json")
	has(t, "export en", enMust(t, "", "scripts", "export", "--out", path, id), "exported 1 scripts to "+path)
	has(t, "import en", enMust(t, "", "scripts", "import", path), "NAME", "STATE", "CONFLICTS WITH", "imported: 0 new, 0 replaced, 0 renamed, 1 skipped")
	has(t, "import es", must(t, "", "scripts", "import", path), "CHOCA CON", "importados: 0 nuevos, 0 reemplazados, 0 renombrados, 1 omitidos")
	must(t, "", "scripts", "edit", id, "--desc", "cambió")
	_, err := en(t, "", "scripts", "import", path)
	errHas(t, "import sin decisión en", err, "nothing was imported: 1 conflict(s) still need a decision", "--all=ACTION: "+id)
	_, err = mctl(t, "", "scripts", "import", path)
	errHas(t, "import sin decisión es", err, "no se importó nada: falta decidir 1 conflicto(s)", "--all=ACCIÓN: "+id)
	_, err = en(t, "", "scripts", "import", path, "--all=fusionar")
	errHas(t, "--all en", err, `--all="fusionar": use renombrar, reemplazar or omitir`)
	_, err = mctl(t, "", "scripts", "import", path, "--all=fusionar")
	errHas(t, "--all es", err, `--all="fusionar": use renombrar, reemplazar u omitir`)
	_, err = en(t, "", "scripts", "import", path, "--decision", "malformada")
	errHas(t, "--decision en", err, `--decision "malformada": use ID=renombrar|reemplazar|omitir`)
	has(t, "import omitir en", enMust(t, "", "scripts", "import", path, "--all=omitir"), "1 skipped")

	// archivo de comandos que no es regular y borrar
	_, err = en(t, "", "scripts", "add", "X", "--tech", "l2", "--platform", "ios-xe", "--file", t.TempDir())
	errHas(t, "no regular en", err, "is not a regular file")
	_, err = mctl(t, "", "scripts", "add", "X", "--tech", "l2", "--platform", "ios-xe", "--file", t.TempDir())
	errHas(t, "no regular es", err, "no es un archivo regular")
	has(t, "rm en", enMust(t, "", "scripts", "rm", id), "deleted "+id)

	// plantilla
	has(t, "template en", enMust(t, "", "scripts", "template", "--fields"), "FIELD", "REQUIRED", "EXAMPLE", "DESCRIPTION", "yes")
	has(t, "template es", must(t, "", "scripts", "template", "--fields"), "CAMPO", "OBLIGATORIO", "sí")
}

func TestIdioma30eScriptsColecciones(t *testing.T) {
	startCore(t)
	s := addScript(t, "Uno", "show clock\n")
	out := enMust(t, "", "scripts", "col", "add", "Mi col")
	m := regexp.MustCompile(`created ([0-9a-f]{32}) \(Mi col\)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("col add: %q", out)
	}
	c := m[1]
	has(t, "col list en", enMust(t, "", "scripts", "col", "list"), "ORDER", "NAME", c)
	has(t, "col list es", must(t, "", "scripts", "col", "list"), "ORDEN", "NOMBRE")
	has(t, "col set en", enMust(t, "", "scripts", "col", "set", c, s), "collection "+c+" (Mi col): 1 scripts")
	has(t, "col set es", must(t, "", "scripts", "col", "set", c, s), "colección "+c+" (Mi col): 1 scripts")
	has(t, "col show en", enMust(t, "", "scripts", "col", "show", c), "· order ", "created: ", "edited: ")
	has(t, "col show es", must(t, "", "scripts", "col", "show", c), "· orden ", "creada: ", "editada: ")
	has(t, "col edit en", enMust(t, "", "scripts", "col", "edit", c, "--desc", "d"), "saved "+c)
	has(t, "col edit es", must(t, "", "scripts", "col", "edit", c, "--desc", "e"), "guardada "+c)
	has(t, "col order en", enMust(t, "", "scripts", "col", "order", "favoritos", c), "order saved")
	has(t, "col order es", must(t, "", "scripts", "col", "order", "favoritos", c), "orden guardado")
	path := filepath.Join(t.TempDir(), "c.json")
	has(t, "col export en", enMust(t, "", "scripts", "col", "export", "--out", path, c), "exported 1 collections and 1 scripts to "+path)
	has(t, "col export es", must(t, "", "scripts", "col", "export", "--out", path, "--overwrite", c), "exportadas 1 colecciones y 1 scripts a "+path)
	imp := enMust(t, "", "scripts", "col", "import", path)
	has(t, "col import en", imp, "TYPE", "CONFLICTS WITH", "collection", "imported: ", "merged", "skipped; scripts: ")
	has(t, "col import es", must(t, "", "scripts", "col", "import", path), "TIPO", "colección", "importadas: ", "fusionadas", "omitidas; scripts: ")
	_, err := en(t, "", "scripts", "col", "import", path, "--decision", "nada=omitir")
	errHas(t, "col decision en", err, "--decision nada: not a collection or a script in the file")
	_, err = mctl(t, "", "scripts", "col", "import", path, "--decision", "nada=omitir")
	errHas(t, "col decision es", err, "--decision nada: no es una colección ni un script del archivo")
	has(t, "col rm en", enMust(t, "", "scripts", "col", "rm", c), "deleted "+c)
	must(t, "", "scripts", "col", "add", "Otra")
}

func TestIdioma30eVaultYCred(t *testing.T) {
	startCore(t)
	has(t, "status en", enMust(t, "", "vault", "status"), "vault does not exist")
	has(t, "status es", must(t, "", "vault", "status"), "bóveda no existe")
	_, err := en(t, "una\notra\n", "vault", "create")
	errHas(t, "create en", err, "the passwords do not match")
	_, err = mctl(t, "una\notra\n", "vault", "create")
	errHas(t, "create es", err, "las contraseñas no coinciden")
	must(t, "maestra\nmaestra\n", "vault", "create")
	has(t, "status abierta en", enMust(t, "", "vault", "status"), "vault unlocked")
	must(t, "", "vault", "lock")
	has(t, "status cerrada en", enMust(t, "", "vault", "status"), "vault locked")
	must(t, "maestra\n", "vault", "unlock")
	_, err = en(t, "", "cred", "add", "--label", "x")
	errHas(t, "cred add en", err, "--user is missing")
	_, err = mctl(t, "", "cred", "add", "--label", "x")
	errHas(t, "cred add es", err, "falta --user")
	_, err = en(t, "a\nb\nc\n", "vault", "passwd")
	errHas(t, "passwd en", err, "the passwords do not match")
	must(t, "PW\nEN\n", "cred", "add", "--label", "core", "--user", "USR")
	_, err = en(t, "", "cred", "backup", "export", filepath.Join(t.TempDir(), "r"))
	errHas(t, "export sin yes en", err, "the backup holds all your credentials: confirm with --yes")
	_, err = mctl(t, "", "cred", "backup", "export", filepath.Join(t.TempDir(), "r"))
	errHas(t, "export sin yes es", err, "el respaldo contiene todas tus credenciales: confirma con --yes")
	_, err = en(t, "frase-respaldo-1\notra-frase-larga\n", "cred", "backup", "export", filepath.Join(t.TempDir(), "r"), "--yes")
	errHas(t, "frases en", err, "the passphrases do not match")
	ruta := filepath.Join(t.TempDir(), "r.mcvault")
	has(t, "export en", enMust(t, "frase-respaldo-1\nfrase-respaldo-1\n", "cred", "backup", "export", ruta, "--yes"), "backup of 1 credentials in "+ruta)
	has(t, "import en", enMust(t, "frase-respaldo-1\n", "cred", "backup", "import", ruta), "LABEL", "STATE", "imported: 0 new, 0 replaced, 0 renamed, 0 skipped, 1 unchanged")
	has(t, "import es", must(t, "frase-respaldo-1\n", "cred", "backup", "import", ruta), "ETIQUETA", "importadas: 0 nuevas, 0 reemplazadas, 0 renombradas, 0 omitidas, 1 iguales")
	_, err = en(t, "frase-respaldo-1\n", "cred", "backup", "import", ruta, "--all=x")
	errHas(t, "import all en", err, `--all="x": use renombrar, reemplazar or omitir`)
}

func TestIdioma30eSecurityPki(t *testing.T) {
	startCore(t)
	_, err := en(t, "sec\n", "radius", "test", "127.0.0.1:abc", "--user", "u")
	errHas(t, "puerto en", err, `invalid port "abc"`)
	_, err = mctl(t, "sec\n", "radius", "test", "127.0.0.1:abc", "--user", "u")
	errHas(t, "puerto es", err, `puerto inválido "abc"`)
	_, err = en(t, "sec\n", "radius", "test", "127.0.0.1:1812", "--user", "u", "--acct-port", "70000")
	errHas(t, "acct-port en", err, "invalid --acct-port")
	_, err = en(t, "sec\n", "radius", "test", "127.0.0.1:1812")
	errHas(t, "user o cred en", err, "--user or --cred is missing")
	_, err = mctl(t, "sec\n", "radius", "test", "127.0.0.1:1812")
	errHas(t, "user o cred es", err, "falta --user o --cred")

	t.Chdir(t.TempDir())
	_, err = en(t, "", "pki", "key")
	errHas(t, "key en", err, "-o FILE is missing")
	_, err = mctl(t, "", "pki", "key")
	errHas(t, "key es", err, "falta -o ARCHIVO")
	_, err = en(t, "", "pki", "csr")
	errHas(t, "csr en", err, "--cn is missing")
	_, err = en(t, "", "pki", "ca", "init")
	errHas(t, "ca init en", err, "--name is missing")
	_, err = en(t, "a\nb\n", "pki", "key", "-o", "k.pem")
	errHas(t, "mismatch en", err, "the passwords do not match")
	_, err = mctl(t, "a\nb\n", "pki", "key", "-o", "k.pem")
	errHas(t, "mismatch es", err, "las contraseñas no coinciden")
	has(t, "key en", enMust(t, "pw\npw\n", "pki", "key", "-o", "k.pem"), "sealed key in k.pem")
	os.Remove("k.pem")
	has(t, "key es", must(t, "pw\npw\n", "pki", "key", "-o", "k.pem"), "llave sellada en k.pem")
	has(t, "ca init en", enMust(t, "capw\ncapw\n", "pki", "ca", "init", "--name", "Lab CA", "--out", "ca"), "CA in ca/ (ca.crt.pem, sealed ca.key.pem)")
	has(t, "csr en", enMust(t, "kpw\nkpw\n", "pki", "csr", "--cn", "ise01.lab", "-o", "ise01"), "CSR in ise01.csr.pem")
	_, err = en(t, "kpw\nkpw\n", "pki", "csr", "--cn", "ise01.lab", "-o", "ise01")
	errHas(t, "csr existe en", err, "ise01.csr.pem already exists")
	_, err = mctl(t, "kpw\nkpw\n", "pki", "csr", "--cn", "ise01.lab", "-o", "ise01")
	errHas(t, "csr existe es", err, "ise01.csr.pem ya existe")
	has(t, "sign en", enMust(t, "capw\n", "pki", "ca", "sign", "--ca", "ca", "--csr", "ise01.csr.pem", "-o", "ise01.crt.pem"), "certificate in ise01.crt.pem")
	has(t, "export en", enMust(t, "", "pki", "export", "--cert", "ise01.crt.pem", "--format", "pem", "-o", "out.pem"), "exported to out.pem")
	os.Remove("out.pem")
	has(t, "export es", must(t, "", "pki", "export", "--cert", "ise01.crt.pem", "--format", "pem", "-o", "out.pem"), "exportado a out.pem")
}

func TestIdioma30eToolsYVisibility(t *testing.T) {
	startCore(t)
	_, err := en(t, "", "tls", "inspect", "127.0.0.1:abc")
	errHas(t, "tls en", err, `invalid port "abc"`)
	_, err = mctl(t, "", "tls", "inspect", "127.0.0.1:abc")
	errHas(t, "tls es", err, `puerto inválido "abc"`)
	syslog := []string{"syslog", "listen", "--addr", "127.0.0.1:0", "--for", "1"}
	has(t, "syslog en", enMust(t, "", syslog...), "listening on 127.0.0.1:")
	has(t, "syslog es", must(t, "", syslog...), "escuchando en 127.0.0.1:")
	traps := []string{"snmp", "traps", "listen", "--addr", "127.0.0.1:0", "--for", "1"}
	has(t, "traps en", enMust(t, "", traps...), "listening for traps on 127.0.0.1:", "/udp")
	has(t, "traps es", must(t, "", traps...), "escuchando traps en 127.0.0.1:")
	flows := []string{"flows", "listen", "--addr", "127.0.0.1:0", "--for", "1"}
	has(t, "flows en", enMust(t, "", flows...), "listening for flows on 127.0.0.1:")
	has(t, "flows es", must(t, "", flows...), "escuchando flujos en 127.0.0.1:")
}

func TestIdioma30eMetricsYPorts(t *testing.T) {
	startCore(t)
	dir := metricsJob(t)
	has(t, "metrics en", enMust(t, "", "job", "metrics", dir, "--device", "sw1"), "SW1 (10.0.0.1) · 2 rounds", "CPU    latest 5s/1min/5min: ", "5s peak: ", "INTERFACE", "PEAK UTIL %", "warning: ")
	has(t, "metrics es", must(t, "", "job", "metrics", dir, "--device", "sw1"), "SW1 (10.0.0.1) · 2 rondas", "CPU    último 5s/1min/5min: ", "pico 5s: ", "INTERFAZ", "PICO UTIL %", "aviso: ")
	csv := enMust(t, "", "job", "metrics", dir, "--csv")
	has(t, "metrics csv no se traduce", csv, "equipo,serie,nombre,ronda,hora,metrica,valor")
	_, err := en(t, "", "job", "metrics", dir, "--csv", "--json")
	errHas(t, "metrics uso sigue en es", err, "uso: mctl job metrics")
}

func TestIdioma30ePortsStatusYSet(t *testing.T) {
	startCore(t)
	dir := t.TempDir()
	dd := filepath.Join(dir, "SW1_10.0.0.1")
	os.MkdirAll(dd, 0o700)
	read := func(n string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "parse", "iosxe", "testdata", n+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	body := "===== ronda 1 · 2026-11-06T10:00:00Z · show interfaces status =====\n" + read("ios152_show-interfaces-status") +
		"===== ronda 1 · 2026-11-06T10:00:01Z · show interfaces trunk =====\n" + read("ios152_show-interfaces-trunk") +
		"===== ronda 1 · 2026-11-06T10:00:02Z · show etherchannel summary =====\n" + read("iosxe_show-etherchannel-summary")
	os.WriteFile(filepath.Join(dd, "SW1.txt"), []byte(body), 0o600)
	has(t, "ports status en", enMust(t, "", "ports", "status", dir), "PORT", "STATE", "DUPLEX", "SPEED", "NOTES", "DESCRIPTION", "channel Po1 (SU, LACP): Gi1/0/1(P) Gi1/0/2(P)")
	has(t, "ports status es", must(t, "", "ports", "status", dir), "PUERTO", "ESTADO", "DÚPLEX", "VELOCIDAD", "NOTAS", "canal Po1 (SU, LACP)")
	has(t, "ports runs en", enMust(t, "", "ports", "runs"), "There are no runs.")
	has(t, "ports runs es", must(t, "", "ports", "runs"), "No hay ejecuciones.")
}

func TestIdioma30ePortsSet(t *testing.T) {
	args, rec := portsRig(t, nil)
	has(t, "plan en", enMust(t, "", append(args, "--vlan", "20")...), "Only the plan was shown: nothing was changed. To apply it, add --asistido.")
	has(t, "plan es", must(t, "", append(args, "--vlan", "20")...), "Solo se mostró el plan: no se cambió nada. Para aplicarlo agrega --asistido.")
	_, err := en(t, "", append(args, "--shut", "--no-shut")...)
	errHas(t, "shut en", err, "--shut and --no-shut are mutually exclusive")
	_, err = mctl(t, "", append(args, "--shut", "--no-shut")...)
	errHas(t, "shut es", err, "--shut y --no-shut son excluyentes")
	_, err = en(t, "", append(args, "--vlan", "4095")...)
	errHas(t, "vlan en", err, "VLANs range from 1 to 4094")
	_, err = mctl(t, "", append(args, "--vlan", "4095")...)
	errHas(t, "vlan es", err, "las VLAN van de 1 a 4094")
	if len(rec.Lines()) != 0 {
		t.Fatalf("llegó %q", rec.Lines())
	}
	has(t, "asistido en", func() string { o, _ := en(t, "n\n", append(args, "--vlan", "20", "--asistido")...); return o }(), "ASSISTED MODE ACTIVE. Run ", "every step that changes the network asks for confirmation.")
	has(t, "asistido es", func() string { o, _ := mctl(t, "n\n", append(args, "--vlan", "20", "--asistido")...); return o }(), "MODO ASISTIDO ACTIVO. Ejecución ", "cada paso que cambia la red pide confirmación.")
}

func TestIdioma30eTransfer(t *testing.T) {
	startCore(t)
	_, err := en(t, "", "transfer", "serve", "--proto", "tftp", "--listen", "127.0.0.1", "--allow", "no-ip")
	errHas(t, "allow en", err, `--allow "no-ip" is not an IP`)
	_, err = mctl(t, "", "transfer", "serve", "--proto", "tftp", "--listen", "127.0.0.1", "--allow", "no-ip")
	errHas(t, "allow es", err, `--allow "no-ip" no es una IP`)
	_, err = en(t, "", "transfer", "serve", "--proto", "ftp", "--listen", "127.0.0.1", "--pasv-ports", "9-1")
	errHas(t, "pasv en", err, "--pasv-ports expects MIN-MAX, e.g. 50000-50031")
	_, err = mctl(t, "", "transfer", "serve", "--proto", "ftp", "--listen", "127.0.0.1", "--pasv-ports", "9-1")
	errHas(t, "pasv es", err, "--pasv-ports espera MIN-MAX, p. ej. 50000-50031")
	pub := t.TempDir()
	_, err = en(t, "", "transfer", "serve", "--proto", "tftp", "--listen", "127.0.0.1", "--from", pub, "--files", "../x")
	errHas(t, "files en", err, `--files "../x": with --from, use a relative name inside that folder`)
	_, err = mctl(t, "", "transfer", "serve", "--proto", "tftp", "--listen", "127.0.0.1", "--from", pub, "--files", "../x")
	errHas(t, "files es", err, `--files "../x": con --from va un nombre relativo dentro de esa carpeta`)
	_, err = en(t, "", "transfer", "serve", "--proto", "tftp", "--listen", "127.0.0.1", "--from", pub, "--files", "no-esta")
	errHas(t, "files stat en", err, `--files "no-esta": `)
	_, err = en(t, "", "transfer", "put", "tftp://127.0.0.1/x", t.TempDir())
	errHas(t, "put en", err, "LOCAL must be a file, not a folder")
	_, err = mctl(t, "", "transfer", "put", "tftp://127.0.0.1/x", t.TempDir())
	errHas(t, "put es", err, "LOCAL debe ser un archivo, no una carpeta")
	has(t, "hint en", enMust(t, "", "transfer", "hint", "scp", "2222"), "The device uses port 22; the app listens on 2222 and never opens privileged ports.", "Redirect (you run it):", "To remove it when done:", "Broader alternative:")
	has(t, "hint es", must(t, "", "transfer", "hint", "scp", "2222"), "El equipo usa el puerto 22; la app escucha en el 2222 y nunca abre puertos privilegiados.", "Redirección (la ejecutas tú):")
	has(t, "list en", enMust(t, "", "transfer", "list"), "no servers are open")
	has(t, "list es", must(t, "", "transfer", "list"), "no hay servidores abiertos")
	_, err = en(t, "", "transfer", "stop", "no-existe")
	if err == nil {
		t.Log("stop de un servidor inexistente no falla")
	}
}
