package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

const vtpTransparent = "VTP Domain Name                 : \nVTP Operating Mode              : Transparent\n"

func snippetRig(t *testing.T, errs map[string]string, mods ...func(*simulator.Config)) portsEnv {
	t.Helper()
	all := append([]func(*simulator.Config){func(c *simulator.Config) {
		c.Vlans = []int{1, 10}
		c.Commands = map[string]string{"show vtp status": vtpTransparent, "show interfaces trunk": "Port        Mode             Encapsulation  Status        Native vlan\nGi1/0/48    on               802.1q         trunking      1\n\nPort        Vlans allowed on trunk\nGi1/0/48    10,20\n\nPort        Vlans allowed and active in management domain\nGi1/0/48    10\n", "show ip interface brief": "Interface              IP-Address      OK? Method Status                Protocol\nVlan1                  unassigned      YES unset  up                    down\n"}
		c.Interfaces["GigabitEthernet1/0/48"] = []string{"switchport mode trunk", "switchport trunk allowed vlan 10,20"}
	}}, mods...)
	return portsRigFull(t, errs, all...)
}

func (e portsEnv) snip(kind string, rest ...string) []string {
	return append([]string{"snippet", kind, e.addr}, append(rest, "--cred", e.cred, "--accept", e.fp)...)
}

func TestSnippetVlanWithoutAsistidoOnlyPrintsPlan(t *testing.T) {
	e := snippetRig(t, nil)
	out := must(t, "", e.snip("vlan", "30", "--name", "Cuarentena")...)
	for _, w := range []string{"REVERSA", "vlan 30", "name Cuarentena", "no vlan 30", "no se cambió nada"} {
		if !strings.Contains(out, w) {
			t.Errorf("falta %q:\n%s", w, out)
		}
	}
	if len(e.rec.Lines()) != 0 {
		t.Fatalf("sin --asistido llegó configuración: %q", e.rec.Lines())
	}
}

func TestSnippetVlanAsistidoAsksAndApplies(t *testing.T) {
	e := snippetRig(t, nil)
	for _, in := range []string{"", "n\n"} {
		if _, err := mctl(t, in, append(e.snip("vlan", "30", "--name", "Cuarentena"), "--asistido")...); err == nil || len(e.rec.Lines()) != 0 {
			t.Fatalf("stdin %q: err=%v lines=%q", in, err, e.rec.Lines())
		}
	}
	out := must(t, "s\ns\n", append(e.snip("vlan", "30", "--name", "Cuarentena"), "--asistido")...)
	if !strings.Contains(out, "MODO ASISTIDO ACTIVO") || !strings.Contains(out, "Listo") {
		t.Fatalf("salida:\n%s", out)
	}
	if got := strings.Join(e.rec.Lines(), "|"); got != "vlan 30|name Cuarentena|end" {
		t.Fatalf("el equipo recibió %q", got)
	}
}

func TestSnippetVlanRemoveFlag(t *testing.T) {
	e := snippetRig(t, nil)
	// Sin --asistido solo muestra el plan: borra y la reversa recrea la VLAN con su nombre por omisión.
	out := must(t, "", e.snip("vlan", "10", "--remove", "--accept-trunk")...)
	for _, w := range []string{"no vlan 10", "REVERSA", "no se cambió nada"} {
		if !strings.Contains(out, w) {
			t.Errorf("falta %q:\n%s", w, out)
		}
	}
	if len(e.rec.Lines()) != 0 {
		t.Fatalf("sin --asistido llegó configuración: %q", e.rec.Lines())
	}
	if _, err := mctl(t, "", e.snip("vlan", "10", "--remove", "--name", "x")...); err == nil {
		t.Error("--remove con --name debe fallar")
	}
	if _, err := mctl(t, "", e.snip("vlan", "99", "--remove")...); err == nil {
		t.Error("borrar una VLAN inexistente debe fallar")
	}
	// El trunk de Gi1/0/48 lleva la VLAN 10: sin --accept-trunk no se borra.
	if _, err := mctl(t, "", e.snip("vlan", "10", "--remove")...); err == nil || !strings.Contains(err.Error(), "trunk") {
		t.Errorf("VLAN en un trunk sin --accept-trunk: %v", err)
	}
	must(t, "s\ns\n", append(e.snip("vlan", "10", "--remove", "--accept-trunk"), "--asistido")...)
	if got := strings.Join(e.rec.Lines(), "|"); got != "no vlan 10|end" {
		t.Fatalf("el equipo recibió %q", got)
	}
}

func TestSnippetTrunkOnlyAddOrRemoveFromTheCLI(t *testing.T) {
	e := snippetRig(t, nil)
	const up = "GigabitEthernet1/0/48"
	for _, bad := range [][]string{{up, "set", "30"}, {up, "30"}, {up, "add", "10,20"}, {up, "add", "-1"}, {up, "add", "0"}, {up, "add", "4095"}, {up, "all", "30"}} {
		if out, err := mctl(t, "", e.snip("trunk", bad...)...); err == nil {
			t.Errorf("%v aceptado:\n%s", bad, out)
		}
	}
	out := must(t, "s\ns\n", append(e.snip("trunk", up, "add", "30"), "--asistido")...)
	if !strings.Contains(out, "switchport trunk allowed vlan add 30") || !strings.Contains(out, "switchport trunk allowed vlan remove 30") {
		t.Fatalf("el plan debe mostrar add y su reversa remove:\n%s", out)
	}
	if got := strings.Join(e.rec.Lines(), "|"); got != "interface "+up+"|switchport trunk allowed vlan add 30|end" {
		t.Fatalf("el equipo recibió %q", got)
	}
	// Un puerto de acceso no es trunk: el núcleo lo rechaza y no se envía nada.
	n := len(e.rec.Lines())
	if _, err := mctl(t, "s\n", append(e.snip("trunk", gi1, "add", "30"), "--asistido")...); err == nil || len(e.rec.Lines()) != n {
		t.Fatalf("puerto de acceso: %v", err)
	}
}

func TestSnippetSviAsistidoAndRollbackOnFailure(t *testing.T) {
	e := snippetRig(t, map[string]string{"no shutdown": "% Invalid input detected at '^' marker."})
	out, err := mctl(t, "s\ns\ns\n", append(e.snip("svi", "99", "10.9.9.1", "255.255.255.0", "--desc", "Servidores"), "--asistido")...)
	if err == nil || !strings.Contains(out, "SE DETUVO") || !strings.Contains(out, "[rolled-back]") {
		t.Fatalf("err=%v\n%s", err, out)
	}
	if !strings.Contains(strings.Join(e.rec.Lines(), "|"), "no interface Vlan99") {
		t.Fatalf("la reversa no borró la SVI creada: %q", e.rec.Lines())
	}
	if _, err := mctl(t, "", e.snip("svi", "99", "10.9.9.1", "24")...); err == nil {
		t.Error("máscara en prefijo aceptada")
	}
}

// ---- cred rotate ----

const (
	techOld = "Viejo-Secreto.1"
	techNew = "Nuev0-Secreto.2026"
)

func rotateRig(t *testing.T, mods ...func(*simulator.Config)) (portsEnv, string) {
	t.Helper()
	all := append([]func(*simulator.Config){func(c *simulator.Config) { c.Users = map[string]string{"tech": techOld} }}, mods...)
	e := portsRigFull(t, nil, all...)
	tech := strings.TrimSpace(must(t, techOld+"\nen-lab\n", "cred", "add", "--label", "tech", "--user", "tech"))
	return e, tech
}

func TestCredRotateNeverPrintsSecretAndUpdatesVault(t *testing.T) {
	e, tech := rotateRig(t)
	args := []string{"cred", "rotate", e.addr, "--user", "tech", "--cred", e.cred, "--update-cred", tech, "--accept", e.fp}
	out := must(t, techNew+"\n", args...)
	if !strings.Contains(out, "no se cambió nada") || strings.Contains(out, techNew) || len(e.rec.Lines()) != 0 {
		t.Fatalf("sin --asistido solo se muestra el plan (y sin el secreto):\n%s", out)
	}
	if !strings.Contains(out, "<oculto>") {
		t.Fatalf("el plan debe mostrar los secretos ocultos:\n%s", out)
	}
	if !strings.Contains(out, "write memory es obligatorio") || !strings.Contains(out, "(anterior)") {
		t.Fatalf("el plan debe avisar de write memory obligatorio y de la credencial anterior:\n%s", out)
	}
	out = must(t, techNew+"\ns\ns\n", append(args, "--asistido")...) // aplicar y write memory
	for _, s := range []string{techNew, techOld, "$9$"} {
		if strings.Contains(out, s) {
			t.Fatalf("la salida contiene %q:\n%s", s, out)
		}
	}
	if !strings.Contains(out, "Listo") || !strings.Contains(out, "sesión nueva") {
		t.Fatalf("salida:\n%s", out)
	}
	// La bóveda quedó con la credencial nueva: una prueba de login con ella entra al equipo.
	if got := strings.Join(e.rec.Lines(), "|"); !strings.Contains(got, "secret "+techNew) || !strings.Contains(got, "!write memory") {
		t.Fatalf("el equipo recibió %q", got)
	}
	if l := must(t, "", "cred", "list"); !strings.Contains(l, "tech (anterior)") {
		t.Fatalf("la credencial anterior debe conservarse en la bóveda:\n%s", l)
	}
}

// Rechazar write memory no cierra la rotación: se propone la reversa y la bóveda no cambia.
func TestCredRotateRejectedWriteMemoryOffersRollbackAndKeepsVault(t *testing.T) {
	e, tech := rotateRig(t)
	args := []string{"cred", "rotate", e.addr, "--user", "tech", "--cred", e.cred, "--update-cred", tech, "--accept", e.fp, "--asistido"}
	out, err := mctl(t, techNew+"\ns\nn\ns\ns\n", args...) // aplicar, rechazar write memory, revertir, confirmar la reversa
	if err == nil || !strings.Contains(out, "SE DETUVO") || !strings.Contains(out, "[rolled-back]") {
		t.Fatalf("err=%v\n%s", err, out)
	}
	if got := strings.Join(e.rec.Lines(), "|"); strings.Contains(got, "!write memory") || !strings.Contains(got, "secret 9 $9$") {
		t.Fatalf("el equipo recibió %q", got)
	}
	if l := must(t, "", "cred", "list"); strings.Contains(l, "(anterior)") {
		t.Fatalf("la bóveda no debía cambiar:\n%s", l)
	}
	for _, s := range []string{techNew, techOld} {
		if strings.Contains(out, s) {
			t.Fatalf("la salida contiene %q:\n%s", s, out)
		}
	}
}

func TestCredRotateRefusesConnectedUserAndGenerateNeedsVaultCredential(t *testing.T) {
	e, tech := rotateRig(t)
	base := []string{"cred", "rotate", e.addr, "--cred", e.cred, "--accept", e.fp}
	if out, err := mctl(t, techNew+"\n", append(base, "--user", "admin")...); err == nil || len(e.rec.Lines()) != 0 {
		t.Fatalf("rotar al usuario de la sesión: err=%v\n%s", err, out)
	}
	if _, err := mctl(t, "", append(base, "--user", "tech", "--generate")...); err == nil {
		t.Fatal("--generate sin --update-cred")
	}
	if _, err := mctl(t, "corto\n", append(base, "--user", "tech")...); err == nil {
		t.Fatal("secreto corto")
	}
	if out, err := mctl(t, "", "cred", "rotate", e.addr, "--cred", e.cred); err == nil || strings.Contains(out, techNew) {
		t.Fatalf("sin --user: %v", err)
	}
	_ = tech
}

func TestCredRotateLoginFailureOffersRollback(t *testing.T) {
	e, tech := rotateRig(t, func(c *simulator.Config) { c.IgnoreUserChange = true })
	args := []string{"cred", "rotate", e.addr, "--user", "tech", "--cred", e.cred, "--update-cred", tech, "--accept", e.fp, "--asistido"}
	out, err := mctl(t, techNew+"\ns\ns\ns\n", args...)
	if err == nil || !strings.Contains(out, "SE DETUVO") || !strings.Contains(out, "no entró") || !strings.Contains(out, "[rolled-back]") {
		t.Fatalf("err=%v\n%s", err, out)
	}
	for _, s := range []string{techNew, techOld} {
		if strings.Contains(out, s) {
			t.Fatalf("la salida contiene %q:\n%s", s, out)
		}
	}
}

// ---- catálogo de plantillas (fase 28b) ----

func TestSnippetListShowsTheCatalogByTech(t *testing.T) {
	snippetRig(t, nil)
	out := must(t, "", "snippet", "list")
	for _, w := range []string{"l2", "speed-duplex", "storm-control", "port-security", "errdisable-recovery", "interfaces", "ipv4_mask", "(obligatorio)", "shutdown|trap",
		"\ngestion\n", "\nseguridad\n", "ruta-estatica", "loopback", "helper-address", "ntp-server", "logging-host", "snmp-community", "snmpv3-usuario", "banner-motd", "vty-acl", "secret"} {
		if !strings.Contains(out, w) {
			t.Errorf("falta %q:\n%s", w, out)
		}
	}
	last := -1
	for _, tech := range []string{"\nl2\n", "\nl3\n", "\ngestion\n", "\nseguridad\n"} {
		if i := strings.Index(out, tech); i < last {
			t.Errorf("la tecnología %q va fuera del orden del catálogo:\n%s", tech, out)
		} else {
			last = i
		}
	}
	if i, j := strings.Index(out, "\nl2"), strings.Index(out, "\nl3"); i < 0 || j < i {
		t.Errorf("las tecnologías deben ir en orden de catálogo:\n%s", out)
	}
	if none := must(t, "", "snippet", "list", "--platform", "nxos"); strings.Contains(none, "speed-duplex") {
		t.Errorf("filtro por plataforma:\n%s", none)
	}
	var doc struct {
		Templates []struct {
			ID     string `json:"id"`
			Tech   string `json:"tech"`
			Fields []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"fields"`
		} `json:"templates"`
	}
	if err := json.Unmarshal([]byte(must(t, "", "snippet", "list", "--platform", "ios-xe", "--json")), &doc); err != nil || len(doc.Templates) < 18 || doc.Templates[0].Tech != "l2" {
		t.Fatalf("--json: %v %+v", err, doc)
	}
}

func (e portsEnv) run(id string, rest ...string) []string {
	return append([]string{"snippet", "run", e.addr, id}, append(rest, "--cred", e.cred, "--accept", e.fp)...)
}

func TestSnippetRunWithoutAsistidoOnlyPrintsPlanAndNotes(t *testing.T) {
	e := snippetRig(t, nil)
	out := must(t, "", e.run("speed-duplex", "--set", "interfaces="+gi1, "--set", "speed=100", "--set", "duplex=full")...)
	for _, w := range []string{"REVERSA", "speed 100", "duplex full", "no duplex", "no speed", "Avisos", "reinicia el enlace", "no se cambió nada"} {
		if !strings.Contains(out, w) {
			t.Errorf("falta %q:\n%s", w, out)
		}
	}
	if len(e.rec.Lines()) != 0 {
		t.Fatalf("sin --asistido llegó configuración: %q", e.rec.Lines())
	}
}

func TestSnippetRunAsistidoAppliesAndRejectsBadSet(t *testing.T) {
	e := snippetRig(t, nil)
	out := must(t, "s\ns\n", append(e.run("port-security", "--set", "interfaces="+gi1, "--set", "maximum=2"), "--asistido")...)
	if !strings.Contains(out, "MODO ASISTIDO ACTIVO") || !strings.Contains(out, "Listo") {
		t.Fatalf("salida:\n%s", out)
	}
	if got := strings.Join(e.rec.Lines(), "|"); got != "interface "+gi1+"|switchport port-security maximum 2|switchport port-security|end" {
		t.Fatalf("el equipo recibió %q", got)
	}
	n := len(e.rec.Lines())
	for name, args := range map[string][]string{
		"plantilla desconocida": e.run("no-existe", "--set", "a=b"),
		"sin igual":             e.run("port-security", "--set", "interfaces"),
		"repetido":              e.run("port-security", "--set", "interfaces="+gi1, "--set", "interfaces="+gi1),
		"valor inválido":        e.run("port-security", "--set", "interfaces="+gi1, "--set", "maximum=0"),
		"sin plantilla":         {"snippet", "run", e.addr, "--cred", e.cred},
	} {
		if _, err := mctl(t, "", args...); err == nil {
			t.Errorf("%s: aceptado", name)
		}
	}
	if len(e.rec.Lines()) != n {
		t.Fatalf("un error de uso configuró algo: %q", e.rec.Lines())
	}
}

// Fase 28d: un secreto pasado con --set no sale en el plan impreso ni en la salida.
func TestSnippetRunSNMPCommunityPlanNeverPrintsTheCommunity(t *testing.T) {
	const comm = "Zx9-Secreta.Comm"
	e := snippetRig(t, nil, func(c *simulator.Config) { c.Running = "hostname SW1\nsnmp-server community otra RO\n!\nend\n" })
	out := must(t, "", e.run("snmp-community", "--set", "community="+comm)...)
	for _, w := range []string{"REVERSA", "snmp-server community", "no snmp-server community", "no se cambió nada"} {
		if !strings.Contains(out, w) {
			t.Errorf("falta %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, comm) || len(e.rec.Lines()) != 0 {
		t.Fatalf("salida con la community o con configuración enviada (%q):\n%s", e.rec.Lines(), out)
	}
}
