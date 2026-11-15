package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
)

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fixture arma un trabajo de una ronda contra sw1 y un paquete con dos playbooks (ios/a, ios/b).
func fixture(t *testing.T) (job, pack string) { return fixtureWith(t, "SuperSecreto123") }

// fixtureWith es fixture con el valor de «password 0 <valor>» en la evidencia (línea 25 del archivo de la ronda).
func fixtureWith(t *testing.T, value string) (job, pack string) {
	t.Helper()
	root := t.TempDir()
	pack = filepath.Join(root, "pack")
	write(t, filepath.Join(pack, "playbooks", "a.yaml"), `id: a
platform: ios
name: A
commands:
  - cmd: show version
  - cmd: show foo
  - cmd: show bar
  - cmd: show perm
  - cmd: show nunca
  - cmd: show dup
    platforms: [ios-xe]
`)
	write(t, filepath.Join(pack, "playbooks", "b.yaml"), `id: b
platform: ios
name: B
params:
  - name: interface
    kind: interface
commands:
  - cmd: show dup
  - cmd: show empty
  - cmd: show interfaces {interface}
  - cmd: show running-config
  - cmd: show otra
    platforms: [ios-xe]
`)
	job = filepath.Join(root, "validacion_20261114-100000")
	ended := time.Date(2026, 11, 14, 10, 1, 2, 0, time.UTC)
	m := patrol.Manifest{
		EndedAt:   ended,
		Playbooks: []patrol.PlaybookRef{{ID: "ios/a"}, {ID: "ios/b"}},
		Params:    map[string]string{"interface": "Gi0/1"},
		Devices: []patrol.DeviceResult{{Target: patrol.Target{Address: "10.0.0.1"}, Round: 1, Hostname: "sw1", Platform: "ios",
			State: "completed", Commands: 9, Invalid: 1, Skipped: []string{"show dup", "show otra"}}},
		Masked: true, MaskCounts: map[string]int{"secret": 1},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(job, "manifest.json"), string(b))
	write(t, filepath.Join(job, "sw1_10.0.0.1", "r001_20261114-100000.txt"), `===== 2026-11-14T10:00:00Z · show version =====
Cisco IOS Software
===== 2026-11-14T10:00:01Z · show foo · comando inválido =====
show foo
     ^
% Invalid input detected at '^' marker.
===== 2026-11-14T10:00:02Z · show bar =====
Incorrect usage. Use the '?' or <TAB> key to list commands.
===== 2026-11-14T10:00:02Z · show perm =====
% Permission denied for the role, password 0 `+value+`
===== 2026-11-14T10:00:02Z · show dup =====

===== 2026-11-14T10:00:03Z · show empty =====

===== 2026-11-14T10:00:04Z · show interfaces Gi0/1 =====
GigabitEthernet0/1 is up
===== 2026-11-14T10:01:00Z · show running-config =====
username admin secret <MASKED:secret>
snmp-server community public RO
snmp-server community <MASKED:snmp-community> RO
tacacs-server key 7 0822455D0A16
 ip ospf message-digest-key 1 md5 7 1234ABCD
snmp-server user u1 g1 auth md5 0xabcdef0123 priv 0x99887766
username x password <MASKED:secret> secret suelto123
username y password 0 `+value+`
ntp authentication-key 1 md5 `+value+` 7
 pre-shared-key local `+value+`
 pre-shared-key address 0.0.0.0 0.0.0.0 key `+value+`
 security wpa psk set-key ascii 0 `+value+`
Community name: `+value+`
enable password level 15 7 `+value+`
password "dos `+value+`"
snmp-server user u2 g2 auth sha `+value+` priv aes-128 0xabc
crypto isakmp key `+value+` address 1.1.1.1 password x
{"k":"-----BEGIN RSA PRIVATE KEY-----\n`+value+`\n"}
===== 2026-11-14T10:01:01Z · show extra =====
%PARSER-5-CFGLOG_LOGGEDCMD: User:x logged command:crypto isakmp key `+value+` address 1.1.1.1
`)
	return job, pack
}

func TestReporte(t *testing.T) {
	job, pack := fixture(t)
	var out strings.Builder
	if err := report(&out, job, []string{pack}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	// sección de cada playbook: desde su título hasta el siguiente
	section := func(id string) string {
		i := strings.Index(got, "## "+id)
		if i < 0 {
			t.Fatalf("falta la sección %s:\n%s", id, got)
		}
		rest := got[i+3:]
		if j := strings.Index(rest, "\n## "); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	a, b := section("ios/a"), section("ios/b")
	for _, want := range []string{"`show foo` — rechazado: % Invalid input", "`show bar` — rechazado: Incorrect usage",
		"`show perm` — rechazado: % Permission denied", "`show nunca` — no corrió"} {
		if !strings.Contains(a, want) {
			t.Errorf("ios/a sin %q:\n%s", want, a)
		}
	}
	for _, want := range []string{"`show empty` — salida vacía", "`show interfaces Gi0/1` — lento: 56 s", "`show dup` — salida vacía"} {
		if !strings.Contains(b, want) {
			t.Errorf("ios/b sin %q:\n%s", want, b)
		}
	}
	if strings.Contains(a, "show dup") {
		t.Errorf("show dup (solo ios-xe en ios/a) se atribuyó a ios/a:\n%s", a)
	}
	for _, no := range []string{"`show version`", "`show otra`", "`show running-config` — lento"} {
		if strings.Contains(got, no) {
			t.Errorf("no debería aparecer %q:\n%s", no, got)
		}
	}
	if !strings.Contains(section("Fuera de playbook"), "`show extra`") {
		t.Errorf("show extra no sale fuera de playbook:\n%s", got)
	}
	sec := section("Posibles secretos")
	// Cada candidato sale como comando · palabra clave · marcador · archivo:línea, sin texto de la línea.
	f := "sw1_10.0.0.1/r001_20261114-100000.txt:"
	for _, want := range []string{"community ⟦secreto? ", f + "19", "key ⟦secreto? ", f + "21",
		"message-digest-key ⟦secreto? ", f + "22", "auth ⟦secreto? ", f + "23",
		"secret ⟦secreto? ", f + "24", "`show running-config` · password ⟦secreto? 17 car.⟧ · " + f + "25",
		f + "26", f + "27", f + "28", f + "29", f + "30", f + "31", f + "32", f + "33", f + "34", f + "35"} {
		if !strings.Contains(sec, want) {
			t.Errorf("secreto sin detectar %q:\n%s", want, sec)
		}
	}
	if !strings.Contains(got, "`show extra` — aviso % del equipo (revisar)") {
		t.Errorf("la línea %% desconocida no salió como rechazo sin texto:\n%s", got)
	}
	if strings.Contains(sec, f+"20") { // community <MASKED:...>: no es candidato
		t.Errorf("una línea enmascarada salió como secreto:\n%s", sec)
	}
	if !strings.Contains(got, "sw1") || !strings.Contains(got, "completed") {
		t.Errorf("falta el estado del equipo:\n%s", got)
	}
}

// Un trabajo sin manifest (aún corriendo o cancelado) es error claro, no un reporte vacío que parezca limpio.
func TestSinManifest(t *testing.T) {
	job, pack := fixture(t)
	if err := os.Remove(filepath.Join(job, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := report(&out, job, []string{pack}, 30*time.Second); err == nil {
		t.Fatal("sin manifest debería fallar")
	}
}

// Un playbook que no está en -pack no cuenta como limpio: sale con su problema.
func TestPlaybookFaltanteNoCuentaComoLimpio(t *testing.T) {
	job, pack := fixture(t)
	if err := os.Remove(filepath.Join(pack, "playbooks", "b.yaml")); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := report(&out, job, []string{pack}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "## ios/b") || !strings.Contains(got, "no está en los paquetes") || !strings.Contains(got, "0 de 2 playbooks") {
		t.Fatalf("ios/b ausente salió limpio:\n%s", got)
	}
}

// Un equipo que falló al conectar no deja salida: el reporte igual muestra su estado y motivo.
func TestEquipoSinSalidaMuestraSuEstado(t *testing.T) {
	job, pack := fixture(t)
	if err := os.RemoveAll(filepath.Join(job, "sw1_10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	m := patrol.Manifest{Playbooks: []patrol.PlaybookRef{{ID: "ios/a"}}, Devices: []patrol.DeviceResult{{Target: patrol.Target{Address: "10.0.0.1"},
		Round: 1, State: "failed", Detail: "auth: credencial rechazada"}}}
	b, _ := json.Marshal(m)
	write(t, filepath.Join(job, "manifest.json"), string(b))
	var out strings.Builder
	if err := report(&out, job, []string{pack}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "failed") || !strings.Contains(got, "credencial rechazada") {
		t.Fatalf("falta el estado del equipo:\n%s", got)
	}
}

// El reporte nunca muestra un secreto: con dos valores distintos del mismo largo la salida es idéntica, así que
// ninguna parte del valor llega a ella (solo su largo).
func TestElReporteNoMuestraSecretos(t *testing.T) {
	run := func(value string) string {
		job, pack := fixtureWith(t, value)
		var out strings.Builder
		if err := report(&out, job, []string{pack}, 30*time.Second); err != nil {
			t.Fatal(err)
		}
		// la carpeta temporal cambia entre corridas: solo cuenta lo que sigue al título
		return strings.SplitN(out.String(), "\n", 2)[1]
	}
	a, b := run("SuperSecreto123"), run("QxQxQxQxQxQxQxQ")
	if a != b {
		t.Fatalf("la salida depende del valor del secreto:\n%s\n---\n%s", a, b)
	}
	for _, leak := range []string{"SuperSecreto123", "suelto123", "0822455D0A16", "1234ABCD", "0xabcdef0123", "public", "0x99887766", "logged command"} {
		if strings.Contains(a, leak) {
			t.Errorf("el reporte muestra %q:\n%s", leak, a)
		}
	}
}

// El detalle del manifest sale tal cual salvo que parezca traer un secreto.
func TestDetalleConSecretoSeOmite(t *testing.T) {
	job, pack := fixture(t)
	m := patrol.Manifest{Playbooks: []patrol.PlaybookRef{{ID: "ios/a"}}, Devices: []patrol.DeviceResult{{Target: patrol.Target{Address: "10.0.0.1"},
		Hostname: "sw1", Round: 1, State: "failed", Detail: "prompt: username y password 0 SuperSecreto123"}}}
	b, _ := json.Marshal(m)
	write(t, filepath.Join(job, "manifest.json"), string(b))
	var out strings.Builder
	if err := report(&out, job, []string{pack}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); strings.Contains(got, "SuperSecreto123") || !strings.Contains(got, "detalle omitido") {
		t.Fatalf("detalle con secreto:\n%s", got)
	}
}

// Falsos positivos del laboratorio del 2026-11-14 (9120 EWC y 3560CX): contadores y estados «etiqueta : valor», palabras
// de configuración que no son secretos y líneas ya enmascaradas tras la palabra clave. Los secretos reales siguen.
func TestSecretAtSinFalsosPositivosDelLaboratorio(t *testing.T) {
	for _, ln := range []string{
		"AAA override passphrase : No", "Wrong PSK : 132", "EasyPSK PSK mismatch error : 0", "PSK mode failure : 0",
		"PSK Provisioning : DISABLED", "PSK : Enabled", "FT PSK : Disabled", "PSK Key-Index key number : 1",
		"password encryption aes", "wireless mesh security psk provisioning inuse 1", "Mesh PSK Config",
		"security wpa psk set-key ascii 8 <MASKED:wifi-psk>", "    0 Unknown community name",
		"    0 Illegal operation for community name supplied",
	} {
		if kw, n, ok := secretAt(ln); ok {
			t.Errorf("falso positivo %q: %s %d", ln, kw, n)
		}
	}
	for _, ln := range []string{
		"username y password 0 SuperSecreto123", "Community name: Xyz123abc", "PSK : Xyz123abc456",
		" security wpa psk set-key ascii 0 Xyz123abc456", "ntp authentication-key 1 md5 0822455D0A16 7",
		"snmp-server community public RO", "username x password <MASKED:secret> secret suelto123",
	} {
		if _, _, ok := secretAt(ln); !ok {
			t.Errorf("secreto sin detectar: %q", ln)
		}
	}
}

// «Función no activa» (% LLDP is not enabled, % BGP not active...) no es un error del paquete: sale en su sección y
// el playbook no cuenta como con problemas. «% Error: Unsupported command» sí es rechazo, y un % informativo
// (% Key pair was generated at...) no se presenta como rechazo.
func TestFuncionNoActivaVaAparte(t *testing.T) {
	job, pack := fixture(t)
	write(t, filepath.Join(pack, "playbooks", "c.yaml"), `id: c
platform: ios
name: C
commands:
  - cmd: show lldp
  - cmd: show ip bgp summary
  - cmd: show spanning-tree mst
  - cmd: show snmp pending
  - cmd: show crypto key mypubkey rsa
  - cmd: show wireless mobility summary
`)
	m := patrol.Manifest{EndedAt: time.Date(2026, 11, 14, 10, 0, 10, 0, time.UTC), Playbooks: []patrol.PlaybookRef{{ID: "ios/c"}},
		Devices: []patrol.DeviceResult{{Target: patrol.Target{Address: "10.0.0.1"}, Round: 1, Hostname: "sw1", Platform: "ios", State: "completed"}}}
	b, _ := json.Marshal(m)
	write(t, filepath.Join(job, "manifest.json"), string(b))
	write(t, filepath.Join(job, "sw1_10.0.0.1", "r001_20261114-100000.txt"), `===== 2026-11-14T10:00:00Z · show lldp =====
% LLDP is not enabled
===== 2026-11-14T10:00:01Z · show ip bgp summary =====
% BGP not active
===== 2026-11-14T10:00:02Z · show spanning-tree mst =====
% Switch is not in mst mode
===== 2026-11-14T10:00:03Z · show snmp pending =====
%SNMP manager not enabled
===== 2026-11-14T10:00:04Z · show crypto key mypubkey rsa =====
% Key pair was generated at: 05:13:27 MX Apr 9 2001
Key name: TP-self-signed
===== 2026-11-14T10:00:05Z · show wireless mobility summary =====
% Error: Unsupported command 'show_wireless_mobility_summary_req'
`)
	var out strings.Builder
	if err := report(&out, job, []string{pack}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	inactive := got[strings.Index(got, "## Funciones no activas"):]
	for _, want := range []string{"`show lldp` — not enabled", "`show ip bgp summary` — not active", "`show spanning-tree mst` — not in", "`show snmp pending` — not enabled"} {
		if !strings.Contains(inactive, want) {
			t.Errorf("falta %q en funciones no activas:\n%s", want, got)
		}
	}
	c := got[strings.Index(got, "## ios/c"):]
	c = c[:strings.Index(c, "playbooks sin problemas")]
	for _, no := range []string{"show lldp", "show ip bgp", "show spanning-tree", "show snmp pending"} {
		if strings.Contains(c, no) {
			t.Errorf("%s salió como problema del playbook:\n%s", no, c)
		}
	}
	for _, want := range []string{"`show wireless mobility summary` — rechazado: Unsupported command", "`show crypto key mypubkey rsa` — aviso % del equipo (revisar)"} {
		if !strings.Contains(c, want) {
			t.Errorf("falta %q:\n%s", want, c)
		}
	}
}

// La misma función apagada vista por dos playbooks sale una vez.
func TestFuncionNoActivaSinRepetir(t *testing.T) {
	job, pack := fixture(t)
	for _, f := range []string{"c.yaml", "d.yaml"} {
		write(t, filepath.Join(pack, "playbooks", f), "id: "+f[:1]+"\nplatform: ios\nname: X\ncommands:\n  - cmd: show lldp\n")
	}
	m := patrol.Manifest{Playbooks: []patrol.PlaybookRef{{ID: "ios/c"}, {ID: "ios/d"}},
		Devices: []patrol.DeviceResult{{Target: patrol.Target{Address: "10.0.0.1"}, Round: 1, Hostname: "sw1", Platform: "ios", State: "completed"}}}
	b, _ := json.Marshal(m)
	write(t, filepath.Join(job, "manifest.json"), string(b))
	write(t, filepath.Join(job, "sw1_10.0.0.1", "r001_20261114-100000.txt"), "===== 2026-11-14T10:00:00Z · show lldp =====\n% LLDP is not enabled\n===== 2026-11-14T10:00:01Z · show lldp =====\n% LLDP is not enabled\n")
	var out strings.Builder
	if err := report(&out, job, []string{pack}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "`show lldp` — not enabled"); n != 1 {
		t.Fatalf("show lldp sale %d veces:\n%s", n, out.String())
	}
}
