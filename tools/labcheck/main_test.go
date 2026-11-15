package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/analyze"
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
		// Cat9000v (IOS-XE 17.15): nombre de proceso con dirección (show memory) y encabezado de show mka keychains
		"      123       4  Ion Password           :7F3A2B1C0D9E+1A2B3C4", "MKA PSK Keychain(s) Summary...",
	} {
		if kw, n, ok := secretAt(ln); ok {
			t.Errorf("falso positivo %q: %s %d", ln, kw, n)
		}
	}
	for _, ln := range []string{
		"username y password 0 SuperSecreto123", "Community name: Xyz123abc", "PSK : Xyz123abc456",
		" security wpa psk set-key ascii 0 Xyz123abc456", "ntp authentication-key 1 md5 0822455D0A16 7",
		"snmp-server community public RO", "username x password <MASKED:secret> secret suelto123",
		// de la revisión: las reglas de descarte no pueden esconder un secreto antes de los dos puntos ni junto a un <MASKED:
		"username admin password 0 abc:123", "key-string 0 MyKey:2024", "Community name: 123456",
		"snmp-server community S3cret RO <MASKED:x>", "username bob password 0 hunter2 <MASKED:x>", "community name S3cret",
	} {
		if _, _, ok := secretAt(ln); !ok {
			t.Errorf("secreto sin detectar: %q", ln)
		}
	}
}

// Formas sin tipo de cifrado: «key X» y «token X» al inicio de línea (submodos de radius/tacacs, Umbrella) y «authentication
// text X» (HSRP/VRRP). Los usos que no son secretos (key chain, key config-key, crypto key generate, key 1) no cuentan.
func TestSecretAtFormasSinTipo(t *testing.T) {
	for _, ln := range []string{" key RADLAB1", "key RADLAB2", " token UMBTOK1", "token UMBTOK2", " authentication text FHRPLAB1", "standby 1 authentication text FHRPLAB2", "  key 12ab"} {
		if _, _, ok := secretAt(ln); !ok {
			t.Errorf("secreto sin detectar: %q", ln)
		}
	}
	for _, ln := range []string{
		"key chain KC1", " key chain KC1", "key config-key password-encrypt", "crypto key generate rsa", "crypto key zeroize rsa", " key 1", "key 10",
		"Press any key to continue", " key <MASKED:radius-key>", " key *****", " token <MASKED:token>", "Token Ring is not supported", " authentication text <MASKED:fhrp-key>",
		"key exchange failed", "key-string 7 <MASKED:key-string>", "authentication md5 key-chain KC1",
	} {
		if kw, n, ok := secretAt(ln); ok {
			t.Errorf("falso positivo %q: %s %d", ln, kw, n)
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
  - cmd: show macsec summary
  - cmd: show device-tracking counters
  - cmd: show platform software process slot switch active r0 monitor
  - cmd: show rara
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
===== 2026-11-14T10:00:04Z · show macsec summary =====
%No Secure Channels
===== 2026-11-14T10:00:04Z · show device-tracking counters =====
% no ipv6 snooping policy attached on Box
===== 2026-11-14T10:00:04Z · show platform software process slot switch active r0 monitor =====
%Cpu(s): 33.9 us, 26.8 sy,  0.0 ni, 39.3 id
===== 2026-11-14T10:00:04Z · show rara =====
%Algo raro del equipo
===== 2026-11-14T10:00:05Z · show wireless mobility summary =====
% Error: Unsupported command 'show_wireless_mobility_summary_req'
`)
	var out strings.Builder
	if err := report(&out, job, []string{pack}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	inactive := got[strings.Index(got, "## Funciones no activas"):]
	for _, want := range []string{"`show lldp` — not enabled", "`show ip bgp summary` — not active", "`show spanning-tree mst` — not in", "`show snmp pending` — not enabled",
		"`show macsec summary` — not configured", "`show device-tracking counters` — not configured"} {
		if !strings.Contains(inactive, want) {
			t.Errorf("falta %q en funciones no activas:\n%s", want, got)
		}
	}
	c := got[strings.Index(got, "## ios/c"):]
	c = c[:strings.Index(c, "playbooks sin problemas")]
	// %Cpu(s) (top) y «% Key pair was generated at» son salida normal: ni problema ni aviso.
	for _, no := range []string{"show lldp", "show ip bgp", "show spanning-tree", "show snmp pending", "show macsec", "show device-tracking",
		"show platform software process", "show crypto key"} {
		if strings.Contains(c, no) {
			t.Errorf("%s salió como problema del playbook:\n%s", no, c)
		}
	}
	for _, want := range []string{"`show wireless mobility summary` — rechazado: Unsupported command", "`show rara` — aviso % del equipo (revisar)"} {
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

// «Función no activa» no tapa un rechazo en las mismas líneas ni lo que el driver marcó (inválido, incompleto).
func TestFuncionNoActivaNoTapaRechazos(t *testing.T) {
	s := analyze.Section{Command: "show x", Text: "% Invalid input detected; feature not enabled\n"}
	if _, ok := inactiveOnly(s); ok {
		t.Error("un rechazo con «not enabled» salió como función no activa")
	}
	s = analyze.Section{Command: "show x", Text: "% LLDP is not enabled\n", Invalid: true}
	if _, ok := inactiveOnly(s); ok {
		t.Error("lo marcado inválido por el driver salió como función no activa")
	}
	s = analyze.Section{Command: "show x", Text: "% LLDP is not enabled\n", Incomplete: true}
	if _, ok := inactiveOnly(s); ok {
		t.Error("una salida incompleta salió como función no activa")
	}
	if p, ok := inactiveOnly(analyze.Section{Command: "show lldp", Text: "% LLDP is not enabled\n"}); !ok || p != "not enabled" {
		t.Errorf("función no activa = %q %v", p, ok)
	}
}

// Evidencia de una versión anterior del paquete: un comando que ya no está en su playbook (show viejo) pero sí en uno
// posterior no puede arrastrar la alineación hasta allá y dejar como «no corrió» todo lo intermedio.
func TestAlineacionConEvidenciaDeOtraVersion(t *testing.T) {
	job, pack := fixture(t)
	write(t, filepath.Join(pack, "playbooks", "c.yaml"), "id: c\nplatform: ios\nname: C\ncommands:\n  - cmd: show uno\n  - cmd: show dos\n")
	write(t, filepath.Join(pack, "playbooks", "d.yaml"), "id: d\nplatform: ios\nname: D\ncommands:\n  - cmd: show tres\n  - cmd: show cuatro\n  - cmd: show viejo\n")
	m := patrol.Manifest{Playbooks: []patrol.PlaybookRef{{ID: "ios/c"}, {ID: "ios/d"}},
		Devices: []patrol.DeviceResult{{Target: patrol.Target{Address: "10.0.0.1"}, Round: 1, Hostname: "sw1", Platform: "ios", State: "completed"}}}
	b, _ := json.Marshal(m)
	write(t, filepath.Join(job, "manifest.json"), string(b))
	// en la versión vieja, c traía show viejo entre uno y dos
	write(t, filepath.Join(job, "sw1_10.0.0.1", "r001_20261114-100000.txt"), "===== 2026-11-14T10:00:00Z · show uno =====\na\n"+
		"===== 2026-11-14T10:00:00Z · show viejo =====\nb\n===== 2026-11-14T10:00:00Z · show dos =====\nc\n"+
		"===== 2026-11-14T10:00:00Z · show tres =====\nd\n===== 2026-11-14T10:00:00Z · show cuatro =====\ne\n===== 2026-11-14T10:00:00Z · show viejo =====\nf\n")
	var out strings.Builder
	if err := report(&out, job, []string{pack}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); strings.Contains(got, "no corrió") || !strings.Contains(got, "2 de 2 playbooks sin problemas") {
		t.Fatalf("alineación rota:\n%s", got)
	}
}

// «% No such interface» (un dato que no existe en el equipo) es un rechazo, no una función apagada; MACsec y
// device-tracking sin configurar sí lo son.
func TestNoSuchEsRechazo(t *testing.T) {
	for _, ln := range []string{"% No such interface", "% No such VRF", "% No matching route", "% No hay tal cosa en el equipo"} {
		if p, ok := inactiveOnly(analyze.Section{Command: "show x", Text: ln + "\n"}); ok {
			t.Errorf("%q salió como función no activa (%s)", ln, p)
		}
	}
	if got := problems(analyze.Section{Command: "show x", Text: "% No such interface\n"}, time.Time{}, time.Hour); len(got) == 0 || got[0] != "rechazado: % No such" {
		t.Errorf("problems = %v", got)
	}
	for _, ln := range []string{"%No Secure Channels", "% no ipv6 snooping policy attached on Box"} {
		if p, ok := inactiveOnly(analyze.Section{Command: "show x", Text: ln + "\n"}); !ok || p != "not configured" {
			t.Errorf("%q = %q %v", ln, p, ok)
		}
	}
}

// Lo que viene de una línea citada entre comillas (show tech del ASA: «*** Output from config line N, "…"») nunca se
// descarta: ahí los descartes de la salida normal (etiqueta : valor, palabras de configuración, <MASKED: cercano) pueden
// esconder una clave real.
func TestLineaCitadaNuncaSeDescarta(t *testing.T) {
	for _, ln := range []string{
		`*** Output from config line 9, "enable password cisco"`,
		`*** Output from config line 4, "password encryption Sup3rS3cret"`,
		`*** Output from config line 5, "snmp-server community name"`,
		`WARNING: "psk provisioning K3yPr0v" ignored`,
	} {
		if _, _, ok := secretAt(ln); !ok {
			t.Errorf("descartó una línea citada: %q", ln)
		}
	}
}

// Falsos positivos del ASAv de CML (2026-11-14): el ASA ya oculta con asteriscos, el contador de llaves de
// show crypto accelerator statistics y la prosa de show password-policy. Lo citado entre comillas sí se sigue marcando.
func TestFalsosPositivosDelASAv(t *testing.T) {
	for _, ln := range []string{
		"enable password ***** pbkdf2", "username cisco password ***** encrypted privilege 15",
		"Secret keys derived: 0", "Minimum allowed password length is 8", "Password must contain:",
	} {
		if kw, n, ok := secretAt(ln); ok {
			t.Errorf("falso positivo %q: %s %d", ln, kw, n)
		}
	}
	if _, _, ok := secretAt(`*** Output from config line 9, "password length Cl4ve"`); !ok {
		t.Error("lo citado se descartó")
	}
}

// dosPlaybooks arma un trabajo con c y d, que piden ambos show comun; el texto de la evidencia lo pone cada prueba.
func dosPlaybooks(t *testing.T, evidence string) string {
	t.Helper()
	job, pack := fixture(t)
	write(t, filepath.Join(pack, "playbooks", "c.yaml"), "id: c\nplatform: ios\nname: C\ncommands:\n  - cmd: show uno\n  - cmd: show comun\n")
	write(t, filepath.Join(pack, "playbooks", "d.yaml"), "id: d\nplatform: ios\nname: D\ncommands:\n  - cmd: show comun\n  - cmd: show dos\n")
	m := patrol.Manifest{Playbooks: []patrol.PlaybookRef{{ID: "ios/c"}, {ID: "ios/d"}},
		Devices: []patrol.DeviceResult{{Target: patrol.Target{Address: "10.0.0.1"}, Round: 1, Hostname: "sw1", Platform: "ios", State: "completed"}}}
	b, _ := json.Marshal(m)
	write(t, filepath.Join(job, "manifest.json"), string(b))
	write(t, filepath.Join(job, "sw1_10.0.0.1", "r001_20261114-100000.txt"), evidence)
	t.Setenv("LABCHECK_PACK", pack)
	return job
}

func reportOf(t *testing.T, job string) string {
	t.Helper()
	var out strings.Builder
	if err := report(&out, job, []string{filepath.Join(os.Getenv("LABCHECK_PACK"))}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

const h = "===== 2026-11-14T10:00:00Z · "

// Con la deduplicación, show comun sale una vez en la evidencia: no es «no corrió» para el segundo playbook, y si el
// equipo lo rechaza, falla en los dos.
func TestComandoCompartidoSeAtribuyeATodos(t *testing.T) {
	ok := reportOf(t, dosPlaybooks(t, h+"show uno =====\na\n"+h+"show comun =====\nb\n"+h+"show dos =====\nc\n"))
	if strings.Contains(ok, "no corrió") || !strings.Contains(ok, "2 de 2 playbooks sin problemas") {
		t.Fatalf("falsos:\n%s", ok)
	}
	bad := reportOf(t, dosPlaybooks(t, h+"show uno =====\na\n"+h+"show comun · comando inválido =====\n% Invalid input detected\n"+h+"show dos =====\nc\n"))
	for _, id := range []string{"## ios/c", "## ios/d"} {
		i := strings.Index(bad, id)
		if i < 0 || !strings.Contains(bad[i:], "`show comun` — rechazado") {
			t.Fatalf("%s sin el rechazo:\n%s", id, bad)
		}
	}
	if strings.Contains(bad, "no corrió") {
		t.Fatalf("falso no corrió:\n%s", bad)
	}
	// no emparejado en la evidencia: sale «no corrió» en los dos
	miss := reportOf(t, dosPlaybooks(t, h+"show uno =====\na\n"+h+"show dos =====\nc\n"))
	if strings.Count(miss, "`show comun` — no corrió") != 2 {
		t.Fatalf("debía faltar en los dos:\n%s", miss)
	}
}

// Evidencia de antes de la deduplicación (show comun dos veces): se alinea como siempre.
func TestEvidenciaViejaConDuplicadosSigueIgual(t *testing.T) {
	got := reportOf(t, dosPlaybooks(t, h+"show uno =====\na\n"+h+"show comun =====\nb\n"+h+"show comun =====\nb\n"+h+"show dos =====\nc\n"))
	if strings.Contains(got, "no corrió") || strings.Contains(got, "Fuera de playbook") || !strings.Contains(got, "2 de 2 playbooks sin problemas") {
		t.Fatalf("evidencia vieja rota:\n%s", got)
	}
}

func TestAvisoSinEnmascarar(t *testing.T) {
	const aviso = "esta evidencia se recogió sin enmascarar: puede traer secretos"
	job, pack := fixture(t) // Masked: true
	var out strings.Builder
	if err := report(&out, job, []string{pack}, 30*time.Second); err != nil || strings.Contains(out.String(), aviso) {
		t.Fatalf("enmascarado no avisa: %v\n%s", err, out.String())
	}
	raw, _ := os.ReadFile(filepath.Join(job, "manifest.json"))
	write(t, filepath.Join(job, "manifest.json"), strings.Replace(string(raw), `"masked":true`, `"masked":false`, 1))
	out.Reset()
	if err := report(&out, job, []string{pack}, 30*time.Second); err != nil || !strings.Contains(out.String(), aviso) {
		t.Fatalf("sin enmascarar avisa: %v\n%s", err, out.String())
	}
}

func TestSecretAtVeFormasNegadas(t *testing.T) {
	for _, ln := range []string{
		"no snmp-server community Cl4veX RO",
		"  no username U secret 0 Cl4veX",
		"no ntp authentication-key 1 md5 Cl4veX",
		"no tacacs-server key Cl4veX",
		"  no radius-server host 1.1.1.1 key Cl4veX",
		"no crypto isakmp key Cl4veX address 1.1.1.1",
		"tacacs-server key Cl4veX",
	} {
		if _, _, ok := secretAt(ln); !ok {
			t.Errorf("secretAt no ve %q", ln)
		}
	}
	// El número de tipo no es el valor: ya enmascaradas no avisan.
	for _, ln := range []string{
		"tacacs-server host 1.1.1.1 key 7 <MASKED:tacacs-key>",
		"crypto isakmp key 6 <MASKED:psk> address 1.1.1.1",
		`*** Output from config line 3, "tacacs-server key 7 <MASKED:tacacs-key>"`,
	} {
		if kw, n, ok := secretAt(ln); ok {
			t.Errorf("falso positivo %q: %s %d", ln, kw, n)
		}
	}
}
