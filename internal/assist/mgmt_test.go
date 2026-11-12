package assist

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// noLeak falla si alguno de los textos cita el secreto.
func noLeak(t *testing.T, secret, what string, texts ...string) {
	t.Helper()
	for _, s := range texts {
		if strings.Contains(s, secret) {
			t.Errorf("%s cita el secreto %q: %s", what, secret, s)
		}
	}
}

// ---- ntp-server ----

func TestNTPServerEmptyStateRollbackIsNo(t *testing.T) {
	dev := newL3("ntp server 10.0.0.9", "ntp authentication-key 1 md5 0822455D0A16 7")
	dp := l3RoundTrip(t, "ntp-server", Values{"address": "10.0.0.1", "prefer": "true"}, dev)
	if got := joined(dp.Apply); got != "ntp server 10.0.0.1 prefer" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "no ntp server 10.0.0.1" {
		t.Errorf("Rollback = %s", got)
	}
	if !slices.Contains(dev.global, "ntp server 10.0.0.9") {
		t.Errorf("la reversa tocó otro servidor: %v", dev.global)
	}
	dp = l3RoundTrip(t, "ntp-server", Values{"address": "10.0.0.2"}, newL3())
	if joined(dp.Apply) != "ntp server 10.0.0.2" {
		t.Errorf("Apply = %s", joined(dp.Apply))
	}
	// El mismo servidor en otra VRF es otro servidor: no estorba.
	l3RoundTrip(t, "ntp-server", Values{"address": "10.0.0.2"}, newL3("ntp server vrf Mgmt 10.0.0.2 prefer"))
}

func TestNTPServerAlreadyThereAndRefusals(t *testing.T) {
	l3Nothing(t, "ya estaba", "ntp-server", Values{"address": "10.0.0.1"}, newL3("ntp server 10.0.0.1"))
	l3Nothing(t, "ya estaba con prefer", "ntp-server", Values{"address": "10.0.0.1", "prefer": "true"}, newL3("ntp server 10.0.0.1 prefer"))
	l3Refused(t, "con key", "ntp-server", Values{"address": "10.0.0.1"}, newL3("ntp server 10.0.0.1 key 3"))
	l3Refused(t, "con version", "ntp-server", Values{"address": "10.0.0.1", "prefer": "true"}, newL3("ntp server 10.0.0.1 version 3 prefer"))
	l3Refused(t, "sin prefer cuando se pide prefer", "ntp-server", Values{"address": "10.0.0.1", "prefer": "true"}, newL3("ntp server 10.0.0.1"))
	l3Refused(t, "con prefer cuando no se pide", "ntp-server", Values{"address": "10.0.0.1"}, newL3("ntp server 10.0.0.1 prefer"))
	l3Refused(t, "salida ilegible", "ntp-server", Values{"address": "10.0.0.1"}, func() *l3Dev { d := newL3(); d.hide[ntpCmd] = true; return d }())
	tpl := mustTemplate(t, "ntp-server")
	for _, bad := range []string{"224.0.0.1", "127.0.0.1", "0.0.0.0", "255.255.255.255"} {
		if _, err := tpl.Pre(Values{"address": bad}); err == nil {
			t.Errorf("%s aceptado", bad)
		}
	}
	if err := ValidateValues(tpl, Values{"address": "10.0.0.1", "prefer": "yes"}); err == nil {
		t.Error("prefer inválido aceptado")
	}
}

// ---- logging-host ----

func TestLoggingHostEmptyStateRollbackIsNo(t *testing.T) {
	dev := newL3("logging buffered 8192", "logging host 10.0.0.9")
	dp := l3RoundTrip(t, "logging-host", Values{"address": "10.0.0.1", "level": "warnings"}, dev)
	if got := joined(dp.Apply); got != "logging host 10.0.0.1|logging trap warnings" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "logging trap informational|no logging host 10.0.0.1" {
		t.Errorf("Rollback = %s", got)
	}
	dp = l3RoundTrip(t, "logging-host", Values{"address": "10.0.0.1"}, newL3())
	if joined(dp.Apply) != "logging host 10.0.0.1" || joined(dp.Rollback) != "no logging host 10.0.0.1" {
		t.Errorf("%v %v", dp.Apply, dp.Rollback)
	}
}

func TestLoggingHostRestoresTheCapturedTrapLevel(t *testing.T) {
	dev := newL3("logging trap errors")
	dp := l3RoundTrip(t, "logging-host", Values{"address": "10.0.0.1", "level": "debugging"}, dev)
	if got := joined(dp.Rollback); got != "logging trap errors|no logging host 10.0.0.1" {
		t.Errorf("Rollback = %s", got)
	}
	// El nivel de fábrica no se muestra: pedirlo quita la línea, y la reversa la vuelve a poner.
	dev = newL3("logging trap errors")
	dp = l3RoundTrip(t, "logging-host", Values{"address": "10.0.0.1", "level": "informational"}, dev)
	if got := joined(dp.Apply); got != "logging host 10.0.0.1|logging trap informational" || joined(dp.Rollback) != "logging trap errors|no logging host 10.0.0.1" {
		t.Errorf("%v %v", dp.Apply, dp.Rollback)
	}
	// Pedir el nivel que el equipo ya tiene (aunque sea el de fábrica) no cambia el trap.
	dp = l3RoundTrip(t, "logging-host", Values{"address": "10.0.0.1", "level": "informational"}, newL3())
	if joined(dp.Apply) != "logging host 10.0.0.1" {
		t.Errorf("Apply = %s", joined(dp.Apply))
	}
	dp = l3RoundTrip(t, "logging-host", Values{"address": "10.0.0.1", "level": "errors"}, newL3("logging trap errors"))
	if joined(dp.Apply) != "logging host 10.0.0.1" {
		t.Errorf("Apply = %s", joined(dp.Apply))
	}
}

func TestLoggingHostBothSyntaxesAndExistingHost(t *testing.T) {
	// IOS 12.x escribe `logging IP`: el post-check lo reconoce y la reversa lo quita.
	old := newL3()
	old.oldLog = true
	l3RoundTrip(t, "logging-host", Values{"address": "10.0.0.1", "level": "warnings"}, old)
	// El destino que ya está (en cualquiera de las dos formas) no se vuelve a agregar: solo cambia el trap.
	for _, line := range []string{"logging host 10.0.0.1", "logging 10.0.0.1"} {
		dp := l3RoundTrip(t, "logging-host", Values{"address": "10.0.0.1", "level": "warnings"}, newL3(line))
		if joined(dp.Apply) != "logging trap warnings" || joined(dp.Rollback) != "logging trap informational" {
			t.Errorf("%s: %v %v", line, dp.Apply, dp.Rollback)
		}
		l3Nothing(t, line+" ya estaba", "logging-host", Values{"address": "10.0.0.1"}, newL3(line))
	}
}

// Revisión de 28d: `no logging trap` se queda en el running en varias versiones y apaga el syslog; la reversa vuelve al nivel de fábrica.
func TestLoggingHostReversaNeverLeavesNoLoggingTrap(t *testing.T) {
	dev := newL3()
	dp := l3RoundTrip(t, "logging-host", Values{"address": "10.0.0.1", "level": "warnings"}, dev)
	if slices.Contains(dev.global, "no logging trap") || slices.Contains(dp.Rollback, "no logging trap") {
		t.Errorf("quedó o se mandó `no logging trap`: %v %v", dev.global, dp.Rollback)
	}
	if _, ok := dp.Baseline["show running-config | include ^(no )*logging"]; !ok || len(dp.Baseline) != 1 {
		t.Errorf("la línea base debe ver también `no logging ...`: %v", dp.Baseline)
	}
	// Una línea base que ya trae `no logging trap` se restaura exactamente (la reversa no la convierte en el nivel de fábrica).
	off := newL3("no logging trap")
	dp = l3RoundTrip(t, "logging-host", Values{"address": "10.0.0.1", "level": "warnings"}, off)
	if joined(dp.Rollback) != "no logging trap|no logging host 10.0.0.1" || !slices.Contains(off.global, "no logging trap") {
		t.Errorf("Rollback = %s, equipo %v", joined(dp.Rollback), off.global)
	}
	// Sin pedir nivel, el `no logging trap` ajeno ni se toca.
	dp = l3RoundTrip(t, "logging-host", Values{"address": "10.0.0.1"}, newL3("no logging trap"))
	if joined(dp.Apply) != "logging host 10.0.0.1" {
		t.Errorf("Apply = %s", joined(dp.Apply))
	}
	// La función no acepta que una reversa de un trap ausente sea `no logging trap` ni que la de uno capturado sea otra cosa.
	tpl := mustTemplate(t, "logging-host")
	plan, err := l3Plan(t, "logging-host", Values{"address": "10.0.0.1", "level": "warnings"}, newL3())
	if err != nil {
		t.Fatal(err)
	}
	bad := plan
	bad.Rollback = []string{"no logging trap", "no logging host 10.0.0.1"}
	if err := Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{bad}}, tpl.Fn); err == nil {
		t.Error("reversa `no logging trap` para un trap ausente aceptada")
	}
}

// Fase 28g: el receptor de la app escucha en un puerto alto, así que el destino lleva transporte y puerto.
func TestLoggingHostTransportAndPort(t *testing.T) {
	for _, c := range []struct {
		name string
		v    Values
		line string
	}{
		{"puerto solo: udp", Values{"port": "5514"}, "logging host 10.0.0.1 transport udp port 5514"},
		{"transporte udp solo: 514", Values{"transport": "udp"}, "logging host 10.0.0.1"},
		{"puerto 514 solo: la forma corta", Values{"port": "514"}, "logging host 10.0.0.1"},
		{"udp 514 explícito: la forma corta", Values{"transport": "udp", "port": "514"}, "logging host 10.0.0.1"},
		{"transporte tcp solo: 601", Values{"transport": "tcp"}, "logging host 10.0.0.1 transport tcp port 601"},
		{"tcp 514 no es la forma corta", Values{"transport": "tcp", "port": "514"}, "logging host 10.0.0.1 transport tcp port 514"},
		{"tcp con puerto", Values{"transport": "tcp", "port": "1514"}, "logging host 10.0.0.1 transport tcp port 1514"},
	} {
		c.v["address"] = "10.0.0.1"
		c.v["level"] = "warnings"
		dev := newL3("logging host 10.0.0.9")
		dp := l3RoundTrip(t, "logging-host", c.v, dev)
		if got := joined(dp.Apply); got != c.line+"|logging trap warnings" {
			t.Errorf("%s: Apply = %s", c.name, got)
		}
		// La reversa es la forma completa: sin ella IOS no sabría cuál de los destinos de la IP quitar.
		if got := joined(dp.Rollback); got != "logging trap informational|no "+c.line {
			t.Errorf("%s: Rollback = %s", c.name, got)
		}
		if !slices.Equal(dev.global, []string{"logging host 10.0.0.9"}) {
			t.Errorf("%s: quedó %v", c.name, dev.global)
		}
	}
	// udp 514 no depende de cómo IOS normalice `transport udp port 514`: forma corta y Expect solo con la IP.
	dp := l3RoundTrip(t, "logging-host", Values{"address": "10.0.0.1", "transport": "udp", "port": "514"}, newL3())
	if len(dp.Expect) != 1 || dp.Expect[0].Line != "10.0.0.1" {
		t.Errorf("Expect = %+v", dp.Expect)
	}
	// Sin transporte ni puerto, igual que antes.
	dp = l3RoundTrip(t, "logging-host", Values{"address": "10.0.0.1"}, newL3())
	if joined(dp.Apply) != "logging host 10.0.0.1" || joined(dp.Rollback) != "no logging host 10.0.0.1" {
		t.Errorf("%v %v", dp.Apply, dp.Rollback)
	}
}

func TestLoggingHostTransportExistingDestination(t *testing.T) {
	udp5514 := Values{"address": "10.0.0.1", "port": "5514"}
	// La misma línea (y las formas que IOS muestra para el mismo transporte y puerto) es «ya estaba».
	l3Nothing(t, "misma línea", "logging-host", udp5514, newL3("logging host 10.0.0.1 transport udp port 5514"))
	l3Nothing(t, "puerto de fábrica explícito contra el sufijo omitido", "logging-host", Values{"address": "10.0.0.1", "transport": "udp", "port": "514"}, newL3("logging host 10.0.0.1"))
	l3Nothing(t, "puerto de fábrica explícito contra port omitido", "logging-host", Values{"address": "10.0.0.1", "transport": "udp", "port": "514"}, newL3("logging host 10.0.0.1 transport udp"))
	l3Nothing(t, "tcp sin port contra el 601", "logging-host", Values{"address": "10.0.0.1", "transport": "tcp"}, newL3("logging host 10.0.0.1 transport tcp"))
	l3Nothing(t, "sin opciones contra la forma completa de fábrica", "logging-host", Values{"address": "10.0.0.1"}, newL3("logging host 10.0.0.1 transport udp port 514"))
	// Otro transporte, otro puerto u otras opciones: la reversa no sabría distinguirlos.
	l3Refused(t, "otro puerto", "logging-host", udp5514, newL3("logging host 10.0.0.1 transport udp port 5515"))
	l3Refused(t, "otro transporte", "logging-host", udp5514, newL3("logging host 10.0.0.1 transport tcp port 5514"))
	l3Refused(t, "destino plano contra un puerto alto", "logging-host", udp5514, newL3("logging host 10.0.0.1"))
	l3Refused(t, "destino plano IOS 12.x contra un puerto alto", "logging-host", udp5514, newL3("logging 10.0.0.1"))
	l3Refused(t, "puerto alto contra destino plano", "logging-host", Values{"address": "10.0.0.1"}, newL3("logging host 10.0.0.1 transport udp port 5514"))
	l3Refused(t, "opciones ajenas", "logging-host", udp5514, newL3("logging host 10.0.0.1 transport udp port 5514 filtered"))
	l3Refused(t, "vrf", "logging-host", udp5514, newL3("logging host 10.0.0.1 vrf Mgmt transport udp port 5514"))
	// El motivo dice el límite real: un solo destino por IP.
	_, err := l3Plan(t, "logging-host", udp5514, newL3("logging host 10.0.0.1 transport tcp port 601"))
	if err == nil || !strings.Contains(err.Error(), "un solo destino por IP") || !strings.Contains(err.Error(), "logging host 10.0.0.1 transport tcp port 601") || strings.Contains(err.Error(), "no las distinguiría") {
		t.Errorf("motivo = %v", err)
	}
	// Otra IP no estorba.
	l3RoundTrip(t, "logging-host", udp5514, newL3("logging host 10.0.0.2 transport udp port 5514"))
}

func TestLoggingHostTransportValidationAndFunction(t *testing.T) {
	tpl := mustTemplate(t, "logging-host")
	for name, v := range map[string]Values{
		"transporte desconocido": {"address": "10.0.0.1", "transport": "beep"},
		"puerto 0":               {"address": "10.0.0.1", "port": "0"},
		"puerto 65536":           {"address": "10.0.0.1", "port": "65536"},
		"puerto negativo":        {"address": "10.0.0.1", "port": "-1"},
		"puerto no numérico":     {"address": "10.0.0.1", "port": "syslog"},
	} {
		if err := ValidateValues(tpl, v); err == nil {
			t.Errorf("%s aceptado", name)
		}
	}
	for _, ok := range []Values{{"address": "10.0.0.1", "port": "65535"}, {"address": "10.0.0.1", "port": "1"}, {"address": "10.0.0.1", "transport": "tcp"}} {
		if err := ValidateValues(tpl, ok); err != nil {
			t.Errorf("%v rechazado: %v", ok, err)
		}
	}
	for _, bad := range []Values{{"address": "10.0.0.1", "port": "0"}, {"address": "10.0.0.1", "port": "70000"}, {"address": "10.0.0.1", "transport": "sctp"}, {"address": "10.0.0.1", "port": "x"}} {
		if _, err := tpl.Pre(bad); err == nil {
			t.Errorf("Pre aceptó %v", bad)
		}
	}
	// Lista cerrada: solo la forma exacta, con su `no` completo.
	for _, good := range []string{"logging host 10.0.0.1 transport udp port 5514", "no logging host 10.0.0.1 transport tcp port 601", "logging host 10.0.0.1", "no logging host 10.0.0.1"} {
		if err := tpl.Fn.Check(good); err != nil {
			t.Errorf("%q rechazado: %v", good, err)
		}
	}
	for _, bad := range []string{
		"logging host 10.0.0.1 transport beep port 5514", "logging host 10.0.0.1 transport udp", "logging host 10.0.0.1 transport udp port",
		"logging host 10.0.0.1 transport udp port 0", "logging host 10.0.0.1 transport udp port 65536", "logging host 10.0.0.1 transport udp port 05514",
		"logging host 10.0.0.1 transport udp port 5514 xml", "logging host 10.0.0.1 port 5514", "logging host 10.0.0.1 transport udp port 5514 filtered",
		"logging host 224.0.0.1 transport udp port 5514", "no logging host 10.0.0.1 transport udp", "logging host 10.0.0.1 transport udp port +5514",
	} {
		if err := tpl.Fn.Check(bad); err == nil {
			t.Errorf("%q aceptado", bad)
		}
	}
	// La reversa de un destino con puerto es su `no` completo, no el corto.
	plan, err := l3Plan(t, "logging-host", Values{"address": "10.0.0.1", "port": "5514"}, newL3())
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{plan}}, tpl.Fn); err != nil {
		t.Fatal(err)
	}
	bad := plan
	bad.Rollback = []string{"no logging host 10.0.0.1"}
	if err := Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{bad}}, tpl.Fn); err == nil {
		t.Error("reversa corta para un destino con puerto aceptada")
	}
	bad.Rollback = []string{"no logging host 10.0.0.1 transport udp port 5515"}
	if err := Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{bad}}, tpl.Fn); err == nil {
		t.Error("reversa de otro puerto aceptada")
	}
}

func TestLoggingHostRefusals(t *testing.T) {
	v := Values{"address": "10.0.0.1", "level": "warnings"}
	l3Refused(t, "destino con otro transporte y puerto", "logging-host", v, newL3("logging host 10.0.0.1 transport tcp port 601"))
	l3Refused(t, "nivel de trap que no se sabe restaurar", "logging-host", v, newL3("logging trap 9"))
	l3Refused(t, "salida ilegible", "logging-host", v, func() *l3Dev { d := newL3(); d.hide[loggingCmd] = true; return d }())
	tpl := mustTemplate(t, "logging-host")
	for _, bad := range []Values{{"address": "10.0.0.1", "level": "verbose"}, {"address": "10.0.0.1", "level": "7"}, {"level": "errors"}} {
		if err := ValidateValues(tpl, bad); err == nil {
			t.Errorf("%v aceptado", bad)
		}
	}
	if _, err := tpl.Pre(Values{"address": "224.0.0.9"}); err == nil {
		t.Error("destino multicast aceptado")
	}
}

// ---- snmp-community ----

const comm = "Zx9-Secreta.Comm"

func TestSNMPCommunityEmptyStateRollbackIsNo(t *testing.T) {
	dev := newL3("snmp-server community otra RO", "snmp-server location Lab")
	dp := l3RoundTrip(t, "snmp-community", Values{"community": comm}, dev)
	if got := joined(dp.Apply); got != "snmp-server community "+comm+" RO" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "no snmp-server community "+comm {
		t.Errorf("Rollback = %s", got)
	}
	if !slices.Contains(dev.global, "snmp-server community otra RO") {
		t.Errorf("la reversa tocó otra community: %v", dev.global)
	}
	acl := newL3()
	acl.acls["MGMT"] = "Standard IP access list MGMT\n    10 permit 10.1.1.0, wildcard bits 0.0.0.255\n"
	dp = l3RoundTrip(t, "snmp-community", Values{"community": comm, "acl": "MGMT"}, acl)
	if joined(dp.Apply) != "snmp-server community "+comm+" RO MGMT" {
		t.Errorf("Apply = %s", joined(dp.Apply))
	}
	// Una ACL numerada y una extendida también existen.
	num := newL3()
	num.acls["10"] = "Standard IP access list 10\n    10 permit any\n"
	l3RoundTrip(t, "snmp-community", Values{"community": comm, "acl": "10"}, num)
	ext := newL3()
	ext.acls["EXT"] = "Extended IP access list EXT\n    10 permit udp any any eq snmp\n"
	l3RoundTrip(t, "snmp-community", Values{"community": comm, "acl": "EXT"}, ext)
}

func TestSNMPCommunityRefusals(t *testing.T) {
	v := Values{"community": comm}
	l3Refused(t, "community existente RO", "snmp-community", v, newL3("snmp-server community "+comm+" RO"))
	l3Refused(t, "community existente RW", "snmp-community", v, newL3("snmp-server community "+comm+" RW 10"))
	l3Refused(t, "community existente con vista", "snmp-community", v, newL3("snmp-server community "+comm+" view V RO"))
	l3Refused(t, "salida ilegible", "snmp-community", v, func() *l3Dev { d := newL3(); d.hide[snmpCommCmd] = true; return d }())
	withACL := Values{"community": comm, "acl": "MGMT"}
	l3Refused(t, "ACL inexistente", "snmp-community", withACL, newL3())
	hidden := newL3()
	hidden.acls["MGMT"] = "Standard IP access list MGMT\n    10 permit any\n"
	hidden.hide[showACL("MGMT")] = true
	l3Refused(t, "ACL ilegible", "snmp-community", withACL, hidden)
	other := newL3()
	other.acls["MGMT"] = "Standard IP access list OTRA\n    10 permit any\n"
	l3Refused(t, "otra ACL", "snmp-community", withACL, other)
}

func TestSNMPCommunityValidation(t *testing.T) {
	tpl := mustTemplate(t, "snmp-community")
	for name, v := range map[string]Values{
		"con espacio":       {"community": "dos palabras"},
		"con interrogación": {"community": "abc?def"},
		"33 caracteres":     {"community": strings.Repeat("a", 33)},
		"sin community":     {},
		"RW como campo":     {"community": comm, "permission": "RW"},
		"ACL con espacio":   {"community": comm, "acl": "dos palabras"},
		"ACL con inyección": {"community": comm, "acl": "MGMT;reload"},
	} {
		if err := ValidateValues(tpl, v); err == nil {
			t.Errorf("%s aceptado", name)
		}
	}
	if _, err := tpl.Pre(Values{"community": "abc@vlan10"}); err == nil {
		t.Error("community con @ aceptada (IOS la toma como community@VLAN)")
	}
}

// Revisión de 28d: la ACL del campo (hasta 64) y la de Check coinciden; la community mide al menos 4 para que Scrub no deje ilegibles los eventos.
func TestSNMPCommunityACLLengthAndMinimumCommunity(t *testing.T) {
	long := strings.Repeat("A", 40)
	dev := newL3()
	dev.acls[long] = "Standard IP access list " + long + "\n    10 permit any\n"
	dp := l3RoundTrip(t, "snmp-community", Values{"community": comm, "acl": long}, dev)
	if !strings.HasSuffix(dp.Apply[0], " RO "+long) {
		t.Errorf("Apply = %v", dp.Apply)
	}
	tpl := mustTemplate(t, "snmp-community")
	if err := ValidateValues(tpl, Values{"community": "abc"}); err == nil {
		t.Error("community de 3 caracteres aceptada")
	}
	if err := ValidateValues(tpl, Values{"community": "abcd"}); err != nil {
		t.Errorf("community de 4: %v", err)
	}
	if _, err := tpl.Pre(Values{"community": "abc"}); err == nil {
		t.Error("Pre acepta una community de 3 caracteres")
	}
	if err := SnippetSNMPCommunity.configLine("snmp-server community abc RO"); err == nil {
		t.Error("la lista cerrada acepta una community de 3 caracteres")
	}
}

// RW nunca: ni aunque alguien arme el plan a mano.
func TestSNMPCommunityFunctionNeverAllowsRW(t *testing.T) {
	fn := SnippetSNMPCommunity
	for _, l := range []string{"snmp-server community " + comm + " RW", "snmp-server community " + comm + " rw", "snmp-server community " + comm,
		"snmp-server community " + comm + " RO 10 20", "snmp-server community a@b RO", "snmp-server host 10.0.0.1 " + comm, "snmp-server enable traps",
		"no snmp-server community", "snmp-server community " + comm + " RO view V"} {
		if err := fn.configLine(l); err == nil {
			t.Errorf("%q aceptada", l)
		}
	}
	for _, l := range []string{"snmp-server community " + comm + " RO", "snmp-server community " + comm + " RO MGMT", "no snmp-server community " + comm} {
		if err := fn.configLine(l); err != nil {
			t.Errorf("%q rechazada: %v", l, err)
		}
	}
}

func TestSNMPCommunityNeverShowsTheSecret(t *testing.T) {
	tpl := mustTemplate(t, "snmp-community")
	if !tpl.Fn.Scrub {
		t.Fatal("la función debe limpiar lo que IOS imprime tras la community")
	}
	dev := newL3("snmp-server community " + comm + " RO")
	v := Values{"community": comm}
	// Los rechazos y los errores de ValidateValues no la citan.
	_, err := l3Plan(t, "snmp-community", v, dev)
	noLeak(t, comm, "el rechazo por community existente", fmt.Sprint(err))
	noLeak(t, comm, "el error de ValidateValues", fmt.Sprint(ValidateValues(tpl, Values{"community": comm + " con espacio"})))
	_, err = tpl.Pre(Values{"community": comm + "@10"})
	noLeak(t, comm, "el error de Pre", fmt.Sprint(err))
	// El plan: la community está en Secrets, y el plan que ve el cliente (Redact) no la trae en ningún campo.
	dp, err := l3Plan(t, "snmp-community", v, newL3())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(dp.Secrets, comm) {
		t.Fatalf("Secrets = %v", dp.Secrets)
	}
	noLeak(t, comm, "Notes", dp.Notes...)
	red := Redact(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{dp}}, tpl.Fn)
	noLeak(t, comm, "el plan redactado", fmt.Sprintf("%+v", red))
	if got := joined(red.Devices[0].Apply); !strings.HasPrefix(got, "snmp-server community <") || !strings.HasSuffix(got, "> RO") {
		t.Errorf("Apply redactado = %v", red.Devices[0].Apply)
	}
	// La validación del plan (que viaja al cliente) tampoco la cita.
	bad := dp
	bad.Rollback = []string{"no snmp-server community otra"}
	err = Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{bad}}, tpl.Fn)
	if err == nil {
		t.Fatal("reversa de otra community aceptada")
	}
	noLeak(t, comm, "el error de Validate", err.Error())
	// El residuo de una reversa que dejó la community no la muestra.
	noLeak(t, comm, "el residuo", residue("hostname SW1\nend", "hostname SW1\nsnmp-server community "+comm+" RO\nend"))
}

// ---- banner-motd ----

const motd = "Solo personal autorizado"

func TestBannerEmptyStateRollbackIsNo(t *testing.T) {
	dev := newL3("hostname SW1")
	dp := l3RoundTrip(t, "banner-motd", Values{"text": motd}, dev)
	if got := joined(dp.Apply); got != "banner motd #"+motd+"#" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "no banner motd" {
		t.Errorf("Rollback = %s", got)
	}
	if slices.ContainsFunc(dev.global, func(l string) bool { return strings.HasPrefix(l, "banner") }) {
		t.Errorf("la reversa no quitó el banner: %v", dev.global)
	}
}

func TestBannerRestoresTheOneLineBanner(t *testing.T) {
	dev := newL3("banner motd ^CAcceso restringido  - 24x7^C")
	dp := l3RoundTrip(t, "banner-motd", Values{"text": motd}, dev)
	if got := joined(dp.Rollback); got != "banner motd #Acceso restringido  - 24x7#" {
		t.Errorf("Rollback = %s", got)
	}
	l3Nothing(t, "ya estaba", "banner-motd", Values{"text": motd}, newL3("banner motd ^C"+motd+"^C"))
}

func TestBannerRefusals(t *testing.T) {
	v := Values{"text": motd}
	l3Refused(t, "banner de varias líneas", "banner-motd", v, newL3("banner motd ^C", "Acceso restringido", "^C"))
	l3Refused(t, "banner de varias líneas con texto en la primera", "banner-motd", v, newL3("banner motd ^CAcceso", "restringido^C"))
	l3Refused(t, "texto previo con # (el delimitador de la reversa)", "banner-motd", v, newL3("banner motd ^CCanal #1 abierto^C"))
	l3Refused(t, "salida ilegible", "banner-motd", v, func() *l3Dev { d := newL3(); d.hide[bannerCmd] = true; return d }())
	tpl := mustTemplate(t, "banner-motd")
	for name, bad := range map[string]string{"con #": "hola # mundo", "con ^": "hola ^C mundo", "con interrogación": "hola?", "no ASCII": "Acción", "201 caracteres": strings.Repeat("a", 201),
		"con salto de línea": "hola\nreload"} {
		if err := ValidateValues(tpl, Values{"text": bad}); err == nil {
			t.Errorf("%s aceptado", name)
		}
	}
	if err := ValidateValues(tpl, Values{}); err == nil {
		t.Error("sin texto aceptado")
	}
}

func TestBannerFieldPatternExcludesQuestionMark(t *testing.T) {
	re := regexp.MustCompile(mustTemplate(t, "banner-motd").Fields[0].Pattern)
	for _, bad := range []string{"hola?", "a#b", "a^b"} {
		if re.MatchString(bad) {
			t.Errorf("el patrón del campo acepta %q", bad)
		}
	}
	if !re.MatchString(motd) {
		t.Error("el patrón rechaza un texto normal")
	}
}

func TestBannerFunctionIsOneLineOnly(t *testing.T) {
	fn := SnippetBanner
	for _, l := range []string{"banner motd #a#b#", "banner motd #", "banner motd ##", "banner login #hola#", "banner motd ^Chola^C", "banner motd #ho^la#", "no banner login", "no banner motd x"} {
		if err := fn.configLine(l); err == nil {
			t.Errorf("%q aceptada", l)
		}
	}
	for _, l := range []string{"banner motd #hola mundo#", "no banner motd"} {
		if err := fn.configLine(l); err != nil {
			t.Errorf("%q rechazada: %v", l, err)
		}
	}
}

func TestL3MgmtTemplatesAreInTheCatalogByTech(t *testing.T) {
	want := map[string]string{"ruta-estatica": "l3", "loopback": "l3", "helper-address": "l3", "ntp-server": "gestion", "logging-host": "gestion",
		"snmp-community": "gestion", "snmpv3-usuario": "gestion", "banner-motd": "gestion", "vty-acl": "seguridad"}
	got := map[string]string{}
	last := -1
	for _, tp := range Templates() {
		got[tp.ID] = tp.Tech
		if i := slices.Index(TechOrder, tp.Tech); i < last {
			t.Errorf("%s: fuera del orden del catálogo", tp.ID)
		} else {
			last = i
		}
	}
	for id, tech := range want {
		if got[id] != tech {
			t.Errorf("%s: tecnología %q, quería %q", id, got[id], tech)
		}
	}
	for _, id := range []string{"snmp-community", "snmpv3-usuario"} {
		tpl := mustTemplate(t, id)
		secrets := 0
		for _, f := range tpl.Fields {
			if f.Type == TypeSecret {
				secrets++
			}
		}
		if secrets == 0 || !tpl.Fn.Scrub {
			t.Errorf("%s: sus secretos deben ser campos secret y la función limpiar la salida", id)
		}
	}
}

// Las columnas de la fase 28d: una salida ilegible es «no se pudo leer», no «no está».
func TestL3ColumnsDistinguishAbsentFromUnreadable(t *testing.T) {
	cases := []struct {
		name string
		e    Expect
		text string
		want string // fragmento del fallo; vacío = se cumple
	}{
		{"ruta presente", Expect{Command: "c", Line: "10.1.0.0 255.255.0.0 10.0.0.1", Column: "static-route", Present: true}, "ip route 10.1.0.0 255.255.0.0 10.0.0.1 5\n", ""},
		{"ruta con interfaz abreviada", Expect{Command: "c", Line: "10.1.0.0 255.255.0.0 Gi1/0/1", Column: "static-route", Present: true}, "ip route 10.1.0.0 255.255.0.0 GigabitEthernet1/0/1\n", ""},
		{"ruta ausente", Expect{Command: "c", Line: "10.1.0.0 255.255.0.0 10.0.0.1", Column: "static-route", Present: true}, "ip route 10.1.0.0 255.255.0.0 10.0.0.2\n", "debía cumplirse"},
		{"ruta que no debía estar", Expect{Command: "c", Line: "10.1.0.0 255.255.0.0 10.0.0.1", Column: "static-route"}, "ip route 10.1.0.0 255.255.0.0 10.0.0.1\n", "no debía cumplirse"},
		{"ruta ilegible", Expect{Command: "c", Line: "10.1.0.0 255.255.0.0 10.0.0.1", Column: "static-route", Present: true}, "% Invalid input detected at '^' marker.\n", "no se pudo leer"},
		{"syslog host", Expect{Command: "c", Line: "10.0.0.1", Column: "logging-host", Present: true}, "logging host 10.0.0.1\n", ""},
		{"syslog 12.x", Expect{Command: "c", Line: "10.0.0.1", Column: "logging-host", Present: true}, "logging 10.0.0.1\n", ""},
		{"syslog con puerto", Expect{Command: "c", Line: "10.0.0.1 transport udp port 5514", Column: "logging-host", Present: true}, "logging host 10.0.0.1 transport udp port 5514\n", ""},
		{"syslog con otro puerto", Expect{Command: "c", Line: "10.0.0.1 transport udp port 5514", Column: "logging-host", Present: true}, "logging host 10.0.0.1 transport udp port 5515\n", "debía cumplirse"},
		{"syslog con otro transporte", Expect{Command: "c", Line: "10.0.0.1 transport tcp port 5514", Column: "logging-host", Present: true}, "logging host 10.0.0.1 transport udp port 5514\n", "debía cumplirse"},
		{"syslog puerto de fábrica omitido", Expect{Command: "c", Line: "10.0.0.1 transport udp port 514", Column: "logging-host", Present: true}, "logging host 10.0.0.1\n", ""},
		{"syslog puerto de fábrica omitido en el sufijo", Expect{Command: "c", Line: "10.0.0.1 transport udp port 514", Column: "logging-host", Present: true}, "logging host 10.0.0.1 transport udp\n", ""},
		{"syslog tcp 601 omitido", Expect{Command: "c", Line: "10.0.0.1 transport tcp port 601", Column: "logging-host", Present: true}, "logging host 10.0.0.1 transport tcp\n", ""},
		{"syslog plano no es un puerto alto", Expect{Command: "c", Line: "10.0.0.1 transport udp port 5514", Column: "logging-host", Present: true}, "logging host 10.0.0.1\n", "debía cumplirse"},
		{"syslog con opciones ajenas", Expect{Command: "c", Line: "10.0.0.1 transport udp port 5514", Column: "logging-host", Present: true}, "logging host 10.0.0.1 transport udp port 5514 filtered\n", "debía cumplirse"},
		{"syslog ausente", Expect{Command: "c", Line: "10.0.0.1", Column: "logging-host", Present: true}, "logging host 10.0.0.2\n", "debía cumplirse"},
		{"usuario presente", Expect{Command: "c", Line: "tech ADMINS", Column: "snmp-user", Present: true}, "User name: tech\nGroup-name: ADMINS\n", ""},
		{"usuario de otro grupo", Expect{Command: "c", Line: "tech ADMINS", Column: "snmp-user", Present: true}, "User name: tech\nGroup-name: LECT\n", "debía cumplirse"},
		{"usuario ausente", Expect{Command: "c", Line: "tech ADMINS", Column: "snmp-user"}, "", ""},
		{"agente apagado", Expect{Command: "c", Line: "tech ADMINS", Column: "snmp-user"}, "%SNMP agent not enabled\n", "no se pudo leer"},
	}
	for _, c := range cases {
		fails := EvalExpect([]Expect{c.e}, map[string]string{"c": c.text})
		switch {
		case c.want == "" && len(fails) > 0, c.want != "" && (len(fails) != 1 || !strings.Contains(fails[0], c.want)):
			t.Errorf("%s: %v, quería %q", c.name, fails, c.want)
		}
	}
}
