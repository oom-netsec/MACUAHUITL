package assist

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
)

// ---- snmpv3-usuario ----

const (
	v3Auth = "Auth-Secreta.1"
	v3Priv = "Priv-Secreta.2"
)

func v3Vals() Values {
	return Values{"user": "tech", "group": "ADMINS", "auth": "sha", "auth_password": v3Auth, "priv": "aes 128", "priv_password": v3Priv}
}

const v3Line = "snmp-server user tech ADMINS v3 auth sha " + v3Auth + " priv aes 128 " + v3Priv

func TestSNMPv3EmptyStateCreatesTheGroupAndRollbackRemovesBoth(t *testing.T) {
	dev := newL3("snmp-server group OTRO v3 auth")
	dp := l3RoundTrip(t, "snmpv3-usuario", v3Vals(), dev)
	if got := joined(dp.Apply); got != "snmp-server group ADMINS v3 priv|"+v3Line {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "no snmp-server user tech ADMINS v3|no snmp-server group ADMINS v3 priv" {
		t.Errorf("Rollback = %s", got)
	}
	if !slices.Contains(dev.global, "snmp-server group OTRO v3 auth") || len(dev.users) != 0 {
		t.Errorf("el equipo quedó %v %v", dev.global, dev.users)
	}
	// IOS no escribe el usuario en el running: lo que se verifica y se compara tras la reversa es show snmp user.
	if !slices.Contains(dp.Post, snmpUserCmd) || !slices.Contains(runningCmds(dp), snmpUserCmd) || !slices.Contains(dp.Pre, snmpUserCmd) {
		t.Errorf("show snmp user debe estar en Pre, Post y en la línea base que se compara: %+v", dp)
	}
	if len(dp.Notes) == 0 || !strings.Contains(dp.Notes[0], "show snmp user") {
		t.Errorf("falta el aviso: %v", dp.Notes)
	}
}

func TestSNMPv3ExistingGroupIsReusedAndKept(t *testing.T) {
	dev := newL3("snmp-server group ADMINS v3 priv read VISTA")
	dp := l3RoundTrip(t, "snmpv3-usuario", v3Vals(), dev)
	if joined(dp.Apply) != v3Line || joined(dp.Rollback) != "no snmp-server user tech ADMINS v3" {
		t.Errorf("%v %v", dp.Apply, dp.Rollback)
	}
	if !slices.Contains(dev.global, "snmp-server group ADMINS v3 priv read VISTA") {
		t.Errorf("la reversa tocó el grupo: %v", dev.global)
	}
}

// «Se espera ver» lista cada comprobación una sola vez: la línea del grupo (si se crea) y el usuario en show snmp user.
func TestSNMPv3ExpectSinRepetidos(t *testing.T) {
	user := Expect{Command: snmpUserCmd, Line: "tech ADMINS", Present: true, Column: "snmp-user"}
	for _, c := range []struct {
		name string
		dev  *l3Dev
		want []Expect
	}{
		{"grupo nuevo", newL3("snmp-server group OTRO v3 auth"), []Expect{{Command: snmpGroupCmd, Line: "snmp-server group ADMINS v3 priv", Present: true}, user}},
		{"grupo existente", newL3("snmp-server group ADMINS v3 priv read VISTA"), []Expect{user}},
	} {
		dp := l3RoundTrip(t, "snmpv3-usuario", v3Vals(), c.dev)
		if !slices.Equal(dp.Expect, c.want) {
			t.Errorf("%s: Expect = %+v", c.name, dp.Expect)
		}
	}
}

func TestSNMPv3Refusals(t *testing.T) {
	v := v3Vals()
	has := newL3()
	has.users = []string{"tech LECT"}
	l3Refused(t, "usuario existente (otro grupo)", "snmpv3-usuario", v, has)
	l3Refused(t, "grupo con otro nivel", "snmpv3-usuario", v, newL3("snmp-server group ADMINS v3 auth"))
	l3Refused(t, "grupo sin autenticación", "snmpv3-usuario", v, newL3("snmp-server group ADMINS v3 noauth"))
	off := newL3()
	off.hide[snmpUserCmd] = true
	l3Refused(t, "show snmp user ilegible (agente apagado)", "snmpv3-usuario", v, off)
	noGroups := newL3()
	noGroups.hide[snmpGroupCmd] = true
	l3Refused(t, "grupos ilegibles", "snmpv3-usuario", v, noGroups)
	// Un grupo v2c con el mismo nombre no estorba.
	l3RoundTrip(t, "snmpv3-usuario", v, newL3("snmp-server group ADMINS v2c"))
}

func TestSNMPv3Validation(t *testing.T) {
	tpl := mustTemplate(t, "snmpv3-usuario")
	mod := func(k, val string) Values { v := v3Vals(); v[k] = val; return v }
	for name, v := range map[string]Values{
		"contraseña de autenticación corta": mod("auth_password", "corta12"),
		"contraseña de privacidad larga":    mod("priv_password", strings.Repeat("a", 65)),
		"contraseña con espacio":            mod("priv_password", "con espacio 123"),
		"auth md5":                          mod("auth", "md5"),
		"priv des":                          mod("priv", "des"),
		"usuario con espacio":               mod("user", "dos palabras"),
		"grupo con inyección":               mod("group", "G;reload"),
		"sin contraseña de privacidad":      {"user": "tech", "group": "ADMINS", "auth_password": v3Auth},
	} {
		err := ValidateValues(tpl, v)
		if err == nil {
			t.Errorf("%s aceptado", name)
			continue
		}
		noLeak(t, v3Auth, name, err.Error())
		noLeak(t, v3Priv, name, err.Error())
	}
	if err := ValidateValues(tpl, v3Vals()); err != nil {
		t.Errorf("valores válidos: %v", err)
	}
}

func TestSNMPv3FunctionIsAClosedList(t *testing.T) {
	fn := SnippetSNMPv3
	for _, l := range []string{
		"snmp-server user tech ADMINS v3 auth md5 " + v3Auth + " priv aes 128 " + v3Priv,
		"snmp-server user tech ADMINS v3 auth sha " + v3Auth + " priv des " + v3Priv,
		"snmp-server user tech ADMINS v3 auth sha " + v3Auth,
		"snmp-server user tech ADMINS v3 auth sha corta priv aes 128 " + v3Priv,
		"snmp-server user tech ADMINS v2c",
		"snmp-server user tech ADMINS v3 remote 10.0.0.1 auth sha " + v3Auth + " priv aes 128 " + v3Priv,
		"snmp-server group ADMINS v3 noauth", "snmp-server group ADMINS v3 auth", "snmp-server group ADMINS v3 priv read V",
		"snmp-server group ADMINS v2c", "snmp-server community x RO", "snmp-server host 10.0.0.1 version 3 priv tech",
		"no snmp-server user tech ADMINS", "no snmp-server group ADMINS v3", "no snmp-server",
	} {
		if err := fn.configLine(l); err == nil {
			t.Errorf("%q aceptada", l)
		}
	}
	for _, l := range []string{v3Line, "snmp-server group ADMINS v3 priv", "no snmp-server user tech ADMINS v3", "no snmp-server group ADMINS v3 priv"} {
		if err := fn.configLine(l); err != nil {
			t.Errorf("%q rechazada: %v", l, err)
		}
	}
}

func TestSNMPv3CheckDeviceRejectsAnUnsoundReversa(t *testing.T) {
	tpl := mustTemplate(t, "snmpv3-usuario")
	dp, err := l3Plan(t, "snmpv3-usuario", v3Vals(), newL3())
	if err != nil {
		t.Fatal(err)
	}
	check := func(what string, mod func(*DevicePlan)) {
		t.Helper()
		bad := dp
		bad.Rollback, bad.Baseline = slices.Clone(dp.Rollback), map[string]string{snmpUserCmd: dp.Baseline[snmpUserCmd], snmpGroupCmd: dp.Baseline[snmpGroupCmd]}
		mod(&bad)
		err := Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{bad}}, tpl.Fn)
		if err == nil {
			t.Errorf("%s: aceptado", what)
			return
		}
		noLeak(t, v3Auth, what, err.Error())
		noLeak(t, v3Priv, what, err.Error())
	}
	check("reversa sin quitar el usuario", func(d *DevicePlan) { d.Rollback = []string{"no snmp-server group ADMINS v3 priv"} })
	check("reversa sin quitar el grupo creado", func(d *DevicePlan) { d.Rollback = []string{"no snmp-server user tech ADMINS v3"} })
	check("reversa en orden inverso", func(d *DevicePlan) {
		d.Rollback = []string{"no snmp-server group ADMINS v3 priv", "no snmp-server user tech ADMINS v3"}
	})
	check("reversa de otro usuario", func(d *DevicePlan) {
		d.Rollback = []string{"no snmp-server user otro ADMINS v3", "no snmp-server group ADMINS v3 priv"}
	})
	check("el usuario ya existía", func(d *DevicePlan) { d.Baseline[snmpUserCmd] = "User name: tech\nGroup-name: LECT\n" })
	check("el grupo ya existía y la reversa lo borra", func(d *DevicePlan) { d.Baseline[snmpGroupCmd] = "snmp-server group ADMINS v3 priv\n" })
	check("sin línea base del usuario", func(d *DevicePlan) { delete(d.Baseline, snmpUserCmd) })
}

func TestSNMPv3NeverShowsTheSecrets(t *testing.T) {
	tpl := mustTemplate(t, "snmpv3-usuario")
	dp, err := l3Plan(t, "snmpv3-usuario", v3Vals(), newL3())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(dp.Secrets, v3Auth) || !slices.Contains(dp.Secrets, v3Priv) || !tpl.Fn.Scrub {
		t.Fatalf("Secrets = %v, Scrub = %v", dp.Secrets, tpl.Fn.Scrub)
	}
	red := Redact(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{dp}}, tpl.Fn)
	for _, s := range []string{v3Auth, v3Priv} {
		noLeak(t, s, "el plan redactado", fmt.Sprintf("%+v", red))
		noLeak(t, s, "Notes", dp.Notes...)
		noLeak(t, s, "DescribeValues", DescribeValues(tpl, v3Vals()))
	}
	// Los rechazos del plan tampoco los citan.
	has := newL3()
	has.users = []string{"tech LECT"}
	_, err = l3Plan(t, "snmpv3-usuario", v3Vals(), has)
	noLeak(t, v3Auth, "el rechazo", fmt.Sprint(err))
	noLeak(t, v3Priv, "el rechazo", fmt.Sprint(err))
}

// ---- ejecución completa contra el modelo ----

// l3Run arma una ejecución del motor sobre el modelo del equipo: leer responde del modelo y configurar lo modifica.
func l3Run(t *testing.T, id string, v Values, dev *l3Dev, onCfg func(lines []string) []string) (*Run, *auditRec) {
	t.Helper()
	dp, err := l3Plan(t, id, v, dev)
	if err != nil {
		t.Fatal(err)
	}
	tpl := mustTemplate(t, id)
	var mu sync.Mutex
	fx := &fakeExec{echo: true}
	fx.readFunc = func(_, cmd string) string { mu.Lock(); defer mu.Unlock(); return dev.read([]string{cmd})[cmd] }
	fx.onConfigure = func(_ string, lines []string) {
		mu.Lock()
		defer mu.Unlock()
		if onCfg != nil {
			lines = onCfg(lines)
		}
		dev.apply(lines)
	}
	a := &auditRec{}
	r, err := NewRun(Options{ID: "run1", Plan: Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{dp}}, Fn: tpl.Fn, Assisted: true, Exec: fx, Audit: a.add})
	if err != nil {
		t.Fatal(err)
	}
	return r, a
}

// toRollback lleva la ejecución hasta confirmar la reversa y la deja esperando su resultado.
func toRollback(t *testing.T, r *Run) {
	t.Helper()
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "close")
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
}

func allEvents(r *Run) string {
	evs, _ := r.Events(0)
	var b strings.Builder
	for _, e := range evs {
		b.WriteString(e.Text + "\n")
	}
	return b.String()
}

func TestSNMPv3RunVerifiesTheReversaWithShowSnmpUser(t *testing.T) {
	// Camino bueno: la reversa quita el usuario y el grupo, y la ejecución llega a rolled-back.
	dev := newL3()
	r, a := l3Run(t, "snmpv3-usuario", v3Vals(), dev, nil)
	toRollback(t, r)
	wait(t, r, RolledBack)
	if len(dev.users) != 0 || len(dev.global) != 0 {
		t.Fatalf("quedó %v %v", dev.users, dev.global)
	}
	for _, s := range []string{v3Auth, v3Priv} {
		noLeak(t, s, "la auditoría", a.text())
		noLeak(t, s, "los eventos", allEvents(r))
	}
	// Una reversa que no logra quitar el usuario no se da por cumplida: show snmp user lo delata aunque el running quede igual.
	dev = newL3()
	r, a = l3Run(t, "snmpv3-usuario", v3Vals(), dev, func(lines []string) []string {
		return slices.DeleteFunc(slices.Clone(lines), func(l string) bool { return strings.HasPrefix(l, "no snmp-server user") })
	})
	toRollback(t, r)
	wait(t, r, Failed)
	if reason := r.FailReason(); !strings.Contains(reason, "no lo dejó como estaba") || !strings.Contains(reason, "User name") {
		t.Fatalf("motivo %q", r.FailReason())
	}
	for _, s := range []string{v3Auth, v3Priv} {
		noLeak(t, s, "el motivo", r.FailReason())
		noLeak(t, s, "la auditoría", a.text())
		noLeak(t, s, "los eventos", allEvents(r))
	}
	if len(r.Changed()) != 1 {
		t.Errorf("el equipo no debe contarse como revertido: %v", r.Changed())
	}
}

func TestSNMPCommunityRunNeverLeaksTheCommunity(t *testing.T) {
	// El equipo no aplica la community: el post-check falla y el motivo, la auditoría y los eventos no la citan.
	dev := newL3()
	r, a := l3Run(t, "snmp-community", Values{"community": comm}, dev, func([]string) []string { return nil })
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	wait(t, r, Failed)
	if !strings.Contains(r.FailReason(), "post-check") {
		t.Fatalf("motivo %q", r.FailReason())
	}
	noLeak(t, comm, "el motivo", r.FailReason())
	noLeak(t, comm, "la auditoría", a.text())
	noLeak(t, comm, "los eventos", allEvents(r))
	// Una reversa que la deja puesta: el residuo la enmascara.
	dev = newL3()
	r, a = l3Run(t, "snmp-community", Values{"community": comm}, dev, func(lines []string) []string {
		return slices.DeleteFunc(slices.Clone(lines), func(l string) bool { return strings.HasPrefix(l, "no snmp-server") })
	})
	toRollback(t, r)
	wait(t, r, Failed)
	if !strings.Contains(r.FailReason(), "sobra") {
		t.Fatalf("motivo %q", r.FailReason())
	}
	noLeak(t, comm, "el motivo", r.FailReason())
	noLeak(t, comm, "la auditoría", a.text())
	noLeak(t, comm, "los eventos", allEvents(r))
}

// ---- vty-acl ----

const mgmtACL = "Standard IP access list MGMT\n    10 permit 10.0.0.0, wildcard bits 0.0.0.255 (4 matches)\n    20 deny   any\n"

// vtyDev es un equipo cuya sesión de la app viene de 10.0.0.50 y que tiene los bloques vty dados.
func vtyDev(acl string, blocks ...string) *l3Dev {
	d := newL3()
	for _, b := range blocks {
		d.addVty(b, "transport input ssh", "login local")
	}
	if acl != "" {
		d.acls["MGMT"] = acl
	}
	return d
}

func vtyVals(lines string) Values { return Values{"acl": "MGMT", "lines": lines} }

func TestVtyACLEmptyStateRollbackIsNo(t *testing.T) {
	dev := vtyDev(mgmtACL, "line vty 0 4", "line vty 5 15")
	dp := l3RoundTrip(t, "vty-acl", vtyVals("0 4"), dev)
	if got := joined(dp.Apply); got != "line vty 0 4|access-class MGMT in" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "line vty 0 4|no access-class MGMT in" {
		t.Errorf("Rollback = %s", got)
	}
	if strings.Contains(joined(dev.vty[1].lines), "access-class") {
		t.Errorf("tocó el otro bloque: %v", dev.vty[1].lines)
	}
	// 0 15 sobre dos bloques: cada uno con su propio encabezado, y la reversa en orden inverso.
	dev = vtyDev(mgmtACL, "line vty 0 4", "line vty 5 15")
	dp = l3RoundTrip(t, "vty-acl", vtyVals("0 15"), dev)
	if got := joined(dp.Apply); got != "line vty 0 4|access-class MGMT in|line vty 5 15|access-class MGMT in" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "line vty 5 15|no access-class MGMT in|line vty 0 4|no access-class MGMT in" {
		t.Errorf("Rollback = %s", got)
	}
	// 0 15 sobre un solo bloque 0 15.
	dp = l3RoundTrip(t, "vty-acl", vtyVals("0 15"), vtyDev(mgmtACL, "line vty 0 15"))
	if joined(dp.Apply) != "line vty 0 15|access-class MGMT in" {
		t.Errorf("Apply = %s", joined(dp.Apply))
	}
	if len(dp.Notes) == 0 || !strings.Contains(dp.Notes[0], "10.0.0.50") {
		t.Errorf("la nota debe decir la IP validada: %v", dp.Notes)
	}
}

func TestVtyACLAlreadyThere(t *testing.T) {
	has := vtyDev(mgmtACL)
	has.addVty("line vty 0 4", "access-class MGMT in", "login local")
	l3Nothing(t, "ya estaba", "vty-acl", vtyVals("0 4"), has)
	// Si uno de los bloques ya la tiene, solo se toca el otro.
	half := vtyDev(mgmtACL)
	half.addVty("line vty 0 4", "access-class MGMT in", "login local")
	half.addVty("line vty 5 15", "login local")
	dp := l3RoundTrip(t, "vty-acl", vtyVals("0 15"), half)
	if joined(dp.Apply) != "line vty 5 15|access-class MGMT in" || joined(dp.Rollback) != "line vty 5 15|no access-class MGMT in" {
		t.Errorf("%v %v", dp.Apply, dp.Rollback)
	}
	if !slices.Contains(half.vty[0].lines, "access-class MGMT in") {
		t.Errorf("la reversa quitó la ACL que ya estaba: %v", half.vty[0].lines)
	}
}

func TestVtyACLRefusals(t *testing.T) {
	v := vtyVals("0 4")
	other := vtyDev(mgmtACL)
	other.addVty("line vty 0 4", "access-class OTRA in", "login local")
	l3Refused(t, "otro access-class in", "vty-acl", v, other)
	outOnly := vtyDev(mgmtACL)
	outOnly.addVty("line vty 0 4", "access-class OTRA out")
	l3RoundTrip(t, "vty-acl", v, outOnly) // un `out` no estorba
	l3Refused(t, "uno de los bloques con otro access-class", "vty-acl", vtyVals("0 15"), func() *l3Dev {
		d := vtyDev(mgmtACL, "line vty 0 4")
		d.addVty("line vty 5 15", "access-class OTRA in")
		return d
	}())
	l3Refused(t, "sin bloques vty", "vty-acl", v, vtyDev(mgmtACL))
	l3Refused(t, "bloque que se parte en el rango", "vty-acl", v, vtyDev(mgmtACL, "line vty 0 15"))
	if _, err := l3Plan(t, "vty-acl", v, vtyDev(mgmtACL, "line vty 0 15")); err == nil || !strings.Contains(err.Error(), "desborda") {
		t.Errorf("el motivo debe decir que el bloque desborda el rango: %v", err)
	}
	l3Refused(t, "bloques con hueco", "vty-acl", vtyVals("0 15"), vtyDev(mgmtACL, "line vty 0 4", "line vty 10 15"))
	l3Refused(t, "bloques que no llegan al final", "vty-acl", vtyVals("0 15"), vtyDev(mgmtACL, "line vty 0 4"))
	hide := vtyDev(mgmtACL, "line vty 0 4")
	hide.hide[vtyCmd] = true
	l3Refused(t, "vty ilegible", "vty-acl", v, hide)
}

func TestVtyACLRefusesAnACLThatWouldLockTheSessionOut(t *testing.T) {
	blocks := []string{"line vty 0 4"}
	for name, c := range map[string]struct {
		acl    string
		accept bool
	}{
		"permit de su red":                  {mgmtACL, true},
		"permit de su host":                 {"Standard IP access list MGMT\n    10 permit 10.0.0.50\n", true},
		"permit host":                       {"Standard IP access list MGMT\n    10 permit host 10.0.0.50\n    20 deny any\n", true},
		"permit any":                        {"Standard IP access list MGMT\n    10 permit any\n", true},
		"permit antes de un deny que cubre": {"Standard IP access list MGMT\n    10 permit 10.0.0.50\n    20 deny any\n", true},
		"deny explícito de su host antes":   {"Standard IP access list MGMT\n    10 deny   host 10.0.0.50\n    20 permit any\n", false},
		"deny de su red antes del permit":   {"Standard IP access list MGMT\n    10 deny   10.0.0.0, wildcard bits 0.0.0.255\n    20 permit any\n", false},
		"no la menciona (deny implícito)":   {"Standard IP access list MGMT\n    10 permit 192.168.1.0, wildcard bits 0.0.0.255\n", false},
		"solo otro host":                    {"Standard IP access list MGMT\n    10 permit host 10.0.0.51\n", false},
		"vacía":                             {"Standard IP access list MGMT\n", false},
		"solo deny any":                     {"Standard IP access list MGMT\n    10 deny any\n", false},
		"extendida":                         {"Extended IP access list MGMT\n    10 permit tcp any any eq 22\n", false},
		"inexistente":                       {"", false},
		"ilegible":                          {"Standard IP access list MGMT\n    10 permit raro raro\n", false},
		"el permit es de una red vecina":    {"Standard IP access list MGMT\n    10 permit 10.0.1.0, wildcard bits 0.0.0.255\n", false},
	} {
		dev := vtyDev(c.acl, blocks...)
		_, err := l3Plan(t, "vty-acl", vtyVals("0 4"), dev)
		if c.accept && err != nil {
			t.Errorf("%s: rechazada: %v", name, err)
		}
		if !c.accept && !errors.Is(err, ErrSnippetRefused) {
			t.Errorf("%s: debía rechazarse y dio %v", name, err)
		}
		for n, want := range map[string]string{"deny explícito de su host antes": "dejaría fuera", "extendida": "extendida", "inexistente": "no existe", "no la menciona (deny implícito)": "dejaría fuera"} {
			if name == n && !c.accept && !strings.Contains(err.Error(), want) {
				t.Errorf("%s: el motivo debe decir %q: %v", name, want, err)
			}
		}
	}
}

func TestVtyACLRefusesWhenTheIPTheDeviceSeesIsUnknown(t *testing.T) {
	const open = "Standard IP access list MGMT\n    10 permit any\n"
	for name, seen := range map[string]string{"show users no la muestra": "", "no es una IP": "no-se", "0.0.0.0": "0.0.0.0"} {
		dev := vtyDev(open, "line vty 0 4")
		dev.seen = seen
		if seen == "no-se" || seen == "0.0.0.0" {
			dev.hide["show users"] = true
		}
		dp, err := l3Plan(t, "vty-acl", vtyVals("0 4"), dev)
		if !errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), "IP de origen") {
			t.Errorf("%s: debía rechazarse por no saber la IP de origen y dio %v %v", name, dp.Apply, err)
		}
	}
	// Una IPv6 de origen no se puede comprobar contra una ACL IPv4.
	v6 := vtyDev(open, "line vty 0 4")
	v6.seen = "2001:db8::50"
	if _, err := l3Plan(t, "vty-acl", vtyVals("0 4"), v6); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("origen IPv6: %v", err)
	}
	// Sin show users en las salidas (el servicio no lo leyó) tampoco se supone.
	tpl := mustTemplate(t, "vty-acl")
	dev := vtyDev(open, "line vty 0 4")
	pre, _ := tpl.Pre(vtyVals("0 4"))
	outs := dev.read(pre)
	delete(outs, "show users")
	if _, err := tpl.Plan("SW1", vtyVals("0 4"), outs); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("sin show users: %v", err)
	}
	// Que la IP local de la app no se conozca no estorba si el equipo sí dice la suya.
	dev = vtyDev(open, "line vty 0 4")
	dev.src = ""
	l3RoundTrip(t, "vty-acl", vtyVals("0 4"), dev)
}

// Revisión de 28d: con NAT o VPN la IP local de la app no es la que el equipo ve; la ACL debe permitir la que ve y también la local si difiere.
func TestVtyACLChecksTheIPTheDeviceSeesAndTheLocalOne(t *testing.T) {
	cases := map[string]struct {
		acl    string
		accept bool
		why    string
	}{
		"permite las dos":           {"Standard IP access list MGMT\n    10 permit 203.0.113.9\n    20 permit 10.0.0.50\n", true, ""},
		"solo la local":             {"Standard IP access list MGMT\n    10 permit 10.0.0.50\n", false, "que ve el equipo (203.0.113.9)"},
		"solo la que ve el equipo":  {"Standard IP access list MGMT\n    10 permit 203.0.113.9\n", false, "local de la sesión (10.0.0.50)"},
		"permit any":                {"Standard IP access list MGMT\n    10 permit any\n", true, ""},
		"niega la que ve el equipo": {"Standard IP access list MGMT\n    10 deny 203.0.113.9\n    20 permit any\n", false, "que ve el equipo"},
	}
	for name, c := range cases {
		dev := vtyDev(c.acl, "line vty 0 4")
		dev.seen = "203.0.113.9" // NAT: la app sale desde 10.0.0.50
		dp, err := l3Plan(t, "vty-acl", vtyVals("0 4"), dev)
		switch {
		case c.accept && err != nil:
			t.Errorf("%s: rechazada: %v", name, err)
		case !c.accept && (!errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), c.why)):
			t.Errorf("%s: debía rechazarse diciendo %q y dio %v", name, c.why, err)
		case c.accept && (len(dp.Notes) == 0 || !strings.Contains(dp.Notes[0], "203.0.113.9") || !strings.Contains(dp.Notes[0], "10.0.0.50")):
			t.Errorf("%s: la nota debe decir las dos IP: %v", name, dp.Notes)
		}
	}
}

// Revisión de 28d: si la ACL cambia entre planear y confirmar, el motor lo detecta; los contadores de matches no cuentan como cambio.
func TestVtyACLRunDetectsTheACLChangingBeforeApplying(t *testing.T) {
	dev := vtyDev(mgmtACL, "line vty 0 4")
	r, _ := l3Run(t, "vty-acl", vtyVals("0 4"), dev, nil)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	// Solo suben los contadores: sigue igual.
	dev.acls["MGMT"] = strings.Replace(mgmtACL, "(4 matches)", "(57 matches)", 1)
	if err := r.Confirm("apply-1"); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "close")
	// La ACL cambia y deja fuera a la sesión: no se aplica nada.
	dev = vtyDev(mgmtACL, "line vty 0 4")
	r, _ = l3Run(t, "vty-acl", vtyVals("0 4"), dev, nil)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	dev.acls["MGMT"] = "Standard IP access list MGMT\n    10 deny any\n"
	r.Confirm("apply-1")
	wait(t, r, Failed)
	if reason := r.FailReason(); !strings.Contains(reason, "cambió") || !strings.Contains(reason, "show ip access-lists MGMT") {
		t.Fatalf("motivo %q", reason)
	}
	if len(dev.vty[0].lines) != 2 || strings.Contains(joined(dev.vty[0].lines), "access-class") {
		t.Errorf("se aplicó algo: %v", dev.vty[0].lines)
	}
}

func TestVtyACLValidationAndClosedList(t *testing.T) {
	tpl := mustTemplate(t, "vty-acl")
	for name, v := range map[string]Values{
		"líneas inválidas": vtyVals("0 98"), "líneas vacías": {"acl": "MGMT"}, "sin ACL": {"lines": "0 4"}, "ACL con espacio": {"acl": "dos palabras", "lines": "0 4"},
		"ACL con inyección": {"acl": "MGMT;reload", "lines": "0 4"},
	} {
		if err := ValidateValues(tpl, v); err == nil {
			t.Errorf("%s aceptado", name)
		}
	}
	fn := SnippetVtyACL
	for _, l := range []string{"line vty 0 98", "line vty 5 1", "line con 0", "line vty 0 4 7", "access-class MGMT out", "access-class MGMT in vrf-also", "access-class MGMT",
		"transport input telnet", "login", "no access-class MGMT out", "no line vty 0 4", "password x"} {
		if err := fn.configLine(l); err == nil {
			t.Errorf("%q aceptada", l)
		}
	}
	for _, l := range []string{"line vty 0 4", "line vty 5 15", "access-class MGMT in", "access-class 10 in", "no access-class MGMT in"} {
		if err := fn.configLine(l); err != nil {
			t.Errorf("%q rechazada: %v", l, err)
		}
	}
}

func TestVtyACLCheckDeviceRejectsAnUnsoundPlan(t *testing.T) {
	tpl := mustTemplate(t, "vty-acl")
	dp, err := l3Plan(t, "vty-acl", vtyVals("0 15"), vtyDev(mgmtACL, "line vty 0 4", "line vty 5 15"))
	if err != nil {
		t.Fatal(err)
	}
	check := func(what string, mod func(*DevicePlan)) {
		t.Helper()
		bad := dp
		bad.Rollback, bad.Apply = slices.Clone(dp.Rollback), slices.Clone(dp.Apply)
		bad.Baseline = map[string]string{vtyCmd: dp.Baseline[vtyCmd]}
		mod(&bad)
		if err := Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{bad}}, tpl.Fn); err == nil {
			t.Errorf("%s: aceptado", what)
		}
	}
	check("reversa en el mismo orden", func(d *DevicePlan) {
		d.Rollback = []string{"line vty 0 4", "no access-class MGMT in", "line vty 5 15", "no access-class MGMT in"}
	})
	check("reversa que olvida un bloque", func(d *DevicePlan) { d.Rollback = []string{"line vty 5 15", "no access-class MGMT in"} })
	check("reversa de otra ACL", func(d *DevicePlan) {
		d.Rollback = []string{"line vty 5 15", "no access-class OTRA in", "line vty 0 4", "no access-class OTRA in"}
	})
	check("dos ACL distintas", func(d *DevicePlan) { d.Apply[3] = "access-class OTRA in" })
	check("el bloque ya tenía access-class in", func(d *DevicePlan) { d.Baseline[vtyCmd] = "line vty 0 4\n access-class OTRA in\nline vty 5 15\n" })
	check("el bloque no existe en la línea base", func(d *DevicePlan) { d.Baseline[vtyCmd] = "line vty 0 4\n" })
	check("sin línea base", func(d *DevicePlan) { delete(d.Baseline, vtyCmd) })
	check("apply sin access-class", func(d *DevicePlan) { d.Apply = []string{"line vty 0 4"} })
}

// Revisión de 28d: las lecturas de vty-acl y ntp-server traen secretos ajenos (contraseña de línea, llave NTP); la función los limpia.
func TestVtyACLAndNTPRunNeverEmitForeignSecretsFromReads(t *testing.T) {
	const pw, key = "0822455D0A16", "SuperNtpKey"
	d := newL3()
	d.addVty("line vty 0 4", "password 7 "+pw, "login", "transport input ssh")
	d.acls["MGMT"] = mgmtACL
	r, a := l3Run(t, "vty-acl", vtyVals("0 4"), d, nil)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	noLeak(t, pw, "los eventos de vty-acl", allEvents(r))
	noLeak(t, pw, "la auditoría de vty-acl", a.text())
	n := newL3("ntp authentication-key 1 md5 "+key+" 7", "ntp trusted-key 1")
	r, a = l3Run(t, "ntp-server", Values{"address": "10.1.1.1"}, n, nil)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	noLeak(t, key, "los eventos de ntp-server", allEvents(r))
	noLeak(t, key, "la auditoría de ntp-server", a.text())
	for _, id := range []string{"vty-acl", "ntp-server"} {
		if !mustTemplate(t, id).Fn.Scrub {
			t.Errorf("%s: su función debe limpiar lo que lee", id)
		}
	}
}
