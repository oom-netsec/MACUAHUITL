package assist

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// l3Dev es un modelo mínimo de cómo IOS guarda el lote L3 y gestión de la fase 28d: líneas globales en el orden en que se aplicaron,
// interfaces, bloques vty, usuarios SNMPv3 (que show snmp user muestra y el running no), ACL y el banner mostrado con ^C. Es un modelo de
// la documentación de Cisco, sin validar en laboratorio.
type l3Dev struct {
	global []string
	ifaces map[string][]string
	vty    []*vtyBlk
	users  []string          // «usuario grupo»
	acls   map[string]string // salida de show ip access-lists NOMBRE
	l2     map[string]bool   // puertos con switchport habilitado
	oldLog bool              // IOS 12.x: «logging IP» en vez de «logging host IP»
	src    string            // IP local de la sesión
	seen   string            // IP de origen que el equipo ve en show users (con NAT difiere de src); vacía = show users no la muestra
	hide   map[string]bool   // comandos que contestan con un aviso de error
}

type vtyBlk struct {
	head  string
	lines []string
}

func newL3(global ...string) *l3Dev {
	return &l3Dev{global: global, ifaces: map[string][]string{}, acls: map[string]string{}, l2: map[string]bool{}, hide: map[string]bool{}, src: "10.0.0.50", seen: "10.0.0.50"}
}

func (d *l3Dev) addVty(head string, lines ...string) { d.vty = append(d.vty, &vtyBlk{head, lines}) }

func (d *l3Dev) removeGlobal(match func(string) bool) {
	d.global = slices.DeleteFunc(d.global, match)
}

func (d *l3Dev) apply(lines []string) {
	ctx, blk := "", (*vtyBlk)(nil)
	var iface string
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "interface "):
			iface, ctx, blk = strings.TrimPrefix(l, "interface "), "if", nil
			if _, ok := d.ifaces[iface]; !ok {
				d.ifaces[iface] = nil
			}
			continue
		case strings.HasPrefix(l, "no interface "):
			delete(d.ifaces, strings.TrimPrefix(l, "no interface "))
			ctx = ""
			continue
		case strings.HasPrefix(l, "line vty "):
			ctx, blk = "vty", nil
			for _, b := range d.vty {
				if b.head == l {
					blk = b
				}
			}
			if blk == nil {
				blk = &vtyBlk{head: l}
				d.vty = append(d.vty, blk)
			}
			continue
		}
		body, neg := strings.CutPrefix(l, "no ")
		switch ctx {
		case "if":
			cur := d.ifaces[iface]
			switch {
			case neg:
				d.ifaces[iface] = slices.DeleteFunc(cur, func(x string) bool { return x == body })
			case strings.HasPrefix(body, "ip address ") || strings.HasPrefix(body, "description "):
				k := strings.Fields(body)[0]
				cur = slices.DeleteFunc(cur, func(x string) bool { return strings.HasPrefix(x, k+" ") })
				d.ifaces[iface] = append(cur, body)
			case !slices.Contains(cur, body):
				d.ifaces[iface] = append(cur, body)
			}
		case "vty":
			if strings.HasPrefix(body, "access-class ") {
				blk.lines = slices.DeleteFunc(blk.lines, func(x string) bool {
					return neg && x == body || !neg && strings.HasPrefix(x, "access-class ") && strings.HasSuffix(x, " in")
				})
			}
			if !neg {
				blk.lines = append(blk.lines, body)
			}
		default:
			d.applyGlobal(body, neg)
		}
	}
}

func (d *l3Dev) applyGlobal(body string, neg bool) {
	f := strings.Fields(body)
	switch {
	case neg && body == "banner motd":
		d.removeGlobal(func(x string) bool { return strings.HasPrefix(x, "banner motd ") })
	case !neg && f[0] == "banner":
		text := strings.TrimSuffix(strings.TrimPrefix(body, "banner motd #"), "#")
		d.removeGlobal(func(x string) bool { return strings.HasPrefix(x, "banner motd ") })
		d.global = append(d.global, "banner motd ^C"+text+"^C")
	case neg && len(f) >= 5 && f[0] == "ip" && f[1] == "route": // «no ip route R M NH [AD]» borra la ruta de ese salto
		key := strings.Join(f[:5], " ")
		d.removeGlobal(func(x string) bool { return hasWordPrefix(x, key) })
	case neg && len(f) == 3 && f[0] == "ntp" && f[1] == "server":
		d.removeGlobal(func(x string) bool { return hasWordPrefix(x, body) })
	case neg && len(f) == 3 && f[0] == "logging" && f[1] == "host":
		d.removeGlobal(func(x string) bool { return x == body || x == "logging "+f[2] })
	case !neg && len(f) == 3 && f[0] == "logging" && f[1] == "host" && d.oldLog:
		d.global = append(d.global, "logging "+f[2])
	case f[0] == "logging" && f[1] == "trap" || neg && body == "logging trap":
		d.removeGlobal(func(x string) bool { return hasWordPrefix(x, "logging trap") || x == "no logging trap" })
		if neg { // varias versiones dejan `no logging trap` en el running: el syslog queda apagado
			d.global = append(d.global, "no logging trap")
		} else if f[2] != "informational" { // el nivel de fábrica no se muestra
			d.global = append(d.global, body)
		}
	case neg && f[0] == "snmp-server" && f[1] == "community":
		d.removeGlobal(func(x string) bool { return hasWordPrefix(x, "snmp-server community "+f[2]) })
	case f[0] == "snmp-server" && f[1] == "user" && !neg: // IOS no lo escribe en el running
		d.users = append(d.users, f[2]+" "+f[3])
	case f[0] == "snmp-server" && f[1] == "user" && neg:
		d.users = slices.DeleteFunc(d.users, func(x string) bool { return x == f[2]+" "+f[3] })
	case neg:
		d.removeGlobal(func(x string) bool { return x == body })
	case !slices.Contains(d.global, body):
		d.global = append(d.global, body)
	}
}

func (d *l3Dev) cfg(n string) string {
	l, ok := d.ifaces[n]
	if !ok {
		return "                 ^\n% Invalid input detected at '^' marker.\n"
	}
	return "Building configuration...\n\nCurrent configuration : 100 bytes\n!\ninterface " + n + "\n " + strings.Join(l, "\n ") + "\nend\n"
}

func (d *l3Dev) brief() string {
	out := "Interface              IP-Address      OK? Method Status                Protocol\n"
	for n, l := range d.ifaces {
		ip := "unassigned"
		for _, x := range l {
			if a, ok := strings.CutPrefix(x, "ip address "); ok {
				ip = strings.Fields(a)[0]
			}
		}
		out += fmt.Sprintf("%-22s %-15s YES manual up                    up\n", n, ip)
	}
	return out
}

func (d *l3Dev) read(cmds []string) map[string]string {
	out := map[string]string{}
	for _, c := range cmds {
		if d.hide[c] {
			out[c] = "% Invalid input detected at '^' marker.\n"
			continue
		}
		switch {
		case strings.HasPrefix(c, "show running-config | include "):
			re := regexp.MustCompile(strings.TrimPrefix(c, "show running-config | include "))
			s := ""
			for _, g := range d.global {
				if re.MatchString(g) {
					s += g + "\n"
				}
			}
			out[c] = s
		case c == vtyCmd:
			s := ""
			for _, b := range d.vty {
				s += b.head + "\n"
				for _, x := range b.lines {
					s += " " + x + "\n"
				}
			}
			out[c] = s
		case c == bannerCmd:
			s := ""
			for _, g := range d.global {
				if strings.HasPrefix(g, "banner motd ") {
					s += g + "\n"
				}
			}
			out[c] = s
		case strings.HasPrefix(c, "show running-config interface "):
			out[c] = d.cfg(strings.TrimPrefix(c, "show running-config interface "))
		case c == showIPBrief:
			out[c] = d.brief()
		case c == snmpUserCmd:
			s := ""
			for _, u := range d.users {
				f := strings.Fields(u)
				s += "User name: " + f[0] + "\nEngine ID: 800000090300AABBCCDDEEFF\nstorage-type: nonvolatile        active\nAuthentication Protocol: SHA\nPrivacy Protocol: AES128\nGroup-name: " + f[1] + "\n\n"
			}
			out[c] = s
		case c == "show users":
			s := "    Line       User       Host(s)              Idle       Location\n   0 con 0                idle                 00:00:00\n"
			if d.seen != "" {
				s += "*  2 vty 0     admin      idle                 00:00:00 " + d.seen + "\n"
			}
			out[c] = s
		case strings.HasPrefix(c, "show ip access-lists "):
			out[c] = d.acls[strings.TrimPrefix(c, "show ip access-lists ")]
		case strings.HasSuffix(c, " switchport"):
			n := strings.TrimSuffix(strings.TrimPrefix(c, "show interfaces "), " switchport")
			if d.l2[n] {
				out[c] = "Name: " + n + "\nSwitchport: Enabled\nAdministrative Mode: static access\nOperational Mode: static access\n"
			} else {
				out[c] = "Name: " + n + "\nSwitchport: Disabled\n"
			}
		}
	}
	out[SessionSourceKey] = d.src
	return out
}

// l3Plan planea con el estado del equipo sin aplicar.
func l3Plan(t *testing.T, id string, v Values, dev *l3Dev) (DevicePlan, error) {
	t.Helper()
	tpl, ok := TemplateByID(id)
	if !ok {
		t.Fatalf("no hay plantilla %s", id)
	}
	if err := ValidateValues(tpl, v); err != nil {
		return DevicePlan{}, err
	}
	pre, err := tpl.Pre(v)
	if err != nil {
		return DevicePlan{}, err
	}
	return tpl.Plan("SW1", v, dev.read(pre))
}

// l3RoundTrip planea, aplica, comprueba lo esperado, aplica la reversa y exige que cada comando de configuración de la línea base
// (los mismos que compara run.go: runningCmds) quede idéntico. Devuelve el plan.
func l3RoundTrip(t *testing.T, id string, v Values, dev *l3Dev) DevicePlan {
	t.Helper()
	dp, err := l3Plan(t, id, v, dev)
	if err != nil {
		t.Fatal(err)
	}
	tpl, _ := TemplateByID(id)
	if err := Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{dp}}, tpl.Fn); err != nil {
		t.Fatal(err)
	}
	for cmd := range dp.Baseline {
		if !slices.Contains(dp.Pre, cmd) {
			t.Errorf("la línea base cita %q, que Pre no lee: el plan caducaría siempre", cmd)
		}
	}
	dev.apply(dp.Apply)
	if fails := EvalExpect(dp.Expect, dev.read(dp.Post)); len(fails) > 0 {
		t.Errorf("tras aplicar: %v", fails)
	}
	dev.apply(dp.Rollback)
	for cmd := range dp.Baseline { // lo único que checkBase no compara es la ACL de vty-acl, que el motor vigila como deriva
		if !slices.Contains(runningCmds(dp), cmd) && !strings.HasPrefix(cmd, "show ip access-lists ") {
			t.Errorf("la línea base trae %q, que checkBase no compara", cmd)
		}
	}
	for _, cmd := range runningCmds(dp) {
		if d := residue(dp.Baseline[cmd], dev.read([]string{cmd})[cmd]); d != "" {
			t.Errorf("la reversa no dejó %q como estaba: %s", cmd, d)
		}
	}
	return dp
}

func l3Refused(t *testing.T, what, id string, v Values, dev *l3Dev) {
	t.Helper()
	if _, err := l3Plan(t, id, v, dev); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("%s: debía rechazarse con ErrSnippetRefused y dio %v", what, err)
	}
}

func l3Nothing(t *testing.T, what, id string, v Values, dev *l3Dev) {
	t.Helper()
	if _, err := l3Plan(t, id, v, dev); err == nil || !strings.Contains(err.Error(), "nada que cambiar") {
		t.Errorf("%s: debía decir que no hay nada que cambiar y dio %v", what, err)
	}
}

// ---- ruta-estatica ----

func routeVals(extra ...string) Values {
	v := Values{"network": "10.1.0.0", "mask": "255.255.0.0", "next_hop": "10.0.0.1"}
	for i := 0; i+1 < len(extra); i += 2 {
		v[extra[i]] = extra[i+1]
	}
	return v
}

func TestRouteEmptyStateRollbackIsNo(t *testing.T) {
	dev := newL3("ip route 10.9.0.0 255.255.0.0 10.0.0.9")
	dp := l3RoundTrip(t, "ruta-estatica", routeVals("distance", "5", "name", "LAB"), dev)
	if got := joined(dp.Apply); got != "ip route 10.1.0.0 255.255.0.0 10.0.0.1 5 name LAB" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "no ip route 10.1.0.0 255.255.0.0 10.0.0.1 5" {
		t.Errorf("Rollback = %s", got)
	}
	// Sin distancia ni nombre, y la distancia de fábrica (1) no se escribe: IOS no la muestra.
	dp = l3RoundTrip(t, "ruta-estatica", routeVals("distance", "1"), newL3())
	if joined(dp.Apply) != "ip route 10.1.0.0 255.255.0.0 10.0.0.1" || joined(dp.Rollback) != "no ip route 10.1.0.0 255.255.0.0 10.0.0.1" {
		t.Errorf("%v %v", dp.Apply, dp.Rollback)
	}
	// Solo interfaz de salida.
	dp = l3RoundTrip(t, "ruta-estatica", Values{"network": "10.4.0.0", "mask": "255.255.255.0", "exit_interface": "Null0"}, newL3())
	if joined(dp.Apply) != "ip route 10.4.0.0 255.255.255.0 Null0" || joined(dp.Rollback) != "no ip route 10.4.0.0 255.255.255.0 Null0" {
		t.Errorf("%v %v", dp.Apply, dp.Rollback)
	}
}

func TestRouteSecondNextHopToTheSameNetworkIsAllowed(t *testing.T) {
	dev := newL3("ip route 10.1.0.0 255.255.0.0 10.0.0.9")
	dp := l3RoundTrip(t, "ruta-estatica", routeVals("distance", "200"), dev) // ruta flotante
	if joined(dp.Rollback) != "no ip route 10.1.0.0 255.255.0.0 10.0.0.1 200" {
		t.Errorf("Rollback = %s", joined(dp.Rollback))
	}
	if !slices.Contains(dev.global, "ip route 10.1.0.0 255.255.0.0 10.0.0.9") {
		t.Errorf("la reversa tocó la otra ruta: %v", dev.global)
	}
}

func TestRouteAlreadyThereAndRefusals(t *testing.T) {
	l3Nothing(t, "ya estaba", "ruta-estatica", routeVals("distance", "5", "name", "LAB"), newL3("ip route 10.1.0.0 255.255.0.0 10.0.0.1 5 name LAB"))
	l3Nothing(t, "ya estaba sin atributos", "ruta-estatica", routeVals(), newL3("ip route 10.1.0.0 255.255.0.0 10.0.0.1"))
	l3Refused(t, "otra distancia", "ruta-estatica", routeVals("distance", "5"), newL3("ip route 10.1.0.0 255.255.0.0 10.0.0.1 10"))
	l3Refused(t, "otro nombre", "ruta-estatica", routeVals("name", "NUEVO"), newL3("ip route 10.1.0.0 255.255.0.0 10.0.0.1 name VIEJO"))
	l3Refused(t, "sin atributos sobre una con tag", "ruta-estatica", routeVals(), newL3("ip route 10.1.0.0 255.255.0.0 10.0.0.1 tag 7"))
	l3Refused(t, "salida ilegible", "ruta-estatica", routeVals(), func() *l3Dev { d := newL3(); d.hide[routeCmd] = true; return d }())
	l3Refused(t, "línea de ruta que no se entiende", "ruta-estatica", routeVals(), newL3("ip route profile"))
}

func TestRouteValidation(t *testing.T) {
	tpl, _ := TemplateByID("ruta-estatica")
	for name, v := range map[string]Values{
		"ruta por defecto":            {"network": "0.0.0.0", "mask": "0.0.0.0", "next_hop": "10.0.0.1"},
		"máscara no contigua":         routeVals("mask", "255.0.255.0"),
		"distancia 0":                 routeVals("distance", "0"),
		"distancia 256":               routeVals("distance", "256"),
		"nombre con espacio":          routeVals("name", "dos palabras"),
		"campo desconocido":           routeVals("tag", "5"),
		"interfaz con caracteres":     routeVals("exit_interface", "Gi1/0/1;reload"),
		"falta la red":                {"mask": "255.255.0.0", "next_hop": "10.0.0.1"},
		"salto no es IPv4":            routeVals("next_hop", "fe80::1"),
		"distancia con signo":         routeVals("distance", "+5"),
		"interfaz con salto de línea": routeVals("exit_interface", "Null0\nreload"),
	} {
		if err := ValidateValues(tpl, v); err == nil {
			t.Errorf("%s aceptado", name)
		}
	}
	// Lo que depende de varios campos lo dice Pre (antes de conectar).
	for name, v := range map[string]Values{
		"sin salto ni interfaz":   {"network": "10.1.0.0", "mask": "255.255.0.0"},
		"bits de host en la red":  routeVals("network", "10.1.0.5"),
		"salto multicast":         routeVals("next_hop", "224.0.0.5"),
		"salto 0.0.0.0":           routeVals("next_hop", "0.0.0.0"),
		"red por defecto con /32": {"network": "0.0.0.0", "mask": "255.255.255.255", "next_hop": "10.0.0.1"},
		"salto en la propia red":  routeVals("next_hop", "10.1.0.0"),
	} {
		if err := ValidateValues(tpl, v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := tpl.Pre(v); err == nil {
			t.Errorf("%s aceptado por Pre", name)
		}
	}
}

func TestRouteCheckDeviceRejectsAReversaThatIsNotTheExactNo(t *testing.T) {
	tpl, _ := TemplateByID("ruta-estatica")
	dp, err := l3Plan(t, "ruta-estatica", routeVals("distance", "5", "name", "LAB"), newL3())
	if err != nil {
		t.Fatal(err)
	}
	check := func(what string, mod func(*DevicePlan)) {
		t.Helper()
		bad := dp
		bad.Rollback = slices.Clone(dp.Rollback)
		bad.Baseline = map[string]string{routeCmd: dp.Baseline[routeCmd]}
		mod(&bad)
		if err := Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{bad}}, tpl.Fn); err == nil {
			t.Errorf("%s: aceptado", what)
		}
	}
	check("reversa de otra ruta", func(d *DevicePlan) { d.Rollback = []string{"no ip route 10.1.0.0 255.255.0.0 10.0.0.2 5"} })
	check("reversa sin la distancia", func(d *DevicePlan) { d.Rollback = []string{"no ip route 10.1.0.0 255.255.0.0 10.0.0.1"} })
	check("reversa que borra una red entera", func(d *DevicePlan) { d.Rollback = []string{"no ip route 10.1.0.0 255.255.0.0"} })
	check("reversa doble", func(d *DevicePlan) { d.Rollback = append(d.Rollback, "no ip route 10.9.0.0 255.255.0.0 10.0.0.9") })
	check("la ruta ya existía en la línea base", func(d *DevicePlan) { d.Baseline[routeCmd] = "ip route 10.1.0.0 255.255.0.0 10.0.0.1 10\n" })
	check("ruta por defecto", func(d *DevicePlan) {
		d.Apply = []string{"ip route 0.0.0.0 0.0.0.0 10.0.0.1"}
		d.Rollback = []string{"no ip route 0.0.0.0 0.0.0.0 10.0.0.1"}
	})
	check("otro comando", func(d *DevicePlan) { d.Apply = []string{"ip routing"} })
}

// Revisión de 28d: una ruta (o la subred de una loopback) que contiene la IP de origen secuestra el regreso de la sesión SSH.
func TestRouteAndLoopbackRefuseToCoverTheSessionOrigin(t *testing.T) {
	dev := func(seen, src string) *l3Dev {
		d := newL3()
		d.seen, d.src = seen, src
		return d
	}
	covering := Values{"network": "10.0.0.0", "mask": "255.255.255.0", "exit_interface": "Null0"}
	l3Refused(t, "ruta que cubre la IP que ve el equipo", "ruta-estatica", covering, dev("10.0.0.50", "192.0.2.7"))
	l3Refused(t, "ruta que cubre la IP local (NAT)", "ruta-estatica", covering, dev("203.0.113.9", "10.0.0.50"))
	l3Refused(t, "ruta a un host que es el origen", "ruta-estatica", Values{"network": "10.0.0.50", "mask": "255.255.255.255", "next_hop": "10.9.9.9"}, dev("10.0.0.50", "10.0.0.50"))
	l3Refused(t, "origen desconocido", "ruta-estatica", routeVals(), dev("", "10.0.0.50"))
	if _, err := l3Plan(t, "ruta-estatica", covering, dev("10.0.0.50", "192.0.2.7")); err == nil || !strings.Contains(err.Error(), "10.0.0.50") {
		t.Errorf("el motivo debe decir la IP cubierta: %v", err)
	}
	l3RoundTrip(t, "ruta-estatica", routeVals(), dev("10.0.5.5", "10.0.5.5")) // 10.1.0.0/16 no la cubre
	loop := Values{"number": "9", "address": "10.0.0.1", "mask": "255.255.255.0"}
	l3Refused(t, "loopback cuya subred cubre la IP que ve el equipo", "loopback", loop, dev("10.0.0.50", "192.0.2.7"))
	l3Refused(t, "loopback cuya subred cubre la IP local", "loopback", loop, dev("203.0.113.9", "10.0.0.77"))
	l3Refused(t, "loopback con la IP del origen", "loopback", loopVals("address", "10.0.0.50"), dev("10.0.0.50", "10.0.0.50"))
	l3Refused(t, "loopback con origen desconocido", "loopback", loopVals(), dev("", "10.0.0.50"))
	l3RoundTrip(t, "loopback", loopVals(), dev("10.0.0.50", "10.0.0.50")) // /32 de otra dirección
	// Un origen IPv6 no choca con una ruta o subred IPv4.
	l3RoundTrip(t, "ruta-estatica", routeVals(), dev("2001:db8::50", "2001:db8::50"))
}

// ---- loopback ----

func loopVals(extra ...string) Values {
	v := Values{"number": "5", "address": "10.255.0.1", "mask": "255.255.255.255"}
	for i := 0; i+1 < len(extra); i += 2 {
		v[extra[i]] = extra[i+1]
	}
	return v
}

func TestLoopbackEmptyStateRollbackRemovesTheInterface(t *testing.T) {
	dev := newL3()
	dev.ifaces["Vlan10"] = []string{"ip address 10.0.10.1 255.255.255.0"}
	dp := l3RoundTrip(t, "loopback", loopVals("description", "Router-ID"), dev)
	if got := joined(dp.Apply); got != "interface Loopback5|description Router-ID|ip address 10.255.0.1 255.255.255.255" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "no interface Loopback5" {
		t.Errorf("Rollback = %s", got)
	}
	if _, ok := dev.ifaces["Loopback5"]; ok {
		t.Error("la reversa no borró la loopback")
	}
	dp = l3RoundTrip(t, "loopback", loopVals("number", "0", "mask", "255.255.255.0", "address", "10.8.0.1"), newL3())
	if joined(dp.Apply) != "interface Loopback0|ip address 10.8.0.1 255.255.255.0" {
		t.Errorf("Apply = %s", joined(dp.Apply))
	}
}

func TestLoopbackRefusals(t *testing.T) {
	existing := newL3()
	existing.ifaces["Loopback5"] = []string{"ip address 10.7.7.7 255.255.255.255"}
	l3Refused(t, "loopback existente", "loopback", loopVals(), existing)
	bare := newL3()
	bare.ifaces["Loopback5"] = nil
	l3Refused(t, "loopback existente sin configuración", "loopback", loopVals(), bare)
	dup := newL3()
	dup.ifaces["Vlan10"] = []string{"ip address 10.255.0.1 255.255.255.0"}
	l3Refused(t, "IP repetida", "loopback", loopVals(), dup)
	unread := newL3()
	unread.hide[showIPBrief] = true
	l3Refused(t, "tabla de IP ilegible", "loopback", loopVals(), unread)
	// La captura que no es ni la interfaz ni el aviso de que no existe tampoco se toma por «no existe».
	odd := newL3()
	pre, _ := mustTemplate(t, "loopback").Pre(loopVals())
	outs := odd.read(pre)
	outs[showCfg("Loopback5")] = "algo raro\n"
	if _, err := mustTemplate(t, "loopback").Plan("SW1", loopVals(), outs); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("captura rara: %v", err)
	}
}

func mustTemplate(t *testing.T, id string) Template {
	t.Helper()
	tpl, ok := TemplateByID(id)
	if !ok {
		t.Fatalf("no hay plantilla %s", id)
	}
	return tpl
}

func TestLoopbackValidation(t *testing.T) {
	tpl := mustTemplate(t, "loopback")
	for name, v := range map[string]Values{
		"número negativo":               loopVals("number", "-1"),
		"número enorme":                 loopVals("number", "2147483648"),
		"con ceros":                     loopVals("number", "05"),
		"sin IP":                        {"number": "5", "mask": "255.255.255.0"},
		"descripción con interrogación": loopVals("description", "a?b"),
	} {
		if err := ValidateValues(tpl, v); err == nil {
			t.Errorf("%s aceptado", name)
		}
	}
	if err := ValidateValues(tpl, loopVals("number", "2147483647")); err != nil {
		t.Errorf("el tope: %v", err)
	}
	for name, v := range map[string]Values{
		"máscara más ancha que /8": loopVals("mask", "128.0.0.0"),
		"dirección de red":         loopVals("address", "10.8.0.0", "mask", "255.255.255.0"),
		"dirección de difusión":    loopVals("address", "10.8.0.255", "mask", "255.255.255.0"),
		"loopback del equipo":      loopVals("address", "127.0.0.1"),
		"multicast":                loopVals("address", "224.0.0.1"),
		"0.0.0.0":                  loopVals("address", "0.0.0.0"),
	} {
		if _, err := tpl.Pre(v); err == nil {
			t.Errorf("%s aceptado por Pre", name)
		}
	}
	if _, err := tpl.Pre(loopVals()); err != nil {
		t.Errorf("/32 en una dirección de host: %v", err)
	}
}

func TestLoopbackCheckDevice(t *testing.T) {
	tpl := mustTemplate(t, "loopback")
	dp, err := l3Plan(t, "loopback", loopVals(), newL3())
	if err != nil {
		t.Fatal(err)
	}
	check := func(what string, mod func(*DevicePlan)) {
		t.Helper()
		bad := dp
		mod(&bad)
		if err := Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{bad}}, tpl.Fn); err == nil {
			t.Errorf("%s: aceptado", what)
		}
	}
	check("reversa de otra loopback", func(d *DevicePlan) { d.Rollback = []string{"no interface Loopback6"} })
	check("reversa que borra una SVI", func(d *DevicePlan) { d.Rollback = []string{"no interface Vlan10"} })
	check("reversa que no borra", func(d *DevicePlan) { d.Rollback = []string{"interface Loopback5", "no ip address"} })
	check("apply sobre una Vlan", func(d *DevicePlan) { d.Apply = []string{"interface Vlan10", "ip address 10.255.0.1 255.255.255.255"} })
	check("apply con shutdown", func(d *DevicePlan) { d.Apply = append(slices.Clone(d.Apply), "shutdown") })
	check("apply con dos interfaces", func(d *DevicePlan) { d.Apply = append(slices.Clone(d.Apply), "interface Loopback6") })
	check("máscara de /7", func(d *DevicePlan) { d.Apply = []string{"interface Loopback5", "ip address 10.255.0.1 254.0.0.0"} })
}

// ---- helper-address ----

func helperVals(iface string) Values { return Values{"interface": iface, "address": "10.9.9.1"} }

func TestHelperAddressEmptyStateRollbackIsNo(t *testing.T) {
	dev := newL3()
	dev.ifaces["Vlan10"] = []string{"ip address 10.0.10.1 255.255.255.0", "ip helper-address 10.9.9.9"}
	dp := l3RoundTrip(t, "helper-address", helperVals("Vlan10"), dev)
	if got := joined(dp.Apply); got != "interface Vlan10|ip helper-address 10.9.9.1" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "interface Vlan10|no ip helper-address 10.9.9.1" {
		t.Errorf("Rollback = %s", got)
	}
	if !slices.Contains(dev.ifaces["Vlan10"], "ip helper-address 10.9.9.9") {
		t.Errorf("la reversa tocó el otro helper: %v", dev.ifaces["Vlan10"])
	}
	// Un puerto físico ruteado.
	dev = newL3()
	dev.ifaces[gi1] = []string{"no switchport", "ip address 10.0.20.1 255.255.255.0"}
	dp = l3RoundTrip(t, "helper-address", helperVals(gi1), dev)
	if joined(dp.Apply) != "interface "+gi1+"|ip helper-address 10.9.9.1" {
		t.Errorf("Apply = %s", joined(dp.Apply))
	}
}

func TestHelperAddressAlreadyThereAndRefusals(t *testing.T) {
	has := newL3()
	has.ifaces["Vlan10"] = []string{"ip address 10.0.10.1 255.255.255.0", "ip helper-address 10.9.9.1"}
	l3Nothing(t, "ya estaba", "helper-address", helperVals("Vlan10"), has)
	vrf := newL3()
	vrf.ifaces["Vlan10"] = []string{"ip address 10.0.10.1 255.255.255.0", "ip helper-address vrf RED 10.9.9.1"}
	l3Refused(t, "mismo helper con vrf", "helper-address", helperVals("Vlan10"), vrf)
	l3Refused(t, "interfaz inexistente", "helper-address", helperVals("Vlan10"), newL3())
	l2 := newL3()
	l2.ifaces[gi1] = []string{"switchport mode access"}
	l2.l2[gi1] = true
	l3Refused(t, "puerto de capa 2", "helper-address", helperVals(gi1), l2)
	member := newL3()
	member.ifaces[gi1] = []string{"no switchport", "channel-group 1 mode active"}
	l3Refused(t, "miembro de canal", "helper-address", helperVals(gi1), member)
}

func TestHelperAddressValidation(t *testing.T) {
	tpl := mustTemplate(t, "helper-address")
	for name, v := range map[string]Values{
		"loopback":    helperVals("Loopback0"),
		"con rango":   helperVals("Gi1/0/1-4"),
		"IP inválida": {"interface": "Vlan10", "address": "10.9.9"},
		"sin IP":      {"interface": "Vlan10"},
		"inyección":   helperVals("Vlan10;reload"),
		"túnel":       helperVals("Tunnel1"),
	} {
		// Lo que la forma del campo deja pasar (Loopback0, Tunnel1) lo corta Pre antes de conectar.
		if err := ValidateValues(tpl, v); err == nil {
			if _, err := tpl.Pre(v); err == nil {
				t.Errorf("%s aceptado", name)
			}
		}
	}
	for _, ok := range []string{"Vlan10", "vlan10", "Gi1/0/1", "GigabitEthernet1/0/1", "Port-channel2", "Gi1/0/1.20"} {
		if err := ValidateValues(tpl, helperVals(ok)); err != nil {
			t.Errorf("%s rechazado: %v", ok, err)
		}
	}
	if _, err := tpl.Pre(Values{"interface": "Vlan10", "address": "224.0.0.9"}); err == nil {
		t.Error("helper multicast aceptado")
	}
}
