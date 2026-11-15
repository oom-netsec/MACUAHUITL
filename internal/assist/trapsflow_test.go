package assist

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Modelo de IOS armado con la documentación de Cisco, sin validar en laboratorio.

// ---- snmp-trap-host ----

const (
	trapHostLine = "snmp-server host 10.1.1.5 version 2c " + comm + " udp-port 162"
	trapSnmp     = "snmp-server enable traps snmp linkdown linkup coldstart"
	trapCfg      = "snmp-server enable traps config"
)

func trapVals(extra ...string) Values {
	v := Values{"address": "10.1.1.5", "community": comm}
	for i := 0; i+1 < len(extra); i += 2 {
		v[extra[i]] = extra[i+1]
	}
	return v
}

func TestTrapHostEmptyStateRollbackRemovesCommunityToo(t *testing.T) {
	dev := newL3("snmp-server community otra RO", "snmp-server location Lab")
	dp := l3RoundTrip(t, "snmp-trap-host", trapVals(), dev)
	if got := joined(dp.Apply); got != trapHostLine+"|"+trapSnmp+"|"+trapCfg {
		t.Errorf("Apply = %s", got)
	}
	// IOS crea la community en silencio como RO al nombrarla en el host: si no existía, la reversa la quita al final.
	if got := joined(dp.Rollback); got != "no "+trapCfg+"|no "+trapSnmp+"|no "+trapHostLine+"|no snmp-server community "+comm {
		t.Errorf("Rollback = %s", got)
	}
	if !slices.Equal(dev.global, []string{"snmp-server community otra RO", "snmp-server location Lab"}) {
		t.Errorf("la reversa tocó otra cosa: %v", dev.global)
	}
}

func TestTrapHostExistingCommunityAndTrapsAreLeftAlone(t *testing.T) {
	dev := newL3("snmp-server community "+comm+" RO 10", "snmp-server enable traps snmp authentication linkdown", trapCfg)
	dp := l3RoundTrip(t, "snmp-trap-host", trapVals("port", "1162"), dev)
	// linkdown y config ya estaban: solo se agregan (y se quitan) linkup y coldstart; la community existente no se toca.
	if got := joined(dp.Apply); got != "snmp-server host 10.1.1.5 version 2c "+comm+" udp-port 1162|snmp-server enable traps snmp linkup coldstart" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "no snmp-server enable traps snmp linkup coldstart|no snmp-server host 10.1.1.5 version 2c "+comm+" udp-port 1162" {
		t.Errorf("Rollback = %s", got)
	}
	want := []string{"snmp-server community " + comm + " RO 10", "snmp-server enable traps snmp authentication linkdown", trapCfg}
	if !slices.Equal(dev.global, want) {
		t.Errorf("tras la reversa: %v", dev.global)
	}
}

func TestTrapHostTrapsChoice(t *testing.T) {
	for _, c := range []struct{ traps, apply string }{
		{"snmp", trapHostLine + "|" + trapSnmp},
		{"config", trapHostLine + "|" + trapCfg},
		{"snmp+config", trapHostLine + "|" + trapSnmp + "|" + trapCfg},
		{"", trapHostLine + "|" + trapSnmp + "|" + trapCfg}, // la omisión es snmp+config
	} {
		dp := l3RoundTrip(t, "snmp-trap-host", trapVals("traps", c.traps), newL3("snmp-server community "+comm+" RO"))
		if got := joined(dp.Apply); got != c.apply {
			t.Errorf("traps=%q: Apply = %s", c.traps, got)
		}
	}
	// Todos los traps ya activos (o la forma sin familia): solo el host.
	for _, have := range [][]string{{"snmp-server enable traps snmp authentication linkdown linkup warmstart coldstart", trapCfg}, {"snmp-server enable traps"}, {"snmp-server enable traps snmp", trapCfg}} {
		dp := l3RoundTrip(t, "snmp-trap-host", trapVals(), newL3(append(have, "snmp-server community "+comm+" RO")...))
		if len(dp.Apply) != 1 || len(dp.Rollback) != 1 {
			t.Errorf("con %v: Apply = %v Rollback = %v", have, dp.Apply, dp.Rollback)
		}
	}
}

func TestTrapHostRefusals(t *testing.T) {
	l3Refused(t, "host existente", "snmp-trap-host", trapVals(), newL3("snmp-server host 10.1.1.5 version 2c otra"))
	l3Refused(t, "host existente con otro puerto", "snmp-trap-host", trapVals(), newL3("snmp-server host 10.1.1.5 version 2c otra udp-port 1162"))
	l3Refused(t, "salida ilegible", "snmp-trap-host", trapVals(), func() *l3Dev { d := newL3(); d.hide[snmpAllCmd] = true; return d }())
	if _, err := l3Plan(t, "snmp-trap-host", trapVals("address", "10.1.1.6"), newL3("snmp-server host 10.1.1.5 version 2c otra")); err != nil {
		t.Errorf("otro host no debe rechazar: %v", err)
	}
}

func TestTrapHostValidation(t *testing.T) {
	tpl := mustTemplate(t, "snmp-trap-host")
	for name, v := range map[string]Values{
		"sin address":        {"community": comm},
		"address multicast":  trapVals("address", "224.0.0.9"),
		"address loopback":   trapVals("address", "127.0.0.1"),
		"puerto 0":           trapVals("port", "0"),
		"puerto 65536":       trapVals("port", "65536"),
		"community corta":    trapVals("community", "abc"),
		"community con @":    trapVals("community", "abc@vlan10"),
		"sin community":      {"address": "10.1.1.5"},
		"traps desconocido":  trapVals("traps", "todos"),
		"campo desconocido":  trapVals("version", "3"),
		"community con '?'":  trapVals("community", "abc?def"),
		"community con tab":  trapVals("community", "ab\tcd"),
		"community de 33":    trapVals("community", strings.Repeat("a", 33)),
		"address con inyec.": trapVals("address", "10.1.1.5;reload"),
	} {
		err := ValidateValues(tpl, v)
		if err == nil {
			_, err = tpl.Pre(v)
		}
		if err == nil {
			t.Errorf("%s aceptado", name)
		}
	}
	if err := ValidateValues(tpl, trapVals("port", "65535", "traps", "snmp")); err != nil {
		t.Error(err)
	}
	// El puerto por omisión es 162.
	dp, err := l3Plan(t, "snmp-trap-host", trapVals(), newL3())
	if err != nil || !strings.Contains(dp.Apply[0], "udp-port 162") {
		t.Errorf("%v %v", dp.Apply, err)
	}
}

func TestTrapHostFunctionClosedList(t *testing.T) {
	fn := SnippetTrapHost
	if !fn.Scrub {
		t.Error("la función debe limpiar lo que IOS imprime tras la community")
	}
	for _, l := range []string{
		"snmp-server community " + comm + " RO", "snmp-server community " + comm + " RW", "no snmp-server community", "no snmp-server community a@b",
		"snmp-server host 10.1.1.5 " + comm, "snmp-server host 10.1.1.5 version 3 priv " + comm, "snmp-server host 10.1.1.5 version 2c " + comm,
		"snmp-server host 10.1.1.5 version 2c " + comm + " udp-port 0", "snmp-server host 10.1.1.5 version 2c abc udp-port 162",
		"snmp-server host 224.0.0.1 version 2c " + comm + " udp-port 162", "snmp-server host 10.1.1.5 informs version 2c " + comm + " udp-port 162",
		"snmp-server enable traps", "snmp-server enable traps snmp", "snmp-server enable traps snmp authentication", "snmp-server enable traps bgp",
		"snmp-server enable traps snmp linkdown linkdown", "snmp-server enable traps config extra", "snmp-server enable traps snmp coldstart linkup linkdown",
		"snmp-server location x", "snmp-server user u g v3",
	} {
		if err := fn.configLine(l); err == nil {
			t.Errorf("%q aceptada", l)
		}
	}
	for _, l := range []string{trapHostLine, trapSnmp, trapCfg, "no " + trapHostLine, "no " + trapSnmp, "no " + trapCfg,
		"snmp-server enable traps snmp linkup", "no snmp-server community " + comm} {
		if err := fn.configLine(l); err != nil {
			t.Errorf("%q rechazada: %v", l, err)
		}
	}
}

// La reversa exacta se exige aunque alguien arme el plan a mano.
func TestTrapHostRollbackIsExact(t *testing.T) {
	tpl := mustTemplate(t, "snmp-trap-host")
	good, err := l3Plan(t, "snmp-trap-host", trapVals(), newL3())
	if err != nil {
		t.Fatal(err)
	}
	check := func(what string, mut func(d *DevicePlan)) {
		t.Helper()
		d := good
		d.Rollback, d.Apply, d.Baseline = slices.Clone(good.Rollback), slices.Clone(good.Apply), map[string]string{snmpAllCmd: good.Baseline[snmpAllCmd]}
		mut(&d)
		if err := Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{d}}, tpl.Fn); err == nil {
			t.Errorf("%s: plan aceptado", what)
		}
	}
	check("sin quitar la community creada", func(d *DevicePlan) { d.Rollback = d.Rollback[:len(d.Rollback)-1] })
	check("community quitada antes que el host", func(d *DevicePlan) {
		n := len(d.Rollback)
		d.Rollback[n-1], d.Rollback[n-2] = d.Rollback[n-2], d.Rollback[n-1]
	})
	check("sin quitar el host", func(d *DevicePlan) { d.Rollback = slices.Delete(d.Rollback, 2, 3) })
	check("reversa del host con otro puerto", func(d *DevicePlan) { d.Rollback[2] = strings.Replace(d.Rollback[2], "162", "163", 1) })
	check("sin quitar los traps agregados", func(d *DevicePlan) { d.Rollback = slices.Delete(d.Rollback, 0, 1) })
	check("reversa en el mismo orden que el apply", func(d *DevicePlan) { d.Rollback[0], d.Rollback[1] = d.Rollback[1], d.Rollback[0] })
	check("línea base ya con el host", func(d *DevicePlan) { d.Baseline[snmpAllCmd] = "snmp-server host 10.1.1.5 version 2c x\n" })
	// Con la community y los traps ya en el equipo, quitar de más rompe lo que había.
	have, _ := l3Plan(t, "snmp-trap-host", trapVals(), newL3("snmp-server community "+comm+" RO", trapCfg))
	d := have
	d.Rollback = append(slices.Clone(have.Rollback), "no snmp-server community "+comm)
	if err := Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{d}}, tpl.Fn); err == nil {
		t.Error("la reversa quita una community que ya existía")
	}
	d = have
	d.Apply, d.Rollback = append(slices.Clone(have.Apply), trapCfg), append([]string{"no " + trapCfg}, have.Rollback...)
	if err := Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{d}}, tpl.Fn); err == nil {
		t.Error("la reversa quita un trap que ya estaba")
	}
}

func TestTrapHostNeverShowsTheCommunity(t *testing.T) {
	tpl := mustTemplate(t, "snmp-trap-host")
	_, err := l3Plan(t, "snmp-trap-host", trapVals(), newL3("snmp-server host 10.1.1.5 version 2c "+comm))
	noLeak(t, comm, "el rechazo por host existente", fmt.Sprint(err))
	noLeak(t, comm, "el error de ValidateValues", fmt.Sprint(ValidateValues(tpl, trapVals("community", comm+" con espacio"))))
	_, err = tpl.Pre(trapVals("community", comm+"@10"))
	noLeak(t, comm, "el error de Pre", fmt.Sprint(err))
	dp, err := l3Plan(t, "snmp-trap-host", trapVals(), newL3())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(dp.Secrets, comm) {
		t.Fatalf("Secrets = %v", dp.Secrets)
	}
	noLeak(t, comm, "Notes", dp.Notes...)
	for _, e := range dp.Expect {
		noLeak(t, comm, "Expect", e.Line)
	}
	red := Redact(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{dp}}, tpl.Fn)
	noLeak(t, comm, "el plan redactado", fmt.Sprintf("%+v", red))
	// Lo que falla en el post-check tampoco la cita.
	dev := newL3("snmp-server community "+comm+" RO", "snmp-server location Lab")
	noLeak(t, comm, "los fallos del post-check", EvalExpect(dp.Expect, dev.read(dp.Post))...)
	bad := dp
	bad.Rollback = []string{"no snmp-server host 10.1.1.9 version 2c " + comm + " udp-port 162"}
	err = Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{bad}}, tpl.Fn)
	if err == nil {
		t.Fatal("reversa de otro host aceptada")
	}
	noLeak(t, comm, "el error de Validate", err.Error())
}

func TestTrapHostPostCheckDetectsMissingHost(t *testing.T) {
	dp, _ := l3Plan(t, "snmp-trap-host", trapVals(), newL3())
	dev := newL3(trapSnmp, trapCfg) // los traps sin el host
	if fails := EvalExpect(dp.Expect, dev.read(dp.Post)); len(fails) != 1 {
		t.Errorf("fallos = %v", fails)
	}
	dev = newL3("snmp-server host 10.1.1.5 version 2c x", "snmp-server enable traps snmp linkdown", trapCfg) // solo uno de los tres traps de snmp
	if fails := EvalExpect(dp.Expect, dev.read(dp.Post)); len(fails) != 1 {
		t.Errorf("traps de snmp incompletos: %v", fails)
	}
	dev = newL3("snmp-server host 10.1.1.5 version 2c x udp-port 1162", trapCfg) // el host con otro puerto, sin los traps de snmp
	if fails := EvalExpect(dp.Expect, dev.read(dp.Post)); len(fails) != 2 {
		t.Errorf("fallos = %v", fails)
	}
}

// ---- netflow-export ----

const (
	nfIf   = "GigabitEthernet1/0/5"
	nfHead = "flow record MX-REC|match ipv4 protocol|match ipv4 source address|match ipv4 destination address|match transport source-port|match transport destination-port|" +
		"collect counter bytes long|collect counter packets long|flow exporter MX-EXP|destination 10.2.2.2|transport udp 2055|export-protocol netflow-v9|"
	nfTail = "flow monitor MX-MON|record MX-REC|exporter MX-EXP|cache timeout active 60|interface " + nfIf + "|ip flow monitor MX-MON input"
	nfBack = "interface " + nfIf + "|no ip flow monitor MX-MON input|no flow monitor MX-MON|no flow exporter MX-EXP|no flow record MX-REC"
)

func nfVals(extra ...string) Values {
	v := Values{"address": "10.2.2.2", "interface": nfIf}
	for i := 0; i+1 < len(extra); i += 2 {
		v[extra[i]] = extra[i+1]
	}
	return v
}

func nfDev() *l3Dev {
	d := newL3()
	d.ifaces[nfIf] = []string{"switchport mode access", "description PC"}
	d.ifaces["Vlan1"] = []string{"ip address 10.0.0.9 255.255.255.0"}
	d.flows = []*vtyBlk{{head: "flow exporter OTRO", lines: []string{"destination 10.9.9.9"}}}
	return d
}

func TestNetflowRoundTripExactSteps(t *testing.T) {
	dev := nfDev()
	dp := l3RoundTrip(t, "netflow-export", nfVals(), dev)
	if got := joined(dp.Apply); got != nfHead+nfTail {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != nfBack {
		t.Errorf("Rollback = %s", got)
	}
	if len(dev.flows) != 1 || dev.flows[0].head != "flow exporter OTRO" || !slices.Equal(dev.ifaces[nfIf], []string{"switchport mode access", "description PC"}) {
		t.Errorf("la reversa tocó otra cosa: %v %v", dev.flows, dev.ifaces[nfIf])
	}
	// Con puerto y source el exporter los lleva, el source al final.
	dp = l3RoundTrip(t, "netflow-export", nfVals("port", "9996", "source", "Vlan1"), nfDev())
	if got := joined(dp.Apply); !strings.Contains(got, "destination 10.2.2.2|transport udp 9996|export-protocol netflow-v9|source Vlan1|flow monitor MX-MON") {
		t.Errorf("Apply = %s", got)
	}
	if joined(dp.Rollback) != nfBack {
		t.Errorf("Rollback = %s", joined(dp.Rollback))
	}
}

func TestNetflowRefusals(t *testing.T) {
	for name, mk := range map[string]func(d *l3Dev){
		"record existente":     func(d *l3Dev) { d.flows = append(d.flows, &vtyBlk{head: "flow record MX-REC"}) },
		"exporter existente":   func(d *l3Dev) { d.flows = append(d.flows, &vtyBlk{head: "flow exporter MX-EXP"}) },
		"monitor existente":    func(d *l3Dev) { d.flows = append(d.flows, &vtyBlk{head: "flow monitor MX-MON"}) },
		"interfaz con monitor": func(d *l3Dev) { d.ifaces[nfIf] = append(d.ifaces[nfIf], "ip flow monitor OTRO input") },
		"interfaz inexistente": func(d *l3Dev) { delete(d.ifaces, nfIf) },
		"flow ilegible":        func(d *l3Dev) { d.hide[flowCmd] = true },
		"interfaz ilegible":    func(d *l3Dev) { d.hide[showCfg(nfIf)] = true },
	} {
		d := nfDev()
		mk(d)
		l3Refused(t, name, "netflow-export", nfVals(), d)
	}
	l3Refused(t, "source inexistente", "netflow-export", nfVals("source", "Vlan99"), nfDev())
	// Un monitor de salida de la interfaz no impide el de entrada.
	d := nfDev()
	d.ifaces[nfIf] = append(d.ifaces[nfIf], "ip flow monitor OTRO output")
	if _, err := l3Plan(t, "netflow-export", nfVals(), d); err != nil {
		t.Errorf("monitor de salida: %v", err)
	}
}

func TestNetflowValidation(t *testing.T) {
	tpl := mustTemplate(t, "netflow-export")
	for name, v := range map[string]Values{
		"sin address":       {"interface": nfIf},
		"sin interfaz":      {"address": "10.2.2.2"},
		"Vlan":              nfVals("interface", "Vlan10"),
		"Port-channel":      nfVals("interface", "Port-channel1"),
		"Loopback":          nfVals("interface", "Loopback0"),
		"Tunnel":            nfVals("interface", "Tunnel0"),
		"subinterfaz":       nfVals("interface", "GigabitEthernet0/0.10"),
		"address multicast": nfVals("address", "224.0.0.5"),
		"puerto 0":          nfVals("port", "0"),
		"puerto 70000":      nfVals("port", "70000"),
		"source inválida":   nfVals("source", "Vlan1;reload"),
		"campo output":      nfVals("direction", "output"),
	} {
		err := ValidateValues(tpl, v)
		if err == nil {
			_, err = tpl.Pre(v)
		}
		if err == nil {
			t.Errorf("%s aceptado", name)
		}
	}
	if err := ValidateValues(tpl, nfVals("source", "Vlan1", "interface", "Gi1/0/5")); err != nil {
		t.Error(err)
	}
}

func TestNetflowFunctionClosedList(t *testing.T) {
	fn := SnippetNetflow
	for _, l := range []string{
		"flow exporter OTRO", "flow record OTRO", "no flow monitor OTRO", "ip flow monitor MX-MON output", "ip flow monitor OTRO input", "no flow record",
		"destination 224.0.0.1", "transport tcp 2055", "transport udp 0", "export-protocol ipfix", "export-protocol netflow-v5", "match ipv4 ttl", "collect counter bytes",
		"cache timeout active 3600", "record OTRO", "exporter OTRO", "source Vlan1;reload", "no destination 10.2.2.2", "no match ipv4 protocol", "interface Vlan10",
		"no interface Gi1/0/5", "interface Port-channel1", "ip flow ingress", "flow hardware", "sampler X", "no ip flow monitor MX-MON output",
	} {
		if err := fn.configLine(l); err == nil {
			t.Errorf("%q aceptada", l)
		}
	}
	for _, l := range strings.Split(nfHead+nfTail+"|"+nfBack+"|source Vlan1|transport udp 65535", "|") {
		if err := fn.configLine(l); err != nil {
			t.Errorf("%q rechazada: %v", l, err)
		}
	}
}

// La reversa exacta y en orden inverso se exige aunque alguien arme el plan a mano.
func TestNetflowRollbackIsExactAndReversed(t *testing.T) {
	tpl := mustTemplate(t, "netflow-export")
	good, err := l3Plan(t, "netflow-export", nfVals("source", "Vlan1"), nfDev())
	if err != nil {
		t.Fatal(err)
	}
	check := func(what string, mut func(d *DevicePlan)) {
		t.Helper()
		d := good
		d.Rollback, d.Apply, d.Baseline = slices.Clone(good.Rollback), slices.Clone(good.Apply), map[string]string{}
		for k, v := range good.Baseline {
			d.Baseline[k] = v
		}
		mut(&d)
		if err := Validate(Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{d}}, tpl.Fn); err == nil {
			t.Errorf("%s: plan aceptado", what)
		}
	}
	check("sin quitar el record", func(d *DevicePlan) { d.Rollback = d.Rollback[:len(d.Rollback)-1] })
	check("sin quitar el monitor de la interfaz", func(d *DevicePlan) { d.Rollback = slices.Delete(d.Rollback, 1, 2) })
	check("sin entrar a la interfaz", func(d *DevicePlan) { d.Rollback = slices.Delete(d.Rollback, 0, 1) })
	check("record antes que el monitor", func(d *DevicePlan) {
		n := len(d.Rollback)
		d.Rollback[n-1], d.Rollback[n-3] = d.Rollback[n-3], d.Rollback[n-1]
	})
	check("exporter antes que el monitor", func(d *DevicePlan) { d.Rollback[2], d.Rollback[3] = d.Rollback[3], d.Rollback[2] })
	check("apply con el monitor antes del exporter", func(d *DevicePlan) {
		i, j := slices.Index(d.Apply, "flow exporter MX-EXP"), slices.Index(d.Apply, "flow monitor MX-MON")
		d.Apply[i], d.Apply[j] = d.Apply[j], d.Apply[i]
	})
	check("apply sin el cache timeout", func(d *DevicePlan) {
		d.Apply = slices.DeleteFunc(d.Apply, func(l string) bool { return strings.HasPrefix(l, "cache ") })
	})
	check("línea base con MX-EXP", func(d *DevicePlan) { d.Baseline[flowCmd] = "flow exporter MX-EXP\n destination 1.1.1.1\n" })
	check("línea base con monitor en la interfaz", func(d *DevicePlan) {
		d.Baseline[showCfg(nfIf)] = "interface " + nfIf + "\n ip flow monitor X input\n"
	})
}

func TestNetflowPostCheck(t *testing.T) {
	dev := nfDev()
	dp := l3RoundTrip(t, "netflow-export", nfVals(), dev)
	dev.apply(dp.Apply)
	if fails := EvalExpect(dp.Expect, dev.read(dp.Post)); len(fails) != 0 {
		t.Fatalf("fallos con todo aplicado: %v", fails)
	}
	// Sin el monitor en la interfaz, o con el exporter apuntando a otro destino, falla.
	dev.ifaces[nfIf] = slices.DeleteFunc(dev.ifaces[nfIf], func(l string) bool { return strings.HasPrefix(l, "ip flow monitor") })
	if fails := EvalExpect(dp.Expect, dev.read(dp.Post)); len(fails) != 1 {
		t.Errorf("sin monitor: %v", fails)
	}
	for _, b := range dev.flows {
		if b.head == "flow exporter MX-EXP" {
			b.lines[0] = "destination 10.7.7.7"
		}
	}
	if fails := EvalExpect(dp.Expect, dev.read(dp.Post)); len(fails) != 2 {
		t.Errorf("sin monitor y con otro destino: %v", fails)
	}
}

// ---- netflow-export: el uplink de una casa ----

// Bajo la interfaz el apply solo lleva el monitor: nada de shutdown, description ni otra línea.
func TestNetflowApplyOnlyTouchesTheMonitorOnTheInterface(t *testing.T) {
	dp, err := l3Plan(t, "netflow-export", nfVals("source", "Vlan1"), nfDev())
	if err != nil {
		t.Fatal(err)
	}
	i := slices.Index(dp.Apply, "interface "+nfIf)
	if i < 0 || !slices.Equal(dp.Apply[i:], []string{"interface " + nfIf, "ip flow monitor MX-MON input"}) {
		t.Fatalf("bajo la interfaz debe ir solo el monitor: %v", dp.Apply)
	}
	// Un plan manipulado con otra línea bajo la interfaz se rechaza con el motivo propio.
	tpl := mustTemplate(t, "netflow-export")
	for _, extra := range []string{"shutdown", "description x", "no shutdown"} {
		d := dp
		d.Apply = append(slices.Clone(dp.Apply), extra)
		err := tpl.Fn.CheckDevice(d)
		if err == nil || !strings.Contains(err.Error(), "bajo la interfaz") {
			t.Errorf("%q bajo la interfaz: %v", extra, err)
		}
	}
}

// La reversa quita el monitor de la interfaz antes que cualquier `no flow`.
func TestNetflowRollbackRemovesInterfaceMonitorFirst(t *testing.T) {
	dp, err := l3Plan(t, "netflow-export", nfVals(), nfDev())
	if err != nil {
		t.Fatal(err)
	}
	if len(dp.Rollback) < 3 || dp.Rollback[0] != "interface "+nfIf || dp.Rollback[1] != "no ip flow monitor MX-MON input" {
		t.Fatalf("la reversa debe abrir con la interfaz y su monitor: %v", dp.Rollback)
	}
	for i, l := range dp.Rollback[2:] {
		if !strings.HasPrefix(l, "no flow ") {
			t.Errorf("línea %d de la reversa tras el monitor: %q", i+2, l)
		}
	}
}

// El pre-check rechaza una interfaz que no está up/up: si ya estaba caída, el post-check no distinguiría.
func TestNetflowRefusesInterfaceNotUp(t *testing.T) {
	for _, st := range []string{"notconnect", "disabled", "err-disabled", "inactive"} {
		d := nfDev()
		d.status = map[string]string{nfIf: st}
		_, err := l3Plan(t, "netflow-export", nfVals(), d)
		if !errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), st) {
			t.Errorf("%s: %v", st, err)
		}
	}
	d := nfDev()
	d.hide[showStatus(nfIf)] = true
	l3Refused(t, "estado ilegible", "netflow-export", nfVals(), d)
}

// Tras el apply la interfaz debe seguir up/up: si queda down o up/down (notconnect), el post-check falla.
func TestNetflowPostCheckInterfaceStaysUp(t *testing.T) {
	dev := nfDev()
	dp := l3RoundTrip(t, "netflow-export", nfVals(), dev)
	dev.apply(dp.Apply)
	if !slices.Contains(dp.Post, showStatus(nfIf)) {
		t.Fatalf("el post no lee el estado de la interfaz: %v", dp.Post)
	}
	for _, st := range []string{"notconnect", "disabled", "err-disabled"} {
		dev.status = map[string]string{nfIf: st}
		fails := EvalExpect(dp.Expect, dev.read(dp.Post))
		if len(fails) != 1 || !strings.Contains(fails[0], st) {
			t.Errorf("%s: %v", st, fails)
		}
	}
}
