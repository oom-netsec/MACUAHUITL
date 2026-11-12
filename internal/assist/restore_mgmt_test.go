package assist

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Switch L3 con `ip routing`: la sesión del núcleo (192.0.2.9) entra a la IP de Loopback0 y el tráfico de regreso sale por la SVI Vlan10,
// cuya VLAN 10 la llevan puertos de acceso (Gi1/0/1, 2, 4 y el uplink de acceso Gi1/0/48). La interfaz que lleva la IP local no es por donde
// entra la sesión.
func routedRunning() string {
	r := rep(reviewRunning, "hostname SW1\n", "hostname SW1\nip routing\n")
	r = rep(r, "interface Vlan99\n", "interface Loopback0\n ip address 10.99.99.1 255.255.255.255\n!\ninterface Vlan99\n")
	return rep(r, "interface Port-channel1\n", "interface GigabitEthernet1/0/48\n description UPLINK-ACCESO\n switchport access vlan 10\n switchport mode access\n!\n"+
		"interface GigabitEthernet1/0/30\n description MGMT-IF\n switchport mode access\n switchport voice vlan 20\n!\n"+
		"interface GigabitEthernet1/0/31\n description VOZ\n switchport access vlan 20\n switchport mode access\n!\n"+
		"interface GigabitEthernet1/0/32\n description SIN-VLAN\n switchport mode access\n!\n"+
		"interface Port-channel1\n")
}

const (
	cefVia10   = "192.0.2.0/24\n  nexthop 10.10.0.2 Vlan10\n"
	cefVia99   = "192.0.2.0/24\n  nexthop 192.0.2.254 Vlan99\n"
	routeVia10 = "Routing entry for 192.0.2.0/24\n  Known via \"ospf 1\", distance 110, metric 20, type intra area\n  Routing Descriptor Blocks:\n" +
		"  * 10.10.0.2, from 10.255.0.2, 00:10:12 ago, via Vlan10\n      Route metric is 20, traffic share count is 1\n"
)

// routedOuts son las lecturas de Pre: local es la IP del equipo a la que entra la sesión; cef y route, la salida hacia el origen (vacío = no hay).
func routedOuts(run, local, cef, route string) map[string]string {
	o := reviewOuts(run)
	o["show tcp brief"] = "TCB       Local Address               Foreign Address             (state)\n7F1A2B3C  " + local + ".22               192.0.2.9.51234             ESTAB\n"
	if cef != "" {
		o["show ip cef 192.0.2.9"] = cef
	}
	delete(o, "show ip route 192.0.2.9")
	if route != "" {
		o["show ip route 192.0.2.9"] = route
	}
	return o
}

func routedPlan(t *testing.T, mod func(string) string, outs map[string]string, c func(*RestoreChange)) (RestorePlan, error) {
	t.Helper()
	ch := RestoreChange{Backup: mod(routedRunning()), BackupSerial: "FOC0001A0AA"}
	if c != nil {
		c(&ch)
	}
	return RestoreDiffPlan("SW1", ch, outs)
}

func uplinkShutdown(b string) string {
	return rep(b, "description UPLINK-ACCESO\n switchport access vlan 10", "description UPLINK-ACCESO\n shutdown\n switchport access vlan 10")
}
func uplinkVlan20(b string) string {
	return rep(b, "description UPLINK-ACCESO\n switchport access vlan 10", "description UPLINK-ACCESO\n switchport access vlan 20")
}

func TestRestoreRoutedSwitchProtectsTheEgressInterfaceAndItsVlan(t *testing.T) {
	run := routedRunning()
	for name, outs := range map[string]map[string]string{
		"CEF":                       routedOuts(run, "10.99.99.1", cefVia10, ""),
		"ruta cuando CEF no existe": routedOuts(run, "10.99.99.1", "% IPv4 CEF not enabled\n", routeVia10),
	} {
		for mn, mod := range map[string]func(string) string{"shutdown": uplinkShutdown, "VLAN 20": uplinkVlan20} {
			p, err := routedPlan(t, mod, outs, nil)
			if !errors.Is(err, ErrRestoreRefused) || !strings.Contains(strings.ToLower(fmtRefused(p)+err.Error()), "gestión") {
				t.Errorf("%s / %s: el puerto de acceso con la VLAN de la SVI de salida (Vlan10) no se toca: err=%v apply=%q", name, mn, err, p.Device.Apply)
			}
		}
	}
	// Si la salida es por Vlan99 (la VLAN 99 es la protegida), el puerto de la VLAN 10 sí se puede restaurar.
	if p, err := routedPlan(t, uplinkShutdown, routedOuts(run, "10.99.99.1", cefVia99, ""), nil); err != nil {
		t.Errorf("con la salida por Vlan99 el uplink de la VLAN 10 se puede restaurar: %v %s", err, fmtRefused(p))
	}
	// Y la interfaz que lleva la IP local sigue protegida aunque no sea la salida.
	back := rep(run, "ip address 10.99.99.1 255.255.255.255", "ip address 10.99.99.2 255.255.255.255")
	if _, err := RestoreDiffPlan("SW1", RestoreChange{Backup: back, BackupSerial: "FOC0001A0AA"}, routedOuts(run, "10.99.99.1", cefVia99, "")); !errors.Is(err, ErrRestoreRefused) {
		t.Errorf("Loopback0 lleva la IP de la sesión: %v", err)
	}
}

func TestRestoreRoutedSwitchWithoutACertainEgressNeedsMgmtIf(t *testing.T) {
	run := routedRunning()
	for name, outs := range map[string]map[string]string{
		"sin CEF ni ruta":         routedOuts(run, "10.99.99.1", "", ""),
		"CEF apagado y sin ruta":  routedOuts(run, "10.99.99.1", "% IPv4 CEF not enabled\n", "% Network not in table\n"),
		"salida recursiva":        routedOuts(run, "10.99.99.1", "0.0.0.0/0\n  via 10.255.0.254, 0 dependencies, recursive\n", ""),
		"salida a Null0":          routedOuts(run, "10.99.99.1", "192.0.2.0/24\n  attached to Null0\n", ""),
		"IP local en la SVI (L3)": routedOuts(run, "192.0.2.10", "", ""),
	} {
		_, err := routedPlan(t, uplinkVlan20, outs, nil)
		if !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "mgmt-if") || !strings.Contains(err.Error(), "salida") {
			t.Errorf("%s: con ip routing y sin certeza de la salida se rechaza y pide --mgmt-if: %v", name, err)
		}
	}
	// Con --mgmt-if se sigue, y la VLAN de esa interfaz queda protegida.
	outs := routedOuts(run, "10.99.99.1", "", "")
	if _, err := routedPlan(t, uplinkVlan20, outs, func(c *RestoreChange) { c.Management = "vlan10" }); !errors.Is(err, ErrRestoreRefused) {
		t.Errorf("--mgmt-if vlan10 protege la VLAN 10 en todos los puertos de acceso: %v", err)
	}
	if p, err := routedPlan(t, uplinkVlan20, outs, func(c *RestoreChange) { c.Management = "vlan99" }); err != nil {
		t.Errorf("--mgmt-if vlan99 deja restaurar el uplink de la VLAN 10: %v %s", err, fmtRefused(p))
	}
}

// Sin la línea `ip routing` (un router la trae activa y no la imprime) la salida se lee igual: una tabla de rutas significa que hay enrutamiento.
func TestRestoreRouterWithoutTheIPRoutingLineStillProtectsTheEgress(t *testing.T) {
	router := strings.Replace(routedRunning(), "ip routing\n", "", 1)
	for name, outs := range map[string]map[string]string{
		"CEF":  routedOuts(router, "10.99.99.1", cefVia10, ""),
		"ruta": routedOuts(router, "10.99.99.1", "% IPv4 CEF not enabled\n", routeVia10),
	} {
		ch := RestoreChange{Backup: uplinkShutdown(router), BackupSerial: "FOC0001A0AA"}
		p, err := RestoreDiffPlan("SW1", ch, outs)
		if !errors.Is(err, ErrRestoreRefused) || !strings.Contains(fmtRefused(p), "gestión") {
			t.Errorf("%s: un router con tabla de rutas protege la interfaz de salida: err=%v apply=%q", name, err, p.Device.Apply)
		}
	}
}

func TestRestoreSwitchWithRoutingOffNeedsNoMgmtIf(t *testing.T) {
	l2 := strings.Replace(routedRunning(), "ip routing\n", "", 1)
	for name, route := range map[string]string{"Default gateway": l2Route, "IP routing not enabled": "IP routing not enabled\n"} {
		if p, err := RestoreDiffPlan("SW1", RestoreChange{Backup: uplinkVlan20(l2), BackupSerial: "FOC0001A0AA"}, routedOuts(l2, "192.0.2.10", "", route)); err != nil {
			t.Errorf("%s: el switch sin enrutamiento se protege por la IP local: %v %s", name, err, fmtRefused(p))
		}
	}
	// `no ip routing` también es «sin enrutamiento», aunque no haya respuesta.
	off := strings.Replace(routedRunning(), "ip routing\n", "no ip routing\n", 1)
	if _, err := RestoreDiffPlan("SW1", RestoreChange{Backup: uplinkVlan20(off), BackupSerial: "FOC0001A0AA"}, routedOuts(off, "192.0.2.10", "", "")); err != nil {
		t.Errorf("no ip routing: %v", err)
	}
	// Sin la línea y sin una respuesta que lo diga no se sabe: se rechaza salvo con --mgmt-if.
	_, err := RestoreDiffPlan("SW1", RestoreChange{Backup: uplinkVlan20(l2), BackupSerial: "FOC0001A0AA"}, routedOuts(l2, "192.0.2.10", "", ""))
	if !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "mgmt-if") {
		t.Errorf("sin saber si enruta: %v", err)
	}
	if _, err := RestoreDiffPlan("SW1", RestoreChange{Backup: uplinkVlan20(l2), BackupSerial: "FOC0001A0AA", Management: "vlan99"}, routedOuts(l2, "192.0.2.10", "", "")); err != nil {
		t.Errorf("--mgmt-if: %v", err)
	}
	// Una línea `ip routing` manda sobre una respuesta de switch L2: la contradicción no se resuelve a favor de «sin enrutamiento».
	if _, err := routedPlan(t, uplinkVlan20, routedOuts(routedRunning(), "10.99.99.1", "", l2Route), nil); !errors.Is(err, ErrRestoreRefused) {
		t.Errorf("ip routing con respuesta de L2: %v", err)
	}
}

func TestRestoreMgmtIfOnAPhysicalPortProtectsItsImplicitVlan1AndVoiceVlan(t *testing.T) {
	run := routedRunning()
	outs := routedOuts(run, "10.99.99.1", "", "")
	set := func(c *RestoreChange) { c.Management = "gi1/0/30" } // access sin `switchport access vlan` (VLAN 1) y con voz 20
	voice := func(b string) string { return rep(b, "description VOZ", "description VOZ-OTRA") }
	implicit := func(b string) string { return rep(b, "description SIN-VLAN", "description OTRA") }
	for name, mod := range map[string]func(string) string{"puerto de la VLAN de voz": voice, "puerto en la VLAN 1 implícita": implicit} {
		p, err := routedPlan(t, mod, outs, set)
		if !errors.Is(err, ErrRestoreRefused) || !strings.Contains(fmtRefused(p), "gestión") {
			t.Errorf("%s: %v %s", name, err, fmtRefused(p))
		}
	}
	// Otro puerto distinto de esas VLAN sí se restaura.
	if p, err := routedPlan(t, uplinkVlan20, outs, set); err == nil || !strings.Contains(fmtRefused(p), "gestión") {
		// uplink pasa de la VLAN 10 a la 20, que es la de voz del puerto indicado: se rechaza.
		t.Errorf("la VLAN de voz del puerto indicado también se protege: %v %s", err, fmtRefused(p))
	}
}

func TestRestoreEgressPreAsksWheneverTheOriginIsKnownUnlessRoutingIsOff(t *testing.T) {
	run := routedRunning()
	got := RestoreEgressPre(reviewOuts(run))
	if !slices.Equal(got, []string{"show ip cef 192.0.2.9", "show ip route 192.0.2.9"}) {
		t.Errorf("Pre del camino de regreso = %q", got)
	}
	if got := RestoreEgressPre(reviewOuts(reviewRunning)); len(got) != 2 {
		t.Errorf("un router no imprime ip routing: se pregunta igual: %q", got)
	}
	if got := RestoreEgressPre(reviewOuts(strings.Replace(run, "ip routing\n", "no ip routing\n", 1))); got != nil {
		t.Errorf("con no ip routing no se pregunta: %q", got)
	}
	o := reviewOuts(run)
	o["show users"] = ""
	if got := RestoreEgressPre(o); got != nil {
		t.Errorf("sin origen conocido no se pregunta: %q", got)
	}
}

// ---- VRF de gestión, SVI en la subred del origen e IPv6 (tercera revisión) ----

// vrfRunning: la sesión entra por Vlan99, que está en la VRF Mgmt (10.88.88.1); el origen (192.0.2.9) queda fuera de su subred.
func vrfRunning(syntax string) string {
	return rep(routedRunning(), "interface Vlan99\n ip address 192.0.2.10 255.255.255.0\n", "interface Vlan99\n "+syntax+" forwarding Mgmt\n ip address 10.88.88.1 255.255.255.0\n")
}

// readOuts son las lecturas de Pre con la IP local dada y solo las respuestas de show indicadas (comando -> texto).
func readOuts(run, local string, answers map[string]string) map[string]string {
	o := routedOuts(run, local, "", "")
	for c, t := range answers {
		o[c] = t
	}
	return o
}

func uplinkDescription(b string) string {
	return rep(b, "description UPLINK\n", "description UPLINK-OTRO\n")
} // Gi1/0/24, VLAN 99

func TestRestoreEgressIsReadInTheVRFOfTheInterfaceThatCarriesTheSession(t *testing.T) {
	for _, syntax := range []string{"vrf", "ip vrf"} {
		run := vrfRunning(syntax)
		pre := RestoreEgressPre(readOuts(run, "10.88.88.1", nil))
		if want := []string{"show ip cef vrf Mgmt 192.0.2.9", "show ip route vrf Mgmt 192.0.2.9"}; !slices.Equal(pre, want) {
			t.Errorf("%s forwarding: Pre = %q, quería %q", syntax, pre, want)
		}
		plan := func(mod func(string) string, answers map[string]string) (RestorePlan, error) {
			return RestoreDiffPlan("SW1", RestoreChange{Backup: mod(run), BackupSerial: "FOC0001A0AA"}, readOuts(run, "10.88.88.1", answers))
		}
		// La tabla global dice Vlan10, pero la sesión vuelve por la VRF: sin su respuesta no hay certeza y se pide --mgmt-if.
		_, err := plan(uplinkVlan20, map[string]string{"show ip cef 192.0.2.9": cefVia10})
		if !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "mgmt-if") {
			t.Errorf("%s forwarding: la tabla global no vale para una interfaz en una VRF: %v", syntax, err)
		}
		// Una respuesta de «Default gateway» (switch L2) tampoco vale en una VRF.
		noRouting := strings.Replace(run, "ip routing\n", "", 1)
		_, err = RestoreDiffPlan("SW1", RestoreChange{Backup: uplinkVlan20(noRouting), BackupSerial: "FOC0001A0AA"}, readOuts(noRouting, "10.88.88.1", map[string]string{"show ip route vrf Mgmt 192.0.2.9": l2Route}))
		if !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "mgmt-if") {
			t.Errorf("%s forwarding: un switch L2 no tiene VRF, la respuesta no es cierta: %v", syntax, err)
		}
		// Con la respuesta de la VRF: la salida por Vlan99 protege la VLAN 99, no la 10.
		via99 := map[string]string{"show ip cef vrf Mgmt 192.0.2.9": cefVia99}
		if p, err := plan(uplinkVlan20, via99); err != nil {
			t.Errorf("%s forwarding: con la salida de la VRF por Vlan99 el uplink de la VLAN 10 se restaura: %v %s", syntax, err, fmtRefused(p))
		}
		if p, err := plan(uplinkDescription, via99); !errors.Is(err, ErrRestoreRefused) || !strings.Contains(fmtRefused(p), "gestión") {
			t.Errorf("%s forwarding: Gi1/0/24 lleva la VLAN 99: %v %s", syntax, err, fmtRefused(p))
		}
		// Y si la VRF sale por Vlan10, esa VLAN es la protegida (la ruta de respaldo también lleva el vrf).
		for name, ans := range map[string]map[string]string{
			"CEF":  {"show ip cef vrf Mgmt 192.0.2.9": cefVia10},
			"ruta": {"show ip cef vrf Mgmt 192.0.2.9": "% IPv4 CEF not enabled\n", "show ip route vrf Mgmt 192.0.2.9": routeVia10},
		} {
			if p, err := plan(uplinkVlan20, ans); !errors.Is(err, ErrRestoreRefused) || !strings.Contains(fmtRefused(p), "gestión") {
				t.Errorf("%s forwarding / %s: la salida de la VRF es Vlan10: %v %s", syntax, name, err, fmtRefused(p))
			}
		}
		// Con --mgmt-if se sigue aunque la VRF no se pueda leer.
		if _, err := RestoreDiffPlan("SW1", RestoreChange{Backup: uplinkVlan20(run), BackupSerial: "FOC0001A0AA", Management: "vlan99"}, readOuts(run, "10.88.88.1", nil)); err != nil {
			t.Errorf("%s forwarding: --mgmt-if: %v", syntax, err)
		}
	}
	// Un nombre de VRF que no sea una palabra simple no se manda a la consola: no se lee y se pide --mgmt-if.
	odd := rep(vrfRunning("vrf"), "interface Vlan99\n vrf forwarding Mgmt", "interface Vlan99\n vrf forwarding Mg;mt")
	if pre := RestoreEgressPre(readOuts(odd, "10.88.88.1", nil)); pre != nil {
		t.Errorf("nombre de VRF no válido: Pre = %q", pre)
	}
}

func TestRestoreProtectsEveryInterfaceWhoseSubnetContainsTheOrigin(t *testing.T) {
	// Switch L2 con dos SVI: la sesión entra por Vlan10 (10.10.0.1), pero el origen (192.0.2.9) está en la subred de Vlan99, que responde por ella.
	l2 := strings.Replace(routedRunning(), "ip routing\n", "", 1)
	// Router o switch L3: la sesión entra a Loopback0 y la tabla dice que sale por Vlan10; Vlan99 también es del segmento del origen.
	l3 := routedRunning()
	for name, outs := range map[string]map[string]string{
		"L2": routedOuts(l2, "10.10.0.1", "", l2Route),
		"L3": routedOuts(l3, "10.99.99.1", cefVia10, ""),
	} {
		run := l2
		if name == "L3" {
			run = l3
		}
		p, err := RestoreDiffPlan("SW1", RestoreChange{Backup: uplinkDescription(run), BackupSerial: "FOC0001A0AA"}, outs)
		if !errors.Is(err, ErrRestoreRefused) || !strings.Contains(fmtRefused(p), "gestión") {
			t.Errorf("%s: Vlan99 es del segmento del origen y su VLAN no se toca: %v %s", name, err, fmtRefused(p))
		}
		// Un puerto de otra VLAN (voz, 20) sí se restaura.
		if p, err := RestoreDiffPlan("SW1", RestoreChange{Backup: rep(run, "description VOZ", "description VOZ-OTRA"), BackupSerial: "FOC0001A0AA"}, outs); err != nil {
			t.Errorf("%s: otro puerto se restaura: %v %s", name, err, fmtRefused(p))
		}
	}
}

// IPv6: la sesión (2001:db8:1::9) entra por Vlan99 (2001:db8:99::1/64) y la salida se lee con show ipv6 cef / show ipv6 route.
func v6Running(extra string) string {
	return rep(routedRunning(), "interface Vlan99\n", "interface Vlan99\n ipv6 address 2001:DB8:99::1/64\n"+extra)
}

func v6Outs(run string, answers map[string]string) map[string]string {
	o := reviewOuts(run)
	o["show users"] = "    Line       User       Host(s)              Idle       Location\n*  2 vty 0     admin      idle                 00:00:00 2001:DB8:1::9\n"
	o["show tcp brief"] = "TCB       Local Address               Foreign Address             (state)\n7F1A2B3C  2001:DB8:99::1.22           2001:DB8:1::9.51234         ESTAB\n"
	delete(o, "show ip route 192.0.2.9")
	for c, t := range answers {
		o[c] = t
	}
	return o
}

func TestRestoreIPv6OriginReadsTheIPv6Tables(t *testing.T) {
	run := v6Running("")
	want := []string{"show ipv6 cef 2001:db8:1::9", "show ipv6 route 2001:db8:1::9"}
	if pre := RestoreEgressPre(v6Outs(run, nil)); !slices.Equal(pre, want) {
		t.Errorf("Pre = %q, quería %q", pre, want)
	}
	// ipv6 unicast-routing es independiente de `no ip routing`: el origen IPv6 se lee igual.
	if pre := RestoreEgressPre(v6Outs(strings.Replace(run, "ip routing\n", "no ip routing\n", 1), nil)); !slices.Equal(pre, want) {
		t.Errorf("con no ip routing y origen IPv6: Pre = %q", pre)
	}
	cef6 := "2001:DB8:1::/64\n  nexthop FE80::A8BB:CCFF:FE00:6400 Vlan10\n"
	route6 := "Routing entry for 2001:DB8:1::/64\n  Routing paths:\n    FE80::A8BB:CCFF:FE00:6400, Vlan10\n"
	plan := func(answers map[string]string) (RestorePlan, error) {
		return RestoreDiffPlan("SW1", RestoreChange{Backup: uplinkVlan20(run), BackupSerial: "FOC0001A0AA"}, v6Outs(run, answers))
	}
	for name, ans := range map[string]map[string]string{
		"CEF":  {want[0]: cef6},
		"ruta": {want[0]: "% IPv6 CEF not enabled\n", want[1]: route6},
	} {
		if p, err := plan(ans); !errors.Is(err, ErrRestoreRefused) || !strings.Contains(fmtRefused(p), "gestión") {
			t.Errorf("%s: la salida IPv6 es Vlan10 y su VLAN no se toca: %v %s", name, err, fmtRefused(p))
		}
	}
	// Sin respuesta de IPv6 (o con una IPv4 que no corresponde) no hay certeza: se pide --mgmt-if.
	for name, ans := range map[string]map[string]string{
		"sin respuesta":    nil,
		"una IPv4 de otra": {"show ip cef 192.0.2.9": cefVia10},
		"IPv6 sin tabla":   {want[0]: "% IPv6 CEF not enabled\n", want[1]: "% Route not found\n"},
	} {
		if _, err := plan(ans); !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "mgmt-if") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// `no ip routing` solo apaga IPv4: la salida IPv6 se lee y protege igual.
	noIP := strings.Replace(run, "ip routing\n", "no ip routing\n", 1)
	if p, err := RestoreDiffPlan("SW1", RestoreChange{Backup: uplinkVlan20(noIP), BackupSerial: "FOC0001A0AA"}, v6Outs(noIP, map[string]string{want[0]: cef6})); !errors.Is(err, ErrRestoreRefused) || !strings.Contains(fmtRefused(p), "gestión") {
		t.Errorf("no ip routing con origen IPv6: %v %s", err, fmtRefused(p))
	}
	// Un switch sin enrutamiento IPv4 que contesta «Default gateway» no dice nada de IPv6: se pide --mgmt-if.
	l2 := strings.Replace(run, "ip routing\n", "", 1)
	if _, err := RestoreDiffPlan("SW1", RestoreChange{Backup: uplinkVlan20(l2), BackupSerial: "FOC0001A0AA"}, v6Outs(l2, map[string]string{want[1]: l2Route})); !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "mgmt-if") {
		t.Errorf("la respuesta de un L2 no vale para IPv6: %v", err)
	}
	// Vlan10 tiene la subred del origen (2001:db8:1::/64): se protege aunque la salida diga Vlan99.
	onLink6 := v6Running("")
	onLink6 = rep(onLink6, "interface Vlan10\n", "interface Vlan10\n ipv6 address 2001:DB8:1::1/64\n")
	via99 := "2001:DB8:1::/64\n  attached to Vlan99\n"
	if p, err := RestoreDiffPlan("SW1", RestoreChange{Backup: uplinkVlan20(onLink6), BackupSerial: "FOC0001A0AA"}, v6Outs(onLink6, map[string]string{want[0]: via99})); !errors.Is(err, ErrRestoreRefused) || !strings.Contains(fmtRefused(p), "gestión") {
		t.Errorf("la subred IPv6 del origen está en Vlan10: %v %s", err, fmtRefused(p))
	}
}
