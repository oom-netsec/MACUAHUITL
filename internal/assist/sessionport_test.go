package assist

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
)

// sess describe una sesión SSH hacia un switch y cómo la ve el equipo. Los formatos son los de la documentación de Cisco (IOS 15.2 e IOS-XE),
// armados a mano y sin validar en laboratorio.
type sess struct {
	origin   string // IP de origen en show users; por omisión 10.20.0.50
	gw       string // si se da, el origen no está en un segmento conectado y se llega por este gateway (con show ip route; con l2 es «Default gateway»)
	l2       bool   // con gw: la tabla de rutas es la de un switch sin ip routing
	mac      string // MAC del siguiente salto (la del origen, o la del gateway)
	ifc      string // interfaz de la tabla ARP; por omisión Vlan20 (con gw, Vlan10)
	port     string // puerto donde la tabla MAC aprendió esa MAC; vacío = sin entrada
	two      string // un segundo puerto donde también la aprendió (MAC flapping)
	noARP    bool   // el equipo no tiene ARP del siguiente salto
	channels string // salida de show etherchannel summary (si el puerto es un Po)
}

func (s sess) outs() map[string]string {
	origin := ifElse(s.origin != "", s.origin, "10.20.0.50")
	mac := ifElse(s.mac != "", s.mac, "aabb.cc00.0100")
	ifc := ifElse(s.ifc != "", s.ifc, ifElse(s.gw != "", "Vlan10", "Vlan20"))
	vlan := strings.TrimPrefix(ifc, "Vlan")
	arpHead := "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
	o := map[string]string{
		showUsersCmd: "    Line       User       Host(s)              Idle       Location\n   0 con 0                idle                 00:00:00\n*  2 vty 0     admin      idle                 00:00:00 " + origin + "\n",
	}
	hop := origin
	switch {
	case s.gw == "":
		o["show ip arp "+origin] = arpHead + "Internet  " + origin + "              3   " + mac + "  ARPA   " + ifc + "\n"
		o["show ip route "+origin] = "Routing entry for 10.20.0.0/24\n  Known via \"connected\", distance 0, metric 0 (connected, via interface)\n  Routing Descriptor Blocks:\n  * directly connected, via " + ifc + "\n      Route metric is 0, traffic share count is 1\n"
	default:
		hop = s.gw
		o["show ip arp "+origin] = arpHead // sin fila: el origen no está en un segmento conectado
		if s.l2 {
			o["show ip route "+origin] = "Default gateway is " + s.gw + "\n\nHost               Gateway           Last Use    Total Uses  Interface\nICMP redirect cache is empty\n"
		} else {
			o["show ip route "+origin] = "Routing entry for 10.30.0.0/24\n  Known via \"ospf 1\", distance 110, metric 20, type intra area\n  Last update from " + s.gw + " on " + ifc + ", 00:10:00 ago\n  Routing Descriptor Blocks:\n  * " + s.gw + ", from 10.30.0.1, 00:10:00 ago, via " + ifc + "\n      Route metric is 20, traffic share count is 1\n"
		}
		o["show ip arp "+hop] = arpHead + "Internet  " + hop + "              5   " + mac + "  ARPA   " + ifc + "\n"
	}
	if s.noARP {
		o["show ip arp "+hop] = arpHead
		return o
	}
	if !strings.HasPrefix(strings.ToLower(ifc), "vlan") {
		o["show etherchannel summary"] = s.channels
		return o // interfaz ruteada: el puerto es la propia interfaz, sin tabla MAC
	}
	cam := "          Mac Address Table\n-------------------------------------------\n\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n"
	for _, p := range []string{s.port, s.two} {
		if p != "" {
			cam += "  " + vlan + "    " + mac + "    DYNAMIC     " + p + "\n"
		}
	}
	o["show mac address-table address "+mac] = cam + "Total Mac Addresses for this criterion: 1\n"
	o["show etherchannel summary"] = s.channels
	return o
}

const ecSummary = "Group  Port-channel  Protocol    Ports\n------+-------------+-----------+-----------------------------------------------\n1      Po1(SU)         LACP      Gi1/0/47(P)   Gi1/0/48(P)\n"

// with le suma a una captura las salidas de la sesión.
func with(outs map[string]string, s sess) map[string]string {
	maps.Copy(outs, s.outs())
	return outs
}

// onGi48 es una sesión que entra por el puerto Gi1/0/48 de un switch con las lecturas de los demás puertos de prueba (Gi1/0/1, Gi1/0/2...).
var onGi48 = sess{port: "Gi1/0/48"}

func TestSessionPortReadsFollowTheChain(t *testing.T) {
	s := sess{port: "Po1", channels: ecSummary}
	full := s.outs()
	have := map[string]string{showUsersCmd: full[showUsersCmd]}
	var asked []string
	for range 6 {
		next := SessionPortReads(have)
		if len(next) == 0 {
			break
		}
		asked = append(asked, next...)
		for _, c := range next {
			if _, ok := full[c]; !ok {
				t.Fatalf("pide %q, que la sesión de prueba no contesta", c)
			}
			have[c] = full[c]
		}
	}
	want := "show ip arp 10.20.0.50|show ip route 10.20.0.50|show mac address-table address aabb.cc00.0100|show etherchannel summary"
	if strings.Join(asked, "|") != want {
		t.Errorf("lecturas = %v", asked)
	}
	sp := sessionPorts(have)
	if !sp.known || !sp.isSession("Port-channel1") || !sp.isSession("GigabitEthernet1/0/47") || !sp.isSession("Gi1/0/48") || sp.isSession("Gi1/0/1") || sp.vlan != "20" {
		t.Errorf("%+v", sp)
	}
	// Sin show users no hay qué leer.
	if got := SessionPortReads(map[string]string{}); got != nil {
		t.Errorf("sin show users: %v", got)
	}
}

func TestSessionPortsGatewayAndRouted(t *testing.T) {
	// Fuera del segmento: el siguiente salto es el gateway de la tabla de rutas (L3) o el «Default gateway» (switch L2).
	for name, s := range map[string]sess{
		"ruta":    {origin: "10.30.0.50", gw: "10.1.1.2", mac: "aabb.cc00.0200", port: "Gi1/0/47"},
		"l2 gw":   {origin: "10.30.0.50", gw: "10.1.1.2", l2: true, mac: "aabb.cc00.0200", port: "Gi1/0/47"},
		"ruteado": {ifc: "Gi1/0/47"},
		"subint":  {ifc: "Gi1/0/47.20"},
	} {
		sp := sessionPorts(s.outs())
		if !sp.known || !sp.isSession("Gi1/0/47") || sp.isSession("Gi1/0/48") {
			t.Errorf("%s: %+v", name, sp)
		}
	}
	// Sin certeza: sin ARP, sin entrada en la tabla MAC, la MAC en dos puertos, dos gateways, IPv6.
	for name, s := range map[string]sess{
		"sin arp":     {port: "Gi1/0/48", noARP: true},
		"sin cam":     {},
		"dos puertos": {port: "Gi1/0/47", two: "Gi1/0/48"},
		"solo cpu":    {port: "CPU"},
		"origen ipv6": {origin: "2001:db8::9", port: "Gi1/0/48"},
		"sin gateway": {origin: "10.30.0.50", gw: "10.1.1.2", noARP: true, port: "Gi1/0/48"},
	} {
		if sp := sessionPorts(s.outs()); sp.known {
			t.Errorf("%s: identificó %+v", name, sp)
		}
	}
	// La misma MAC en otra VLAN (otro puerto) no cuenta: se mira la VLAN que lleva la sesión.
	o2 := sess{port: "Gi1/0/48"}.outs()
	o2["show mac address-table address aabb.cc00.0100"] = strings.Replace(o2["show mac address-table address aabb.cc00.0100"], "  20    aabb", "  10    aabb.cc00.0100    DYNAMIC     Gi1/0/47\n  20    aabb", 1)
	if sp := sessionPorts(o2); !sp.known || !sp.isSession("Gi1/0/48") || sp.isSession("Gi1/0/47") {
		t.Errorf("otra VLAN: %+v", sp)
	}
	// Dos gateways de igual costo: no se adivina.
	o := sess{origin: "10.30.0.50", gw: "10.1.1.2", mac: "aabb.cc00.0200", port: "Gi1/0/47"}.outs()
	o["show ip route 10.30.0.50"] += "  * 10.1.1.6, from 10.30.0.1, 00:10:00 ago, via Vlan11\n"
	if sp := sessionPorts(o); sp.known {
		t.Errorf("ECMP: %+v", sp)
	}
}

// ---- ports ----

func TestPortsRefuseTheSessionPort(t *testing.T) {
	const gi48 = "GigabitEthernet1/0/48"
	mk := func() map[string]string {
		return with(outsOf(map[string]string{
			gi48: cfgOf(gi48, "switchport mode access"), // VLAN 1 de fábrica
			gi1:  cfgOf(gi1, "switchport mode access"),  // otro puerto, también en VLAN 1
			gi2:  cfgOf(gi2, "switchport mode access", "description libre"),
		}), onGi48)
	}
	// La sesión entra por Gi1/0/48: apagarlo o cambiarle la VLAN (de acceso o de voz) la corta.
	for name, ch := range map[string]PortChange{"shutdown": {Shutdown: yes(true)}, "vlan": {Vlan: 20}, "voz": {Voice: 120}} {
		_, err := PortsPlan("SW1", []string{gi48}, ch, mk())
		if !errors.Is(err, ErrPortRefused) || !strings.Contains(err.Error(), "puerto por donde llega esta sesión") || !strings.Contains(err.Error(), "aabb.cc00.0100") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Si el puerto de la sesión va en la lista, rechaza todo el plan.
	if _, err := PortsPlan("SW1", []string{gi1, gi48}, PortChange{Vlan: 20}, mk()); !errors.Is(err, ErrPortRefused) {
		t.Errorf("en una lista: %v", err)
	}
	// Los demás puertos (también en VLAN 1) y los cambios que no cortan se aceptan, sin nota de duda.
	for name, c := range map[string]struct {
		ifs []string
		ch  PortChange
	}{
		"otros puertos de la VLAN 1":     {[]string{gi1, gi2}, PortChange{Vlan: 20, Shutdown: yes(true)}},
		"descripción en el de la sesión": {[]string{gi48}, PortChange{Description: str("uplink")}},
		"no shutdown en el de la sesión": {[]string{gi48}, PortChange{Shutdown: yes(false)}},
	} {
		dp, err := PortsPlan("SW1", c.ifs, c.ch, mk())
		if err != nil || len(dp.NoteItems) != 0 {
			t.Errorf("%s: %v %v", name, err, dp.NoteItems)
		}
	}
}

func TestPortsUnknownSessionAcceptsAccessWithNote(t *testing.T) {
	for name, s := range map[string]sess{"sin ARP": {noARP: true, port: "Gi1/0/1"}, "sin CAM": {}, "dos puertos": {port: "Gi1/0/1", two: "Gi1/0/2"}} {
		dp, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 20}, with(captured(), s))
		if err != nil || len(dp.NoteItems) != 1 || len(dp.Notes) != 1 || !strings.Contains(dp.Notes[0], "No se pudo identificar el puerto") {
			t.Errorf("%s: %v %v", name, err, dp.Notes)
		}
	}
	// Sin show users en las salidas pasa igual (el servicio no lo leyó).
	if dp, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 20}, captured()); err != nil || len(dp.Notes) != 1 {
		t.Errorf("sin show users: %v %v", err, dp.Notes)
	}
	// Con certeza de otro puerto no hay nota.
	if dp, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 20}, with(captured(), onGi48)); err != nil || len(dp.Notes) != 0 {
		t.Errorf("puerto conocido: %v %v", err, dp.Notes)
	}
	// Una descripción sola no corta: no pide show users ni agrega nota.
	pre, _ := PortsPre([]string{gi1}, PortChange{Description: str("x")})
	if slices.Contains(pre, showUsersCmd) {
		t.Errorf("pre = %v", pre)
	}
}

// ---- trunk ----

func TestTrunkRemoveRefusesTheSessionVlanOnTheUplink(t *testing.T) {
	const gi48 = "GigabitEthernet1/0/48"
	up := func(name string, s sess) map[string]string {
		return with(trunkOuts(name, trunkCfg(name, "switchport mode trunk", "switchport trunk allowed vlan 10,20,30"), swTrunk), s)
	}
	// El uplink lleva la sesión por la VLAN 20: quitarla corta; quitar otra no.
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi48, Op: "remove", Vlan: 20}, up(gi48, onGi48)); !errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), "VLAN 20") {
		t.Errorf("uplink, VLAN de la sesión: %v", err)
	}
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi48, Op: "remove", Vlan: 30}, up(gi48, onGi48)); err != nil {
		t.Errorf("uplink, otra VLAN: %v", err)
	}
	// Otro trunk que no es el de la sesión: se acepta aunque sea la VLAN de la sesión.
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi1, Op: "remove", Vlan: 20}, up(gi1, onGi48)); err != nil {
		t.Errorf("otro trunk: %v", err)
	}
	// Agregar nunca corta.
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi48, Op: "add", Vlan: 40}, up(gi48, onGi48)); err != nil {
		t.Errorf("add: %v", err)
	}
	// Port-channel: la sesión entra por Po1 (miembros Gi1/0/47 y 48).
	po := sess{port: "Po1", channels: ecSummary}
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: "Port-channel1", Op: "remove", Vlan: 20}, up("Port-channel1", po)); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("Po1: %v", err)
	}
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: "Port-channel2", Op: "remove", Vlan: 20}, up("Port-channel2", po)); err != nil {
		t.Errorf("Po2: %v", err)
	}
	// Sesión por el gateway: se protege el puerto del gateway.
	gw := sess{origin: "10.30.0.50", gw: "10.1.1.2", mac: "aabb.cc00.0200", port: "Gi1/0/48"}
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi48, Op: "remove", Vlan: 10}, up(gi48, gw)); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("gateway: %v", err)
	}
	// Sin identificar el puerto: un trunk rechaza quitar la VLAN de la sesión (o cualquiera si no se sabe cuál es).
	for name, s := range map[string]sess{"sin CAM": {}, "sin ARP": {noARP: true}} {
		_, err := TrunkPlan("SW1", TrunkChange{Interface: gi48, Op: "remove", Vlan: 30}, up(gi48, s))
		if name == "sin CAM" && err != nil { // la VLAN de la sesión (20) se sabe por el ARP: otra VLAN no la corta
			t.Errorf("%s, otra VLAN: %v", name, err)
		}
		if name == "sin ARP" && !errors.Is(err, ErrSnippetRefused) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi48, Op: "remove", Vlan: 20}, up(gi48, s)); !errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), "no se pudo identificar") {
			t.Errorf("%s, VLAN de la sesión: %v", name, err)
		}
	}
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi48, Op: "remove", Vlan: 20}, trunkOuts(gi48, trunkCfg(gi48, "switchport mode trunk", "switchport trunk allowed vlan 10,20,30"), swTrunk)); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("sin show users: %v", err)
	}
	if pre, _ := TrunkPre(TrunkChange{Interface: gi1, Op: "add", Vlan: 5}); slices.Contains(pre, showUsersCmd) {
		t.Errorf("add no lee show users: %v", pre)
	}
}

// ---- plantillas por puerto ----

// l2Plan planea una plantilla por puerto con el equipo simulado y las salidas de la sesión.
func l2Plan(t *testing.T, id string, v Values, dev *iosDev, s sess) (DevicePlan, error) {
	t.Helper()
	tpl, ok := TemplateByID(id)
	if !ok {
		t.Fatalf("no hay plantilla %s", id)
	}
	if err := ValidateValues(tpl, v); err != nil {
		t.Fatal(err)
	}
	pre, err := tpl.Pre(v)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pre, showUsersCmd) || !tpl.SessionPort {
		t.Fatalf("%s: Pre no lee show users o no pide el puerto de la sesión: %v", id, pre)
	}
	return tpl.Plan("SW1", v, with(dev.read(pre), s))
}

func TestL2TemplatesRefuseTheSessionPort(t *testing.T) {
	const up, other = "GigabitEthernet1/0/48", "GigabitEthernet1/0/47"
	dev := func() *iosDev {
		return newDev(map[string][]string{up: accessGi(), other: accessGi(), gi1: accessGi()})
	}
	cases := []struct {
		id   string
		v    Values
		cuts bool
	}{
		{"speed-duplex", Values{"speed": "10", "duplex": "half"}, true},
		{"speed-duplex", Values{"speed": "auto"}, false}, // ya estaba en auto: sin cambios, el plan no existe
		{"storm-control", Values{"broadcast": "10", "action": "shutdown"}, true},
		{"storm-control", Values{"unicast": "0.5"}, true},
		{"storm-control", Values{"action": "trap"}, false},
		{"portfast-bpduguard", Values{"portfast": "false", "bpduguard": "true"}, true},
		{"portfast-bpduguard", Values{"portfast": "true", "bpduguard": "false"}, false},
		{"port-security", Values{"violation": "shutdown"}, true},
		{"modo-puerto", Values{"mode": "dynamic desirable"}, true},
	}
	for _, c := range cases {
		c.v["interfaces"] = up
		_, err := l2Plan(t, c.id, c.v, dev(), onGi48)
		if c.cuts && (!errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), "puerto por donde llega esta sesión")) {
			t.Errorf("%s %v en el puerto de la sesión: %v", c.id, c.v, err)
		}
		if !c.cuts && errors.Is(err, ErrSnippetRefused) && strings.Contains(err.Error(), "puerto por donde llega esta sesión") {
			t.Errorf("%s %v no corta pero se rechazó: %v", c.id, c.v, err)
		}
		// El mismo cambio en un puerto que no es el de la sesión (en la VLAN 1 como el resto) se acepta.
		c.v["interfaces"] = other
		if dp, err := l2Plan(t, c.id, c.v, dev(), onGi48); c.cuts && (err != nil || len(dp.Apply) == 0) {
			t.Errorf("%s %v en otro puerto: %v", c.id, c.v, err)
		}
	}
	// Un puerto de la lista basta para rechazar el plan.
	if _, err := l2Plan(t, "speed-duplex", Values{"interfaces": other + "," + up, "speed": "100"}, dev(), onGi48); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("en una lista: %v", err)
	}
	// El modo del puerto y port-security no cambian el modo de un trunk, pero un trunk de uplink con speed sí se rechaza si es el de la sesión.
	trunkDev := func() *iosDev {
		return newDev(map[string][]string{up: {"switchport mode trunk"}, other: {"switchport mode trunk"}})
	}
	if _, err := l2Plan(t, "speed-duplex", Values{"interfaces": up, "speed": "10", "duplex": "half"}, trunkDev(), onGi48); !errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), "puerto por donde llega esta sesión") {
		t.Errorf("uplink trunk: %v", err)
	}
	if _, err := l2Plan(t, "speed-duplex", Values{"interfaces": other, "speed": "10", "duplex": "half"}, trunkDev(), onGi48); err != nil {
		t.Errorf("otro trunk: %v", err)
	}
	// Port-channel: sus miembros están protegidos (l2Capture los rechaza si el running trae channel-group, y si no, el set del canal).
	po := sess{port: "Po1", channels: ecSummary}
	if _, err := l2Plan(t, "speed-duplex", Values{"interfaces": up, "speed": "10"}, dev(), po); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("miembro del canal de la sesión: %v", err)
	}
}

func TestL2TemplatesUnknownSession(t *testing.T) {
	const acc, trk = "GigabitEthernet1/0/1", "GigabitEthernet1/0/2"
	dev := func() *iosDev { return newDev(map[string][]string{acc: accessGi(), trk: {"switchport mode trunk"}}) }
	for name, s := range map[string]sess{"sin ARP": {noARP: true}, "sin CAM": {}, "dos puertos": {port: "Gi1/0/1", two: "Gi1/0/2"}} {
		dp, err := l2Plan(t, "speed-duplex", Values{"interfaces": acc, "speed": "100"}, dev(), s)
		if err != nil || !strings.Contains(strings.Join(dp.Notes, "|"), "No se pudo identificar el puerto") || len(dp.NoteItems) != len(dp.Notes) {
			t.Errorf("%s, acceso: %v %v", name, err, dp.Notes)
		}
		if _, err := l2Plan(t, "speed-duplex", Values{"interfaces": trk, "speed": "100"}, dev(), s); !errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), "no se pudo identificar") {
			t.Errorf("%s, trunk: %v", name, err)
		}
		// Un dynamic que negoció un trunk (sin la línea en el running) también es candidato a uplink.
		neg := dev()
		neg.oper = map[string]string{acc: "trunk"}
		if _, err := l2Plan(t, "speed-duplex", Values{"interfaces": acc, "speed": "100"}, neg, s); !errors.Is(err, ErrSnippetRefused) {
			t.Errorf("%s, trunk negociado: %v", name, err)
		}
		if _, err := l2Plan(t, "modo-puerto", Values{"interfaces": acc, "mode": "dynamic desirable"}, dev(), s); err != nil {
			t.Errorf("%s, modo-puerto acceso: %v", name, err)
		}
	}
}
