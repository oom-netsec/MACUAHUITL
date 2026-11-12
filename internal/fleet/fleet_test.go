package fleet

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)

func load(t *testing.T) *Fleet {
	t.Helper()
	f, err := Load("testdata/outputs", now)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLoadUltimaEvidencia(t *testing.T) {
	f := load(t)
	if len(f.Devs) != 3 || f.Devs[0].Name != "ACC1" {
		t.Fatalf("equipos %d", len(f.Devs))
	}
	acc := f.Devs[0]
	e, _ := acc.Get("show mac address-table")
	if e.Job != "trabajo_20261105-080000" || !strings.Contains(e.Text, "Gi1/0/5") {
		t.Errorf("debe ganar el trabajo reciente: %+v", e.Job)
	}
	e, ok := acc.Get("show ntp status")
	if !ok || e.Job != "trabajo_20261103-090000" {
		t.Errorf("el ntp solo existe en el trabajo viejo: %v %v", ok, e.Job)
	}
	if _, err := Load("testdata", now); err == nil {
		// testdata/ tiene un nivel más (outputs/): debe bajar y encontrarlos
		t.Log("ok: baja un nivel")
	}
	if _, err := Load(t.TempDir(), now); err == nil {
		t.Error("carpeta vacía debe fallar")
	}
}

func TestFindPorMACenCualquierNotacion(t *testing.T) {
	f := load(t)
	for _, q := range []string{"AABB.CC00.0A01", "aa:bb:cc:00:0a:01", "aa-bb-cc-00-0a-01"} {
		r := f.Find(q)
		kinds := map[string]bool{}
		for _, h := range r.Hits {
			kinds[h.Device+"/"+h.Kind] = true
		}
		for _, want := range []string{"CORE1/arp", "CORE1/mac-table", "DIST1/mac-table", "ACC1/mac-table", "ACC1/dhcp-snooping"} {
			if !kinds[want] {
				t.Errorf("%s: falta %s en %v", q, want, kinds)
			}
		}
	}
	r := f.Find("aabb.cc00.0a01")
	for _, h := range r.Hits {
		if h.Device == "ACC1" && h.Kind == "mac-table" && (h.Port != "Gi1/0/5" || h.VLAN != "10" || h.At.IsZero() || h.Source == "") {
			t.Errorf("hit %+v", h)
		}
	}
}

func TestFindPorIPyNombre(t *testing.T) {
	f := load(t)
	r := f.Find("10.1.10.20")
	if r.Mode != "ip" {
		t.Fatal(r.Mode)
	}
	// IP -> MAC (ARP/DHCP) -> puertos en las tablas CAM
	if !strings.Contains(f.FindText(r), "ACC1") || len(r.Hits) < 5 {
		t.Errorf("IP: %d hits", len(r.Hits))
	}
	r = f.Find("10.255.0.2") // IP de gestión de DIST1: carpeta + CDP desde CORE1/ACC1 + interfaz
	got := map[string]bool{}
	for _, h := range r.Hits {
		got[h.Kind] = true
	}
	if !got["device"] || !got["cdp"] {
		t.Errorf("gestión: %v", got)
	}
	if r = f.Find("dist1"); r.Mode != "name" || len(r.Hits) < 3 {
		t.Errorf("nombre: %d", len(r.Hits))
	}
	if r = f.Find("10.9.9.9"); len(r.Hits) != 0 {
		t.Errorf("no debe inventar: %+v", r.Hits)
	}
}

func TestTraceHastaAcceso(t *testing.T) {
	f := load(t)
	for _, q := range []string{"aabb.cc00.0a01", "10.1.10.20"} {
		r := f.Trace(q)
		if r.End != "access" || r.Access.Device != "ACC1" || r.Access.Port != "Gi1/0/5" || r.Access.VLAN != "10" {
			t.Fatalf("%s: %+v %v", q, r, r.Warnings)
		}
		var path []string
		for _, h := range r.Hops {
			path = append(path, h.Device+" "+h.Port)
		}
		if strings.Join(path, ",") != "CORE1 Po1,DIST1 Gi1/0/3,ACC1 Gi1/0/5" {
			t.Errorf("salto por port-channel y vecinos: %v", path)
		}
	}
	if r := f.Trace("aabb.cc00.9999"); r.End != "not-found" || len(r.Warnings) == 0 {
		t.Errorf("MAC desconocida: %+v", r)
	}
	if r := f.Trace("10.7.7.7"); r.End != "not-found" {
		t.Errorf("IP sin ARP: %+v", r)
	}
}

func devFrom(key string, cmds map[string]string) *Dev {
	ev := map[string]Evidence{}
	for c, txt := range cmds {
		ev[c] = Evidence{Text: txt, At: now}
	}
	return NewDev(key, ev)
}

const macTbl = "Vlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n  10    aabb.cc00.0a01    DYNAMIC     Gi1/0/1\n"

func cdp(id, ip, local, remote string) string {
	return "Device ID: " + id + "\n  IP address: " + ip + "\nInterface: " + local + ",  Port ID (outgoing port): " + remote + "\n"
}

func TestTraceBucle(t *testing.T) {
	a := devFrom("A_10.0.0.1", map[string]string{"show mac address-table": macTbl, "show cdp neighbors detail": cdp("B", "10.0.0.2", "GigabitEthernet1/0/1", "GigabitEthernet1/0/1")})
	b := devFrom("B_10.0.0.2", map[string]string{"show mac address-table": macTbl, "show cdp neighbors detail": cdp("A", "10.0.0.1", "GigabitEthernet1/0/1", "GigabitEthernet1/0/1")})
	r := New([]*Dev{a, b}, now).Trace("aabb.cc00.0a01")
	if r.End != "loop" || len(r.Hops) != 3 || !strings.Contains(strings.Join(r.Warnings, ";"), "bucle") {
		t.Fatalf("%+v", r)
	}
}

func TestTraceVecinoSinEvidencia(t *testing.T) {
	a := devFrom("A_10.0.0.1", map[string]string{"show mac address-table": macTbl, "show cdp neighbors detail": cdp("X", "10.0.0.9", "GigabitEthernet1/0/1", "GigabitEthernet1/0/2")})
	r := New([]*Dev{a}, now).Trace("aabb.cc00.0a01")
	if r.End != "no-neighbor" || r.Access != nil {
		t.Fatalf("no debe declarar acceso: %+v", r)
	}
}

func TestPathL3ConTramoL2(t *testing.T) {
	f := load(t)
	r := f.Path("10.1.10.20", "10.1.20.50")
	if !r.Arrived || len(r.Hops) != 2 {
		t.Fatalf("%s", f.PathText(r))
	}
	h := r.Hops[1]
	if h.Device != "DIST1" || h.Status != "arrived" || h.OutIf != "Vlan100" || h.Segment.VLAN != "100" || !strings.Contains(h.Reason, "ACC1 Gi1/0/10") {
		t.Errorf("%+v", h)
	}
	// tramo L2 CORE1 -> DIST1: sale por Po1 y la MAC del salto es propia de DIST1
	if l2 := h.Segment.L2; len(l2) != 2 || l2[0].Port != "Po1" || h.Segment.L2End != "self" {
		t.Errorf("l2 %+v", l2)
	}
	if fl := h.Final.L2; len(fl) != 2 || fl[1].Port != "Gi1/0/10" || h.Final.L2End != "access" {
		t.Errorf("final %+v", fl)
	}
	svg := r.SVG()
	if !strings.HasPrefix(svg, "<svg") || !strings.Contains(svg, "CORE1") || strings.Contains(svg, "<script") {
		t.Error("svg")
	}
}

func TestPathCortes(t *testing.T) {
	f := load(t)
	// default hacia un equipo sin evidencia
	r := f.Path("10.1.10.20", "172.31.0.1")
	last := r.Hops[len(r.Hops)-1]
	if r.Arrived || last.Status != "cut" || !strings.Contains(last.Reason, "sin evidencia del siguiente equipo") {
		t.Errorf("%s", f.PathText(r))
	}
	// sin ruta
	r = f.Path("10.1.20.50", "192.0.2.1")
	if last = r.Hops[len(r.Hops)-1]; last.Status != "cut" || !strings.Contains(last.Reason, "sin ruta") {
		t.Errorf("%s", f.PathText(r))
	}
	// ECMP: dos ramas, una continúa y otra se corta
	r = f.Path("10.1.10.20", "10.9.1.1")
	cuts, branches := 0, 0
	for _, h := range r.Hops {
		if h.ECMP {
			branches++
		}
		if h.Status == "cut" {
			cuts++
		}
	}
	if branches < 2 || cuts < 2 {
		t.Errorf("ECMP: %s", f.PathText(r))
	}
	if !strings.Contains(r.SVG(), "CORTE") {
		t.Error("el SVG marca el corte")
	}
	// origen sin evidencia
	if r = f.Path("203.0.113.5", "10.1.20.50"); r.Hops[0].Status != "cut" {
		t.Errorf("%+v", r.Hops)
	}
}

func TestHealth(t *testing.T) {
	r := load(t).Health()
	if len(r.Issues) != 3 {
		t.Fatalf("%+v", r.Issues)
	}
	if i := r.Issues[0]; i.Severity != "critica" || i.Port != "Gi1/0/9" || i.Device != "ACC1" {
		t.Errorf("primero err-disabled: %+v", i)
	}
	i := r.Issues[1]
	kinds := map[string]int64{}
	for _, p := range i.Problems {
		kinds[p.Kind] = p.Value
		if p.Evidence == "" && p.Kind != "half-duplex" {
			t.Errorf("sin evidencia: %+v", p)
		}
	}
	if i.Port != "Gi1/0/5" || kinds["crc"] != 15234 || kinds["runts"] != 12 || i.Severity != "alta" {
		t.Errorf("%+v", i)
	}
	if _, ok := kinds["half-duplex"]; !ok {
		t.Error("half duplex")
	}
	if r.Issues[2].Port != "Po1" || r.Issues[2].Severity != "alta" { // 2300 drops
		t.Errorf("%+v", r.Issues[2])
	}
}

func TestSummary(t *testing.T) {
	f := load(t)
	r := f.Summary()
	got := map[string]Row{}
	for _, x := range r.Rows {
		got[x.Device+"/"+x.Check] = x
	}
	for _, k := range []string{"CORE1/cpu", "DIST1/reboot", "DIST1/memory", "DIST1/flash", "ACC1/ntp"} {
		if _, ok := got[k]; !ok {
			t.Errorf("falta %s: %v", k, r.Rows)
		}
	}
	if len(r.Rows) != 5 {
		t.Errorf("filas de más: %v", r.Rows)
	}
	if ntp := got["ACC1/ntp"]; !strings.Contains(f.Stamp(ntp.At), "DATO VIEJO") {
		t.Errorf("el dato viejo debe notarse: %s", f.Stamp(ntp.At))
	}
	if r.Checked["ntp"] != 3 && r.Checked["ntp"] != 2 {
		t.Errorf("checked %v", r.Checked)
	}
}

func TestCapacity(t *testing.T) {
	need, err := ParseSize("1G")
	if err != nil || need != 1<<30 {
		t.Fatal(need, err)
	}
	r := load(t).Capacity(need)
	fits := map[string]bool{}
	for _, x := range r.Flash {
		fits[x.Device] = *x.Fits
	}
	if !fits["CORE1"] || !fits["ACC1"] || fits["DIST1"] || len(r.DRAM) != 3 {
		t.Errorf("%v %v", fits, r.DRAM)
	}
	if r.DRAM[2].Total != (1333688+6147)<<10 { // DIST1
		t.Errorf("dram %+v", r.DRAM[1])
	}
	if _, err := ParseSize("mucho"); err == nil {
		t.Error("tamaño inválido")
	}
	if n, _ := ParseSize("1.5M"); n != 3<<19 {
		t.Error(n)
	}
}

func TestInventarioCSVyMarkdown(t *testing.T) {
	r := load(t).Inventory()
	var sfp, equipos int
	for _, x := range r.Rows {
		if x.Kind == "sfp" {
			sfp++
		}
		if x.Kind == "equipo" && x.Serial == "" {
			t.Errorf("sin serie %+v", x)
		}
		equipos += map[bool]int{true: 1}[x.Kind == "equipo"]
	}
	if sfp != 2 || equipos != 3 {
		t.Errorf("sfp %d equipos %d", sfp, equipos)
	}
	csv, md := r.CSV(), r.Markdown()
	if !strings.HasPrefix(csv, "Equipo,Tipo,") || !strings.Contains(csv, "SFP-10G-SR") || !strings.Contains(md, "| --- |") {
		t.Error("formatos")
	}
	r.Rows = []InvRow{{Device: "=cmd()", Descr: "a|b"}}
	if c := r.CSV(); !strings.Contains(c, "'=cmd()") {
		t.Errorf("inyección CSV: %s", c)
	}
	if m := r.Markdown(); !strings.Contains(m, `a\|b`) {
		t.Error("pipe en markdown")
	}
}

// Formato inesperado: aviso visible, ningún resultado falso.
func TestFormatoInesperado(t *testing.T) {
	a := devFrom("A_10.0.0.1", map[string]string{
		"show ip arp":            "Protocol Address\nbasura inesperada\n",
		"show mac address-table": "% Invalid input detected at '^' marker.\n",
		"show ntp status":        "NTP is not enabled.\n",
		"show processes cpu":     "formato nuevo\n",
	})
	f := New([]*Dev{a}, now)
	r := f.Find("10.0.0.5")
	if len(r.Hits) != 0 || len(r.Warnings) == 0 {
		t.Errorf("%+v", r)
	}
	s := f.Summary()
	if len(s.Rows) != 0 || len(s.Warnings) < 2 || s.Checked["ntp"] != 0 {
		t.Errorf("el ntp ilegible no cuenta como sincronizado ni como alerta: %+v", s)
	}
	if !strings.Contains(strings.Join(s.Warnings, "|"), "formato inesperado") {
		t.Errorf("%v", s.Warnings)
	}
}

func TestAbreviaturas(t *testing.T) {
	d := devFrom("A_1.1.1.1", map[string]string{"show ip arp | include 10.1": "x"})
	if _, ok := d.Get("show ip arp"); ok {
		t.Error("una salida con pipe no es la tabla completa")
	}
	if _, ok := d.Get("show ip route"); ok {
		t.Error("otro comando")
	}
	d = devFrom("A_1.1.1.1", map[string]string{"sh ip arp": "x"})
	if _, ok := d.Get("show ip arp"); !ok {
		t.Error("abreviatura")
	}
}

// C2c: una línea con forma de ruta que el parser no pudo leer se avisa, no se pierde en silencio.
func TestPathAvisaRutaNoLeida(t *testing.T) {
	a := devFrom("A_10.0.0.1", map[string]string{"show ip route": "Gateway of last resort is not set\n\nC        10.0.0.0/24 is directly connected, Vlan1\nO        172.16.9.0 [110/2] via 10.0.0.2, 00:00:01, Vlan1\n"})
	r := New([]*Dev{a}, now).Path("10.0.0.5", "172.16.9.1")
	if !strings.Contains(strings.Join(r.Warnings, "|"), "no leída") {
		t.Errorf("%v", r.Warnings)
	}
}

// I1: un trunk o port-channel sin vecino no es un puerto de acceso.
func TestTraceTrunkSinVecino(t *testing.T) {
	st := "Port      Name   Status       Vlan  Duplex  Speed Type\nGi1/0/1   x      connected    trunk a-full  a-1000 10/100/1000BaseTX\n"
	a := devFrom("A_10.0.0.1", map[string]string{"show mac address-table": macTbl, "show interfaces status": st})
	r := New([]*Dev{a}, now).Trace("aabb.cc00.0a01")
	if r.End != "trunk-sin-vecino" || r.Access != nil || len(r.Warnings) == 0 {
		t.Fatalf("trunk: %+v", r)
	}
	po := strings.Replace(macTbl, "Gi1/0/1", "Po1", 1)
	b := devFrom("B_10.0.0.2", map[string]string{"show mac address-table": po})
	if r = New([]*Dev{b}, now).Trace("aabb.cc00.0a01"); r.End != "trunk-sin-vecino" || r.Access != nil {
		t.Fatalf("Po: %+v", r)
	}
	c := devFrom("C_10.0.0.3", map[string]string{"show mac address-table": macTbl})
	if r = New([]*Dev{c}, now).Trace("aabb.cc00.0a01"); r.End != "access" {
		t.Fatalf("sin dato de trunk sigue siendo acceso: %+v", r)
	}
}

// I2: un teléfono o AP con CDP en el puerto es un equipo extremo: el puerto es de acceso.
func TestTraceVecinoExtremoEsAcceso(t *testing.T) {
	ph := "Device ID: SEP1\n  IP address: 10.0.0.9\nPlatform: Cisco IP Phone 7960,  Capabilities: Host Phone\nInterface: GigabitEthernet1/0/1,  Port ID (outgoing port): Port 1\n"
	a := devFrom("A_10.0.0.1", map[string]string{"show mac address-table": macTbl, "show cdp neighbors detail": ph})
	r := New([]*Dev{a}, now).Trace("aabb.cc00.0a01")
	if r.End != "access" || r.Access == nil || r.Access.Port != "Gi1/0/1" {
		t.Fatalf("%+v", r)
	}
}

func pathDev(key, route string) *Dev {
	return devFrom(key, map[string]string{"show ip route": "Gateway of last resort is not set\n\n" + route})
}

func devsOf(r PathResult) string {
	var l []string
	for _, h := range r.Hops {
		l = append(l, h.Device+":"+h.Status)
	}
	return strings.Join(l, ",")
}

// I3: el next-hop iBGP a un loopback remoto se resuelve por la tabla del mismo equipo;
// el equipo intermedio no se salta.
func TestPathNextHopRecursivo(t *testing.T) {
	a := pathDev("A_10.0.0.1", "C        10.0.0.0/24 is directly connected, Vlan1\nB        172.16.0.0/16 [200/0] via 192.168.99.1, 00:01:00\nO        192.168.99.1/32 [110/2] via 10.0.0.2, 00:01:00, Vlan1\n")
	b := pathDev("B_10.0.0.2", "S        172.16.0.0/16 [1/0] via 10.0.0.3\n")
	c := pathDev("C_10.0.0.3", "L        192.168.99.1/32 is directly connected, Loopback0\n")
	r := New([]*Dev{a, b, c}, now).Path("10.0.0.5", "172.16.9.1")
	if !strings.Contains(devsOf(r), "B:ok") || r.Hops[1].Device != "B" || r.Hops[1].Via != "10.0.0.2" {
		t.Errorf("debe pasar por B: %s", devsOf(r))
	}
	// next-hop que no se puede resolver: corte explícito, nunca se salta
	a = pathDev("A_10.0.0.1", "C        10.0.0.0/24 is directly connected, Vlan1\nB        172.16.0.0/16 [200/0] via 203.0.113.1, 00:01:00\n")
	r = New([]*Dev{a}, now).Path("10.0.0.5", "172.16.9.1")
	last := r.Hops[len(r.Hops)-1]
	if last.Status != "cut" || !strings.Contains(last.Reason, "siguiente salto recursivo no resuelto") {
		t.Errorf("%s %+v", devsOf(r), last)
	}
}

// M1: Null0/drop es un corte, nunca "ok" ni "sin ARP".
func TestPathNull0(t *testing.T) {
	for _, rt := range []string{
		"O        10.9.0.0/16 is a summary, 00:10:00, Null0\n",
		"S        10.9.0.0/16 is directly connected, Null0\n",
	} {
		a := pathDev("A_10.0.0.1", "C        10.0.0.0/24 is directly connected, Vlan1\n"+rt)
		r := New([]*Dev{a}, now).Path("10.0.0.5", "10.9.1.1")
		last := r.Hops[len(r.Hops)-1]
		if r.Arrived || last.Status != "cut" || !strings.Contains(last.Reason, "descartado (Null0/drop)") {
			t.Errorf("%q: %s %+v", rt, devsOf(r), last)
		}
	}
	// CEF: una entrada drop más específica no deja caer a la default
	cef := "Prefix               Next Hop             Interface\n10.0.0.0/24          attached             Vlan1\n0.0.0.0/0            10.0.0.2             Vlan1\n10.9.0.0/16          drop                 Null0\n"
	a := devFrom("A_10.0.0.1", map[string]string{"show ip cef": cef})
	r := New([]*Dev{a}, now).Path("10.0.0.5", "10.9.1.1")
	if last := r.Hops[len(r.Hops)-1]; last.Status != "cut" || !strings.Contains(last.Reason, "descartado") {
		t.Errorf("cef: %s %+v", devsOf(r), last)
	}
}

// M2: el camino solo modela la tabla global; el aviso va siempre.
func TestPathAvisoAlcance(t *testing.T) {
	r := load(t).Path("10.1.10.20", "10.1.20.50")
	if !strings.Contains(strings.Join(r.Warnings, "|"), "solo tabla global; VRF, PBR y NAT no modelados") {
		t.Errorf("%v", r.Warnings)
	}
}

// I4: una salida filtrada con pipe no se usa como tabla completa.
func TestSalidaFiltradaNoEsTabla(t *testing.T) {
	arpFull := "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\nInternet  10.0.0.5   1   aabb.cc00.0a01  ARPA   Vlan10\nInternet  10.0.0.6   1   aabb.cc00.0a02  ARPA   Vlan10\n"
	arpOne := "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\nInternet  10.0.0.6   1   aabb.cc00.0a02  ARPA   Vlan10\n"
	old := now.Add(-48 * time.Hour)
	a := NewDev("A_10.0.0.1", map[string]Evidence{
		"show ip arp":                    {Text: arpFull, At: old},
		"show ip arp | include 10.0.0.6": {Text: arpOne, At: now},
	})
	r := New([]*Dev{a}, now).Find("10.0.0.5")
	if len(r.Hits) != 1 || !strings.Contains(strings.Join(r.Warnings, "|"), "filtrada") {
		t.Errorf("debe usar la completa y avisar de la filtrada más reciente: %+v", r)
	}
	b := NewDev("B_10.0.0.2", map[string]Evidence{"show ip arp | include 10.0.0.6": {Text: arpOne, At: now}})
	r = New([]*Dev{b}, now).Find("10.0.0.5")
	if len(r.Hits) != 0 || !strings.Contains(strings.Join(r.Warnings, "|"), "solo hay salida filtrada") {
		t.Errorf("solo filtrada: aviso, no tabla: %+v", r)
	}
}

// I6: sin la evidencia, "0 problemas / 0 coincidencias / no cabe en nadie" no puede parecer un "todo bien".
func TestSinEvidenciaNoEsTodoBien(t *testing.T) {
	arp := "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\nInternet  10.0.0.6   1   aabb.cc00.0a02  ARPA   Vlan10\n"
	a := devFrom("A_10.0.0.1", map[string]string{"show ip arp": arp})
	b := devFrom("B_10.0.0.2", map[string]string{"show version": "basura\n"})
	f := New([]*Dev{a, b}, now)

	h := f.Health()
	if len(h.Issues) != 0 || h.Checked["status"] != 0 || !strings.Contains(strings.Join(h.Warnings, "|"), "B: sin evidencia utilizable de show interfaces status") {
		t.Errorf("health: %+v", h)
	}
	if txt := f.HealthText(h); !strings.Contains(txt, "con dato") {
		t.Errorf("el texto debe decir cuántos equipos tienen dato: %s", txt)
	}
	r := f.Find("10.0.0.5")
	if r.Checked["show ip arp"] != 1 || !strings.Contains(strings.Join(r.Warnings, "|"), "sin show ip arp: B") {
		t.Errorf("find: %+v", r)
	}
	c := f.Capacity(1 << 30)
	if len(c.Flash) != 0 || len(c.FlashNoData) != 2 || !strings.Contains(f.CapacityText(c), "sin dato") {
		t.Errorf("capacity: %+v", c)
	}
}
