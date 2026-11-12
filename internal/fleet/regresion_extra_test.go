package fleet

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tmpDirs son las carpetas temporales de los escenarios: sus rutas no entran en el golden.
var tmpDirs []string

const arpHdr = "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"

func arpRow(ip, mac, ifc string) string {
	return fmt.Sprintf("Internet  %-15s  3   %s  ARPA   %s\n", ip, mac, ifc)
}

func macRow(vlan, mac, port string) string {
	return fmt.Sprintf("  %s    %s    DYNAMIC     %s\n", vlan, mac, port)
}

const macHdr = "Vlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n"

// evDev arma un equipo con evidencias a medida (hora, filtradas, truncadas, rechazadas).
func evDev(key string, ev map[string]Evidence) *Dev { return NewDev(key, ev) }

// extraCases son los escenarios que recorren cada aviso, motivo, nota y fila de la flota que los datos de
// ejemplo no alcanzan. Solo usa lo que ya existía antes de la fase 30c.
func extraCases(t *testing.T, add func(name string, v any, text string)) {
	t.Helper()
	trace := func(name string, f *Fleet, q string) {
		r := f.Trace(q)
		add("x-trace-"+name, &r, f.TraceText(r))
	}
	path := func(name string, f *Fleet, a, b string) {
		r := f.Path(a, b)
		add("x-path-"+name, &r, f.PathText(r))
	}
	conn := "C        10.0.0.0/24 is directly connected, Vlan1\n"

	// rastreo: la MAC es del propio equipo, trunk sin vecino, vecino extremo (teléfono), la MAC también en otro equipo
	self := devFrom("A_10.0.0.1", map[string]string{"show mac address-table": macHdr + macRow("10", "aabb.cc00.0a01", "CPU")})
	trace("self", New([]*Dev{self}, now), "aabb.cc00.0a01")
	trunk := devFrom("A_10.0.0.1", map[string]string{"show mac address-table": macHdr + macRow("10", "aabb.cc00.0a01", "Po1")})
	trace("trunk", New([]*Dev{trunk}, now), "aabb.cc00.0a01")
	phone := devFrom("A_10.0.0.1", map[string]string{"show mac address-table": macHdr + macRow("10", "aabb.cc00.0a01", "Gi1/0/5"),
		"show cdp neighbors detail": "Device ID: PHONE1\nEntry address(s):\n  IP address: 10.0.0.77\nPlatform: Cisco IP Phone 7960,  Capabilities: Host Phone\nInterface: GigabitEthernet1/0/5,  Port ID (outgoing port): Port 1\n"})
	trace("phone", New([]*Dev{phone}, now), "aabb.cc00.0a01")
	also := devFrom("B_10.0.0.2", map[string]string{"show mac address-table": macHdr + macRow("10", "aabb.cc00.0a01", "Gi1/0/9")})
	trace("also", New([]*Dev{trunk, also}, now), "aabb.cc00.0a01")
	// la MAC falta en el vecino
	na := devFrom("A_10.0.0.1", map[string]string{"show mac address-table": macHdr + macRow("10", "aabb.cc00.0a01", "Gi1/0/1"), "show cdp neighbors detail": cdp("B", "10.0.0.2", "GigabitEthernet1/0/1", "GigabitEthernet1/0/1")})
	nb := devFrom("B_10.0.0.2", map[string]string{"show mac address-table": macHdr})
	trace("mac-missing", New([]*Dev{na, nb}, now), "aabb.cc00.0a01")
	// una IP con dos MAC en el ARP
	m1 := devFrom("A_10.0.0.1", map[string]string{"show ip arp": arpHdr + arpRow("10.0.0.50", "aabb.cc00.0a01", "Vlan1") + arpRow("10.0.0.50", "aabb.cc00.0a02", "Vlan1"), "show mac address-table": macHdr + macRow("1", "aabb.cc00.0a01", "Gi1/0/3")})
	trace("ip-two-macs", New([]*Dev{m1}, now), "10.0.0.50")
	// más de 32 saltos
	var chain []*Dev
	for i := 1; i <= 60; i++ {
		cmds := map[string]string{"show mac address-table": macHdr + macRow("10", "aabb.cc00.0a01", "Gi1/0/1")}
		cmds["show cdp neighbors detail"] = cdp(fmt.Sprintf("N%02d", i+1), fmt.Sprintf("10.0.1.%d", i+1), "GigabitEthernet1/0/1", "GigabitEthernet1/0/1")
		chain = append(chain, devFrom(fmt.Sprintf("N%02d_10.0.1.%d", i, i), cmds))
	}
	trace("chain", New(chain, now), "aabb.cc00.0a01")

	// camino: CEF en vez de show ip route, líneas de ruta no leídas, descarte, sin siguiente salto
	cef := devFrom("A_10.0.0.1", map[string]string{"show ip cef": "Prefix               Next Hop             Interface\n10.0.0.0/24          attached             Vlan1\n0.0.0.0/0            10.0.0.2             Vlan1\n"})
	path("cef", New([]*Dev{cef}, now), "10.0.0.5", "8.8.8.8")
	path("null0", New([]*Dev{pathDev("A_10.0.0.1", conn+"S        10.9.0.0/16 is directly connected, Null0\n")}, now), "10.0.0.5", "10.9.1.1")
	path("no-nexthop", New([]*Dev{pathDev("A_10.0.0.1", conn+"S        10.6.0.0/16\n")}, now), "10.0.0.5", "10.6.1.1")
	path("no-route", New([]*Dev{pathDev("A_10.0.0.1", conn)}, now), "10.0.0.5", "10.77.1.1")
	path("no-routes-dev", New([]*Dev{pathDev("A_10.0.0.1", conn+"S        172.16.0.0/16 [1/0] via 10.0.0.2\n"), devFrom("B_10.0.0.2", map[string]string{"show ip arp": arpHdr})}, now), "10.0.0.5", "172.16.1.1")
	// destino local, origen con varias puertas de enlace, bucle de enrutamiento
	a := pathDev("A_10.0.0.1", conn+"S        172.16.0.0/16 [1/0] via 10.0.0.2\n")
	b := pathDev("B_10.0.0.2", conn+"S        172.16.0.0/16 [1/0] via 10.0.0.1\n")
	path("loop", New([]*Dev{a, b}, now), "10.0.0.5", "172.16.1.1")
	path("local-dest", New([]*Dev{a, b}, now), "10.0.0.5", "10.0.0.1")
	g1 := devFrom("G1_10.0.0.1", map[string]string{"show ip route": "Gateway of last resort is not set\n\n" + conn, "show ip arp": arpHdr + arpRow("10.0.0.5", "aabb.cc00.0005", "Vlan1")})
	g2 := devFrom("G2_10.0.0.2", map[string]string{"show ip route": "Gateway of last resort is not set\n\n" + conn, "show ip arp": arpHdr + arpRow("10.0.0.5", "aabb.cc00.0005", "Vlan1")})
	path("gateways", New([]*Dev{g1, g2}, now), "10.0.0.5", "10.0.0.9")
	// red conectada: sin ARP del destino, y con ARP pero sin rastro L2
	path("conn-no-arp", New([]*Dev{pathDev("A_10.0.0.1", conn)}, now), "10.0.0.5", "10.0.0.9")
	ca := devFrom("A_10.0.0.1", map[string]string{"show ip route": "Gateway of last resort is not set\n\n" + conn, "show ip arp": arpHdr + arpRow("10.0.0.9", "aabb.cc00.0009", "Vlan1")})
	path("conn-l2-ended", New([]*Dev{ca}, now), "10.0.0.5", "10.0.0.9")
	// recursivos: resuelto, con ECMP, sin ruta y demasiado profundo
	rec := pathDev("A_10.0.0.1", conn+"B        172.16.0.0/16 [200/0] via 192.168.99.1, 00:01:00\nS        192.168.99.0/24 [1/0] via 10.0.0.2\n")
	path("recursive", New([]*Dev{rec, pathDev("B_10.0.0.2", "L        10.0.0.2/32 is directly connected, Vlan1\n")}, now), "10.0.0.5", "172.16.9.1")
	ecmp := pathDev("A_10.0.0.1", conn+"B        172.16.0.0/16 [200/0] via 192.168.99.1, 00:01:00\nS        192.168.99.0/24 [1/0] via 10.0.0.2\n                        [1/0] via 10.0.0.3\n")
	path("recursive-ecmp", New([]*Dev{ecmp}, now), "10.0.0.5", "172.16.9.1")
	nor := pathDev("A_10.0.0.1", conn+"B        172.16.0.0/16 [200/0] via 203.0.113.1, 00:01:00\n")
	path("recursive-unresolved", New([]*Dev{nor}, now), "10.0.0.5", "172.16.9.1")
	deep := "B        172.16.0.0/16 [200/0] via 11.0.0.1, 00:01:00\n"
	for i := 0; i < 10; i++ {
		deep += fmt.Sprintf("S        11.%d.0.0/24 [1/0] via 11.%d.0.1\n", i, i+1)
	}
	path("recursive-deep", New([]*Dev{pathDev("A_10.0.0.1", conn+deep)}, now), "10.0.0.5", "172.16.9.1")
	// más de 64 saltos
	var hops []*Dev
	for i := 1; i <= 70; i++ {
		hops = append(hops, pathDev(fmt.Sprintf("H%02d_10.9.0.%d", i, i), fmt.Sprintf("C        10.9.0.0/24 is directly connected, Vlan1\nS        172.16.0.0/16 [1/0] via 10.9.0.%d\n", i+1)))
	}
	path("long", New(hops, now), "10.9.0.200", "172.16.9.1")

	// lectura de tablas: filtrada sola, filtrada más reciente, truncada, rechazada, formato inesperado
	old, cur := now.Add(-time.Hour), now
	ev := evDev("A_10.0.0.1", map[string]Evidence{
		"show ip arp | include 10.1":       {Text: "x\n", At: cur},
		"show mac address-table":           {Text: macHdr + macRow("10", "aabb.cc00.0a01", "Gi1/0/1"), At: old},
		"show mac address-table | include": {Text: macRow("10", "aabb.cc00.0a01", "Gi1/0/1"), At: cur},
		"show interfaces status":           {Text: "Port Name Status\n", At: cur, Truncated: true},
		"show version":                     {Text: "% Invalid input detected at '^' marker.\n", At: cur},
	})
	fe := New([]*Dev{ev}, now)
	rf := fe.Find("10.1.1.1")
	add("x-find-filtered", &rf, fe.FindText(rf))
	sh := fe.Health()
	add("x-health-truncated", &sh, fe.HealthText(sh))
	sc := fe.Capacity(0)
	add("x-capacity-rejected", &sc, fe.CapacityText(sc))

	// salud: half duplex por estado, errores de contadores
	hd := devFrom("A_10.0.0.1", map[string]string{"show interfaces status": "Port      Name   Status       Vlan  Duplex  Speed Type\nGi1/0/2   uplink connected    10    half    100   10/100BaseTX\nGi1/0/3   sala   err-disabled 10    auto    auto  10/100/1000BaseTX\n"})
	fh := New([]*Dev{hd}, now)
	rh := fh.Health()
	add("x-health-half", &rh, fh.HealthText(rh))

	// carga: carpeta ilegible y topes
	if os.Geteuid() != 0 {
		d := t.TempDir()
		put(t, d, "trabajo_1/SW1_10.0.0.1/r001.txt", errDis)
		blocked := filepath.Join(d, "trabajo_1", "bloqueada")
		os.MkdirAll(blocked, 0o755)
		os.Chmod(blocked, 0)
		defer os.Chmod(blocked, 0o755)
		put(t, d, "trabajo_1/SW1_10.0.0.1/r002.txt", errDis)
		os.Chmod(filepath.Join(d, "trabajo_1", "SW1_10.0.0.1", "r002.txt"), 0)
		fd, err := Load(d, now)
		if err != nil {
			t.Fatal(err)
		}
		hd := fd.Health()
		add("x-load-unreadable", &hd, fd.HealthText(hd))
		tmpDirs = append(tmpDirs, d)
	}
	sTotal, sFile, sEntries, sDevs, sSection, sLine := maxTotal, maxFile, maxEntries, maxDevs, maxSection, maxLine
	defer func() {
		maxTotal, maxFile, maxEntries, maxDevs, maxSection, maxLine = sTotal, sFile, sEntries, sDevs, sSection, sLine
	}()
	maxTotal, maxEntries, maxDevs = 1<<30, 1000, 2
	d := t.TempDir()
	for _, h := range []string{"A_10.0.0.1", "B_10.0.0.2", "C_10.0.0.3", "D_10.0.0.4"} {
		put(t, d, "trabajo_1/"+h+"/r.txt", errDis)
	}
	capped(t, d, "x-load-cap-devs", add)
	maxDevs, maxEntries = 2000, 5
	e := t.TempDir()
	files := map[string]string{}
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("A_10.0.0.1/r%02d.txt", i)] = errDis
	}
	zipOf(t, filepath.Join(e, "trabajo_1", "x.zip"), files)
	capped(t, e, "x-load-cap-entries", add)
	maxEntries, maxTotal = 20000, 2<<20
	g := t.TempDir()
	files = map[string]string{}
	for i := 0; i < 4; i++ {
		files[fmt.Sprintf("A_10.0.0.1/r%d.txt", i)] = hdr("show ntp status") + strings.Repeat("z\n", 512<<10)
	}
	zipOf(t, filepath.Join(g, "trabajo_1", "x.zip"), files)
	capped(t, g, "x-load-cap-bytes", add)
	maxTotal, maxSection, maxLine, maxFile = 1<<30, 200, 1000, 100000
	h := t.TempDir()
	big := strings.Repeat("x", 150) + "\n"
	put(t, h, "trabajo_1/SW1_10.0.0.1/r001.txt", hdr("show ip arp")+big+big+hdr("show ntp status")+"Clock is synchronized, stratum 3\n")
	capped(t, h, "x-load-section", add)
	maxSection, maxLine = 8<<20, 4<<20
	maxFile = 100
	put(t, h, "trabajo_2/SW2_10.0.0.2/r001.txt", hdr("show ntp status")+strings.Repeat("y", 300)+"\n")
	capped(t, h, "x-load-file", add)
}

// capped carga dir y recoge los avisos de carga en el resumen de salud.
func capped(t *testing.T, dir, name string, add func(string, any, string)) {
	t.Helper()
	f, err := Load(dir, now)
	if err != nil {
		t.Fatal(name, err)
	}
	r := f.Health()
	add(name, &r, f.HealthText(r))
}
