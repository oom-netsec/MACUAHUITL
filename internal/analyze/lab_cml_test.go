package analyze

import (
	"strings"
	"testing"
)

// Reglas de log de la v0.6.1: cada patrón casa su línea de ejemplo y no la contraria.
func TestReglasDeLogProtocolos(t *testing.T) {
	rs := rules(t)
	casos := []struct{ id, sev, mala, buena string }{
		{"log-eigrp-vecino-caido", "media", "%DUAL-5-NBRCHANGE: EIGRP-IPv4 100: Neighbor 10.0.12.2 (Ethernet0/1) is down: Auth failure", "%DUAL-5-NBRCHANGE: EIGRP-IPv4 100: Neighbor 10.0.12.2 (Ethernet0/1) is up: new adjacency"},
		{"log-ldp-vecino-caido", "media", "%LDP-5-NBRCHG: LDP Neighbor 192.0.2.2:0 (1) is DOWN (Session KeepAlive Timer expired)", "%LDP-5-NBRCHG: LDP Neighbor 192.0.2.2:0 (1) is UP"},
		{"log-track-caido", "media", "%TRACKING-5-STATE: 1 ip sla 1 reachability Up -> Down", "%TRACKING-5-STATE: 1 ip sla 1 reachability Down -> Up"},
		{"log-track-caido", "media", "%TRACK-6-STATE: 2 interface Et0/1 line-protocol Up -> Down", "%TRACK-6-STATE: 2 interface Et0/1 line-protocol Down -> Up"},
		{"log-fhrp-inestable", "media", "%HSRP-5-STATECHANGE: Vlan10 Grp 10 state Standby -> Init", "%HSRP-5-STATECHANGE: Vlan10 Grp 10 state Standby -> Active"},
		{"log-fhrp-inestable", "media", "%GLBP-6-STATECHANGE: Ethernet0/0 Grp 10 state Active -> Init", "%GLBP-6-STATECHANGE: Ethernet0/0 Grp 10 state Speak -> Active"},
		{"log-fhrp-inestable", "media", "%VRRP-6-STATE: Gi1 IPv4 group 1 state Backup -> Init", "%VRRP-6-STATE: Gi1 IPv4 group 1 state Backup -> Master"},
		{"log-fhrp-inestable", "media", "%VRRP-6-STATECHANGE: Gi0/0 Grp 1 state Master -> Init", "%VRRP-6-STATECHANGE: Gi0/0 Grp 1 state Init -> Master"},
		{"log-ospf-router-id-duplicado", "alta", "%OSPF-4-DUP_RTRID_NBR: OSPF detected duplicate router-id 192.0.2.1 from 10.0.12.2 on interface Ethernet0/1", "%OSPF-5-ADJCHG: Process 1, Nbr 192.0.2.1 on Ethernet0/1 from LOADING to FULL, Loading Done"},
		{"log-ospf-router-id-duplicado", "alta", "%OSPF-4-DUP_RTRID_AREA: OSPF detected duplicate router-id 192.0.2.1 from 10.0.12.2 in Area 0", "%OSPF-4-ERRRCV: Received invalid packet"},
		{"log-bfd-sesion-caida", "media", "%BFDFSM-6-BFD_SESS_DOWN: BFD-SYSLOG: BFD session ld:1 handle:1 is going Down Reason: ECHO FAILURE", "%BFDFSM-6-BFD_SESS_UP: BFD-SYSLOG: BFD session ld:1 handle:1 is going UP"},
		{"log-isis-adyacencia-caida", "media", "%CLNS-5-ADJCHANGE: ISIS: Adjacency to R2 (Ethernet0/1) Down, hold time expired", "%CLNS-5-ADJCHANGE: ISIS: Adjacency to R2 (Ethernet0/1) Up, new adjacency"},
	}
	for _, c := range casos {
		var r *Rule
		for i := range rs {
			if rs[i].ID == c.id {
				r = &rs[i]
			}
		}
		if r == nil {
			t.Errorf("falta la regla %s", c.id)
			continue
		}
		if r.Severity != c.sev || r.TitleEn == "" || r.ExplanationEn == "" || r.ActionEn == "" {
			t.Errorf("%s: severidad %q o textos en inglés incompletos", c.id, r.Severity)
		}
		for linea, quiere := range map[string]bool{c.mala: true, c.buena: false} {
			f := Analyze(bundleOf("show logging", linea+"\n"), rs, Options{}).Findings
			got := false
			for _, x := range f {
				got = got || x.Rule == c.id
			}
			if got != quiere {
				t.Errorf("%s con %q: hallazgo=%v, quería %v", c.id, linea, got, quiere)
			}
		}
	}
}

func hallazgo(fs []Finding, id string, round int) (Finding, bool) {
	for _, f := range fs {
		if f.Rule == id && f.Round == round {
			return f, true
		}
	}
	return Finding{}, false
}

const (
	eigrpHdr = "EIGRP-IPv4 Neighbors for AS(100)\nH   Address                 Interface              Hold Uptime   SRTT   RTO  Q  Seq\n                                                   (sec)         (ms)       Cnt Num\n"
	eigrpA   = "0   10.0.12.2               Et0/1                    12 00:05:23    8   100  0  15\n"
	eigrpB   = "1   10.0.14.2               Et0/3                    13 00:02:10   16    96  0  9\n"
)

func TestEIGRPVecinoPerdido(t *testing.T) {
	rs := rules(t)
	r := Analyze(bundleOf("show ip eigrp neighbors", eigrpHdr+eigrpA+eigrpB, eigrpHdr+eigrpA, eigrpHdr+eigrpA), rs, Options{})
	f, ok := hallazgo(r.Findings, "eigrp-vecino-perdido", 2)
	if !ok || f.Severity != "alta" || !strings.Contains(f.Detail, "10.0.14.2") || !strings.Contains(f.Detail, "Eth0/3") || len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0], "10.0.12.2") {
		t.Fatalf("hallazgo %+v", f)
	}
	if _, ok := hallazgo(r.Findings, "eigrp-vecino-perdido", 3); ok {
		t.Error("la ronda 3 no perdió nada")
	}
	// ronda ilegible: aviso, sin hallazgo
	r = Analyze(bundleOf("show ip eigrp neighbors", eigrpHdr+eigrpA+eigrpB, "% Invalid input\n"), rs, Options{})
	if len(r.Findings) != 0 || len(r.Warnings) == 0 {
		t.Errorf("ilegible: %+v %+v", r.Findings, r.Warnings)
	}
}

const ldpA = "    Peer LDP Ident: 192.0.2.2:0; Local LDP Ident 192.0.2.1:0\n        State: Oper; Msgs sent/rcvd: 28/27; Downstream\n"
const ldpB = "    Peer LDP Ident: 192.0.2.3:0; Local LDP Ident 192.0.2.1:0\n        State: Oper; Msgs sent/rcvd: 14/13; Downstream\n"

func TestLDPVecinoPerdido(t *testing.T) {
	r := Analyze(bundleOf("show mpls ldp neighbor", ldpA+ldpB, ldpA, ldpA), rules(t), Options{})
	f, ok := hallazgo(r.Findings, "ldp-vecino-perdido", 2)
	if !ok || f.Severity != "alta" || !strings.Contains(f.Detail, "192.0.2.3:0") || len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0], "192.0.2.2:0") {
		t.Fatalf("hallazgo %+v", f)
	}
	if _, ok := hallazgo(r.Findings, "ldp-vecino-perdido", 3); ok {
		t.Error("la ronda 3 no perdió nada")
	}
}

func TestTrackCaido(t *testing.T) {
	hdr := "Track Type        Instance                  Parameter        State Last Change\n"
	up := "2     interface   Ethernet0/1               line-protocol    Up    1d02h\n"
	down := "1     ip sla      1                         reachability     Down  00:01:02\n"
	r := Analyze(bundleOf("show track brief", hdr+up, hdr+down+up), rules(t), Options{})
	f, ok := hallazgo(r.Findings, "track-caido", 2)
	if _, otra := hallazgo(r.Findings, "track-caido", 1); otra || !ok || f.Severity != "media" || !strings.Contains(f.Detail, "ip sla") || len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0], "Down") {
		t.Fatalf("hallazgos %+v", r.Findings)
	}
}

func TestGLBPyVRRP(t *testing.T) {
	rs := rules(t)
	gh := "Interface   Grp  Fwd Pri State    Address         Active router   Standby router\n"
	g1 := gh + "Et0/0       10   -   110 Active   10.0.0.254      local           10.0.0.2\nEt0/0       10   2   -   Listen   0007.b400.0a02  10.0.0.2        -\n"
	g2 := gh + "Et0/0       10   -   110 Speak    10.0.0.254      unknown         unknown\nEt0/0       10   2   -   Listen   0007.b400.0a02  10.0.0.2        -\n"
	r := Analyze(bundleOf("show glbp brief", g1, g2), rs, Options{})
	if f, ok := hallazgo(r.Findings, "glbp-inestable", 2); !ok || !strings.Contains(f.Detail, "Active → Speak") || !strings.Contains(f.Detail, "Et0/0 grupo 10") {
		t.Errorf("glbp-inestable: %+v", r.Findings)
	}
	if f, ok := hallazgo(r.Findings, "glbp-estado-anomalo", 2); !ok || strings.Contains(f.Detail, "10/2") || len(f.Evidence) != 1 {
		t.Errorf("glbp-estado-anomalo: %+v", r.Findings)
	}
	// Listen en un AVF es normal; un AVG sin Active router es anómalo aunque esté en Active
	if _, ok := hallazgo(Analyze(bundleOf("show glbp brief", g1), rs, Options{}).Findings, "glbp-estado-anomalo", 1); ok {
		t.Error("Listen es normal en GLBP")
	}
	g3 := gh + "Et0/0       10   -   110 Active   10.0.0.254      unknown         -\n"
	if _, ok := hallazgo(Analyze(bundleOf("show glbp brief", g3), rs, Options{}).Findings, "glbp-estado-anomalo", 1); !ok {
		t.Error("AVG con Active router unknown debe ser anómalo")
	}
	if _, ok := hallazgo(Analyze(bundleOf("show glbp brief", g1), rs, Options{}).Findings, "hsrp-estado-anomalo", 1); ok {
		t.Error("las reglas de HSRP no leen show glbp brief")
	}

	vh := "Interface          Grp Pri Time  Own Pre State   Master addr     Group addr\n"
	v1 := vh + "Gi0/0                1 110 3570       Y  Master  10.0.0.1        10.0.0.254\n"
	v2 := vh + "Gi0/0                1 110 3570       Y  Backup  10.0.0.2        10.0.0.254\n"
	v3 := vh + "Gi0/0                1 110 3570       Y  Init    0.0.0.0         10.0.0.254\n"
	r = Analyze(bundleOf("show vrrp brief", v1, v2, v3), rs, Options{})
	if f, ok := hallazgo(r.Findings, "vrrp-inestable", 2); !ok || !strings.Contains(f.Detail, "Master → Backup") {
		t.Errorf("vrrp-inestable: %+v", r.Findings)
	}
	if _, ok := hallazgo(r.Findings, "vrrp-estado-anomalo", 2); ok {
		t.Error("Backup es normal en VRRP")
	}
	if _, ok := hallazgo(r.Findings, "vrrp-estado-anomalo", 3); !ok {
		t.Errorf("Init debe ser anómalo: %+v", r.Findings)
	}
}

const ospfH = "Neighbor ID     Pri   State           Dead Time   Address         Interface\n"

func ospfRow(id, addr, iface string) string {
	return id + "        1   FULL/DR         00:00:33    " + addr + "       " + iface + "\n"
}

func TestOSPFRouterIDCambiado(t *testing.T) {
	rs := rules(t)
	// caso del laboratorio: el vecino de Et0/2 pasa del RID .3 al .1, que ya es el de Et0/1
	r1 := ospfH + ospfRow("192.0.2.1", "10.0.12.2", "Ethernet0/1") + ospfRow("192.0.2.3", "10.0.13.2", "Ethernet0/2")
	r2 := ospfH + ospfRow("192.0.2.1", "10.0.12.2", "Ethernet0/1") + ospfRow("192.0.2.1", "10.0.13.2", "Ethernet0/2")
	r := Analyze(bundleOf("show ip ospf neighbor", r1, r2), rs, Options{})
	f, ok := hallazgo(r.Findings, "ospf-router-id-cambio", 2)
	if !ok || f.Severity != "alta" ||
		!strings.Contains(f.Detail, "el vecino en Ethernet0/2 (10.0.13.2) cambió de router-id 192.0.2.3 → 192.0.2.1") ||
		!strings.Contains(f.Detail, "el mismo router-id aparece en Ethernet0/1: posible router-id duplicado") {
		t.Fatalf("rid_changed: %+v", f)
	}
	if _, perdido := hallazgo(r.Findings, "ospf-vecino-perdido", 2); perdido {
		t.Error("un RID que cambió no es un vecino perdido")
	}
	// cambio de RID sin que el nuevo aparezca en otra interfaz: sin aviso de duplicado
	r2b := ospfH + ospfRow("192.0.2.1", "10.0.12.2", "Ethernet0/1") + ospfRow("192.0.2.7", "10.0.13.2", "Ethernet0/2")
	f, ok = hallazgo(Analyze(bundleOf("show ip ospf neighbor", r1, r2b), rs, Options{}).Findings, "ospf-router-id-cambio", 2)
	if !ok || strings.Contains(f.Detail, "duplicado") {
		t.Errorf("sin duplicado: %+v", f)
	}
	// dos enlaces al mismo router sin cambio: nada
	two := ospfH + ospfRow("192.0.2.9", "10.0.91.1", "Gi0/0/1") + ospfRow("192.0.2.9", "10.0.92.1", "Gi0/0/2")
	r = Analyze(bundleOf("show ip ospf neighbor", two, two), rs, Options{})
	for _, f := range r.Findings {
		if strings.HasPrefix(f.Rule, "ospf-") {
			t.Errorf("dos enlaces al mismo router no son hallazgo: %+v", f)
		}
	}
	// un vecino que de verdad desaparece sigue siendo lost, no rid_changed
	gone := ospfH + ospfRow("192.0.2.1", "10.0.12.2", "Ethernet0/1")
	r = Analyze(bundleOf("show ip ospf neighbor", r1, gone), rs, Options{})
	if _, ok := hallazgo(r.Findings, "ospf-vecino-perdido", 2); !ok {
		t.Error("el vecino que desaparece debe seguir dando lost")
	}
	if _, ok := hallazgo(r.Findings, "ospf-router-id-cambio", 2); ok {
		t.Error("desaparecer no es cambiar de RID")
	}
}

// Un equipo que se queda sin ningún vecino EIGRP imprime solo la línea del AS: el vecino perdido se reporta.
func TestEIGRPSinVecinosReportaPerdido(t *testing.T) {
	r := Analyze(bundleOf("show ip eigrp neighbors", eigrpHdr+eigrpA, "EIGRP-IPv4 Neighbors for AS(100)\n"), rules(t), Options{})
	f, ok := hallazgo(r.Findings, "eigrp-vecino-perdido", 2)
	if !ok || len(f.Evidence) != 1 || !strings.Contains(f.Detail, "10.0.12.2") || len(r.Warnings) != 0 {
		t.Fatalf("hallazgo %+v avisos %v", r.Findings, r.Warnings)
	}
}

// El mismo vecino e interfaz en dos AS son vecinos distintos: perderlo en uno da hallazgo aunque siga en el otro.
func TestEIGRPClaveConAS(t *testing.T) {
	as := func(n string) string {
		return "EIGRP-IPv4 Neighbors for AS(" + n + ")\nH   Address                 Interface              Hold Uptime   SRTT   RTO  Q  Seq\n                                                   (sec)         (ms)       Cnt Num\n" + eigrpA
	}
	r := Analyze(bundleOf("show ip eigrp neighbors", as("100")+as("200"), as("200")), rules(t), Options{})
	if f, ok := hallazgo(r.Findings, "eigrp-vecino-perdido", 2); !ok || !strings.Contains(f.Detail, "100") {
		t.Fatalf("hallazgos %+v", r.Findings)
	}
}

// LDP sin ningún vecino deja la tabla vacía: el hallazgo cita igual una línea de evidencia.
func TestLDPTodosCaidosConEvidencia(t *testing.T) {
	for _, vacia := range []string{"\n", "  \n\n"} {
		r := Analyze(bundleOf("show mpls ldp neighbor", ldpA+ldpB, vacia), rules(t), Options{})
		f, ok := hallazgo(r.Findings, "ldp-vecino-perdido", 2)
		if !ok || len(f.Evidence) == 0 || strings.TrimSpace(f.Evidence[0]) == "" {
			t.Errorf("%q: hallazgo %+v", vacia, r.Findings)
		}
	}
}

// Solo las transiciones hacia Init del grupo FHRP casan; los cambios normales de un failover planeado no.
func TestFHRPInestableSoloInit(t *testing.T) {
	rs := rules(t)
	casos := map[string]bool{
		"%GLBP-6-STATECHANGE: Ethernet0/0 Grp 10 state Active -> Init":          true,
		"%HSRP-5-STATECHANGE: Vlan10 Grp 10 state Active -> Init":               true,
		"%VRRP-6-STATE: Gi1 IPv4 group 1 state MASTER -> INIT":                  true,
		"%HSRP-5-STATECHANGE: Vlan10 Grp 10 state Active -> Speak":              false,
		"%HSRP-5-STATECHANGE: Vlan10 Grp 10 state Init -> Listen":               false,
		"%HSRP-5-STATECHANGE: Vlan10 Grp 10 state Standby -> Listen":            false,
		"%GLBP-6-FWDSTATECHANGE: Ethernet0/0 Grp 10 Fwd 1 state Active -> Init": false,
	}
	for linea, quiere := range casos {
		_, got := hallazgo(Analyze(bundleOf("show logging", linea+"\n"), rs, Options{}).Findings, "log-fhrp-inestable", 1)
		if got != quiere {
			t.Errorf("%q: hallazgo=%v, quería %v", linea, got, quiere)
		}
	}
}
