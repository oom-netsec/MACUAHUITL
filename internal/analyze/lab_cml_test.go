package analyze

import "testing"

// Reglas de log de la v0.6.1: cada patrón casa su línea de ejemplo y no la contraria.
func TestReglasDeLogProtocolos(t *testing.T) {
	rs := rules(t)
	casos := []struct{ id, sev, mala, buena string }{
		{"log-eigrp-vecino-caido", "media", "%DUAL-5-NBRCHANGE: EIGRP-IPv4 100: Neighbor 10.0.12.2 (Ethernet0/1) is down: Auth failure", "%DUAL-5-NBRCHANGE: EIGRP-IPv4 100: Neighbor 10.0.12.2 (Ethernet0/1) is up: new adjacency"},
		{"log-ldp-vecino-caido", "media", "%LDP-5-NBRCHG: LDP Neighbor 10.255.0.2:0 (1) is DOWN (Session KeepAlive Timer expired)", "%LDP-5-NBRCHG: LDP Neighbor 10.255.0.2:0 (1) is UP"},
		{"log-track-caido", "media", "%TRACKING-5-STATE: 1 ip sla 1 reachability Up -> Down", "%TRACKING-5-STATE: 1 ip sla 1 reachability Down -> Up"},
		{"log-track-caido", "media", "%TRACK-6-STATE: 2 interface Et0/1 line-protocol Up -> Down", "%TRACK-6-STATE: 2 interface Et0/1 line-protocol Down -> Up"},
		{"log-fhrp-inestable", "media", "%HSRP-5-STATECHANGE: Vlan10 Grp 10 state Standby -> Init", "%HSRP-5-STATECHANGE: Vlan10 Grp 10 state Standby -> Active"},
		{"log-fhrp-inestable", "media", "%GLBP-6-STATECHANGE: Ethernet0/0 Grp 50 state Active -> Speak", "%GLBP-6-STATECHANGE: Ethernet0/0 Grp 50 state Speak -> Active"},
		{"log-fhrp-inestable", "media", "%VRRP-6-STATE: Gi1 IPv4 group 1 state Backup -> Init", "%VRRP-6-STATE: Gi1 IPv4 group 1 state Backup -> Master"},
		{"log-fhrp-inestable", "media", "%VRRP-6-STATECHANGE: Gi0/0 Grp 1 state Master -> Init", "%VRRP-6-STATECHANGE: Gi0/0 Grp 1 state Init -> Master"},
		{"log-ospf-router-id-duplicado", "alta", "%OSPF-4-DUP_RTRID_NBR: OSPF detected duplicate router-id 10.255.0.1 from 10.0.12.2 on interface Ethernet0/1", "%OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.1 on Ethernet0/1 from LOADING to FULL, Loading Done"},
		{"log-ospf-router-id-duplicado", "alta", "%OSPF-4-DUP_RTRID_AREA: OSPF detected duplicate router-id 10.255.0.1 from 10.0.12.2 in Area 0", "%OSPF-4-ERRRCV: Received invalid packet"},
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
