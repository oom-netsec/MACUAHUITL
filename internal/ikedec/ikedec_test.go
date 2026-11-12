package ikedec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, name string) Report {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return Decode(string(b))
}

func codes(r Report) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range r.Findings {
		m[f.Code] = f
	}
	return m
}

// Reglas sin validar en laboratorio: las fixtures siguen la documentación pública de Cisco.
func TestFixtures(t *testing.T) {
	for file, c := range map[string]struct{ want, not []string }{
		"ikev1_p1_mismatch.txt":      {want: []string{"p1-propuesta"}, not: []string{"psk", "sin-respuesta"}},
		"ikev1_psk_mismatch.txt":     {want: []string{"psk", "retrans-key-exch"}, not: []string{"p1-propuesta", "sin-respuesta"}},
		"ikev1_no_response.txt":      {want: []string{"sin-respuesta"}, not: []string{"psk", "p1-propuesta"}},
		"ikev1_p2_proxy.txt":         {want: []string{"proxy-id"}, not: []string{"p2-propuesta", "p1-propuesta", "pfs"}},
		"ikev1_p2_transform_pfs.txt": {want: []string{"p2-propuesta", "pfs"}, not: []string{"proxy-id"}},
		"ikev2_no_proposal.txt":      {want: []string{"p1-propuesta"}, not: []string{"nat-t", "p2-propuesta"}},
		"ikev2_auth_fail.txt":        {want: []string{"psk", "nat-t", "sin-respuesta"}, not: []string{"p1-propuesta"}},
		"ikev2_ts_identity.txt":      {want: []string{"identidad", "proxy-id", "dpd"}, not: []string{"psk", "sin-respuesta"}},
		"show_ipsec_sa_oneway.txt":   {want: []string{"ipsec-unidireccional", "ipsec-sin-sa", "ipsec-errores"}, not: []string{"ipsec-solo-entrada"}},
		"show_sa_tables.txt":         {want: []string{"sa-estado", "nat-t"}},
		"asa_ikev1.txt":              {want: []string{"p1-propuesta", "proxy-id", "psk"}},
	} {
		r := load(t, file)
		got := codes(r)
		for _, w := range c.want {
			f, ok := got[w]
			if !ok {
				t.Errorf("%s: falta %s; hallazgos %v", file, w, keys(got))
				continue
			}
			if f.Explanation == "" || f.Action == "" || len(f.Evidence) == 0 {
				t.Errorf("%s/%s incompleto: %+v", file, w, f)
			}
		}
		for _, n := range c.not {
			if _, ok := got[n]; ok {
				t.Errorf("%s: sobra %s: %+v", file, n, got[n])
			}
		}
	}
}

func keys(m map[string]Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestIKEv1ProposalsAndPhases(t *testing.T) {
	r := load(t, "ikev1_p1_mismatch.txt")
	if len(r.Proposals) != 2 || r.Proposals[0].Result != "rechazada" || !strings.Contains(r.Proposals[0].Detail, "encryption DES-CBC") {
		t.Fatalf("propuestas: %+v", r.Proposals)
	}
	if d := codes(r)["p1-propuesta"].Explanation; !strings.Contains(d, "cifrado") || !strings.Contains(d, "grupo DH") || !strings.Contains(d, "hash") {
		t.Errorf("detalle: %s", d)
	}
	if r.Phase1 != "falló" || r.Phase2 != "sin datos" {
		t.Errorf("fases: %s / %s", r.Phase1, r.Phase2)
	}
	p := load(t, "ikev1_p2_proxy.txt")
	if p.Phase1 != "establecida" || p.Phase2 != "falló" || p.Proposals[0].Phase != 2 || p.Proposals[0].Result != "aceptada" {
		t.Errorf("proxy: %s / %s %+v", p.Phase1, p.Phase2, p.Proposals)
	}
}

func TestIKEv2ReceivedVsExpected(t *testing.T) {
	r := load(t, "ikev2_no_proposal.txt")
	var recv, exp string
	for _, p := range r.Proposals {
		switch p.Source {
		case "recibida del par":
			recv = p.Detail
		case "esperada (local)":
			exp = p.Detail
		}
	}
	if !strings.Contains(recv, "Group 2") || !strings.Contains(exp, "Group 14") {
		t.Fatalf("%+v", r.Proposals)
	}
}

func TestShowCounters(t *testing.T) {
	r := load(t, "show_ipsec_sa_oneway.txt")
	if len(r.IPsec) != 2 {
		t.Fatalf("%+v", r.IPsec)
	}
	a := r.IPsec[0]
	if a.Peer != "192.0.2.2" || a.Encaps != 152 || a.Decaps != 0 || !a.HasSA || !strings.Contains(a.Local, "10.1.1.0") {
		t.Fatalf("%+v", a)
	}
	if b := r.IPsec[1]; b.HasSA || b.Counters["send errors"] != 3 {
		t.Fatalf("%+v", b)
	}
	s := load(t, "show_sa_tables.txt")
	states := map[string]string{}
	for _, sa := range s.SAs {
		states[sa.Peer] = sa.State
	}
	if states["203.0.113.9"] != "MM_NO_STATE" || states["192.0.2.2"] != "QM_IDLE" || states["198.51.100.9"] != "IN-NEG" || states["198.51.100.2"] != "READY" {
		t.Fatalf("%+v", s.SAs)
	}
	for _, sa := range s.SAs {
		if sa.Peer == "198.51.100.2" && !strings.Contains(sa.Detail, "DH Grp:14") {
			t.Errorf("detalle IKEv2: %+v", sa)
		}
	}
}

func TestUnknownInputAndText(t *testing.T) {
	r := Decode("hola\nnada que ver")
	if len(r.Findings) != 0 || !strings.Contains(r.Text(), "No se reconoció") {
		t.Fatal(r.Text())
	}
	r = load(t, "asa_ikev1.txt")
	txt := r.Text()
	if !strings.Contains(txt, "sin validar en laboratorio") || !strings.Contains(txt, "Acción:") {
		t.Fatal(txt)
	}
	Decode(strings.Repeat("ISAKMP:      x\n", 10000)) // entrada grande sin propuesta abierta: no truena
}
