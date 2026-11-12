package change

import (
	"os"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/capture"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/playbooks"
)

func dev(t *testing.T, file string) capture.Device {
	t.Helper()
	b, err := os.ReadFile("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	return capture.Device{Address: "192.0.2.1", Hostname: "DIST-01", State: "completed", Outputs: capture.Split(string(b))}
}

func TestParseSnapshot(t *testing.T) {
	s := Parse(dev(t, "pre.txt").Outputs)
	checks := map[string]bool{
		"version": s.Version == "17.09.04a",
		"uptime":  s.UptimeMinutes == ((365+14+3)*24+4)*60+5,
		"ifaces":  len(s.Interfaces) == 6 && s.Interfaces["Vlan1"] == "administratively down/down" && s.Interfaces["Vlan10"] == "up/up",
		"cdp":     len(s.CDP) == 2 && s.CDP["ACC-02.ejemplo.lab @ GigabitEthernet1/0/2"] == "GigabitEthernet1/1/1",
		"lldp":    len(s.LLDP) == 1 && s.LLDP["ACC-01.ejemplo.lab @ Gi1/0/1"] == "Gi1/1/1",
		"ospf":    len(s.OSPF) == 2 && s.OSPF["192.0.2.3 @ GigabitEthernet1/0/24"] == "FULL" && s.OSPF["192.0.2.2 @ Vlan10"] == "FULL",
		"bgp":     len(s.BGP) == 2 && s.BGP["192.0.2.9"] == "Established" && s.BGPPfx["192.0.2.9"] == 118,
		"routes":  s.Routes["ospf 1"] == 15 && s.Routes["bgp 65001"] == 138 && s.Routes["connected"] == 6 && len(s.Routes) == 5,
		"mac":     s.MACs["10"] == 3 && s.MACs["20"] == 4 && len(s.MACs) == 2,
		"arp":     s.ARP["Vlan10"] == 3 && s.ARP["Vlan20"] == 4,
		"hsrp":    s.HSRP["Vl10 grupo 10"] == "Active" && s.HSRP["Vl20 grupo 20"] == "Standby",
		"stp":     len(s.STPRoot) == 3 && s.STPRoot["VLAN0010"] == "24586 00a3.d14f.0001",
		"config":  s.Config != nil && len(s.Config.Children) > 5,
	}
	for k, ok := range checks {
		if !ok {
			t.Errorf("%s: %+v", k, s)
		}
	}
}

func TestCompareRegressions(t *testing.T) {
	r := Compare([]capture.Device{dev(t, "pre.txt")}, []capture.Device{dev(t, "post.txt")})
	if len(r.Devices) != 1 {
		t.Fatalf("devices = %d", len(r.Devices))
	}
	d := r.Devices[0]
	if d.Verdict != Regression {
		t.Fatalf("verdict = %s", d.Verdict)
	}
	want := []struct {
		facet string
		level Level
		sub   string
	}{
		{"interfaces", Regression, "GigabitEthernet1/0/2"},
		{"interfaces", Info, "GigabitEthernet1/0/3"},
		{"cdp", Regression, "ACC-02"},
		{"lldp", Info, "ACC-03"},
		{"ospf", Regression, "192.0.2.3"},
		{"bgp", Regression, "203.0.113.9"},
		{"rutas", Review, "ospf 1: 15 → 5"},
		{"rutas", Review, "bgp 65001: 138 → 118"},
		{"mac", Review, "VLAN 20: 4 → 1"},
		{"arp", Review, "Vlan20: 4 → 2"},
		{"hsrp", Review, "Vl20 grupo 20: Standby → Active"},
		{"stp", Regression, "VLAN0010"},
		{"versión", Info, "17.09.04a → 17.12.04"},
		{"versión", Review, "recarg"},
		{"config", Info, "1 agregadas"},
	}
	for _, w := range want {
		found := false
		for _, f := range d.Findings {
			found = found || f.Facet == w.facet && f.Level == w.level && strings.Contains(f.Detail, w.sub)
		}
		if !found {
			t.Errorf("missing %s/%s %q in %+v", w.facet, w.level, w.sub, d.Findings)
		}
	}
	for _, f := range d.Findings {
		if strings.Contains(f.Detail, "192.0.2.9") || strings.Contains(f.Detail, "ACC-01") || strings.Contains(f.Detail, "VLAN0001") {
			t.Errorf("unchanged item reported: %+v", f)
		}
	}
	if len(d.ConfigDiff) != 1 || d.ConfigDiff[0] != "+ line vty 0 15 > exec-timeout 10 0" {
		t.Errorf("config diff = %q", d.ConfigDiff)
	}
	txt := r.Text()
	if !strings.Contains(txt, "REGRESIÓN") || !strings.Contains(txt, "DIST-01") || !strings.Contains(r.Note, "sin validar en laboratorio") {
		t.Errorf("text:\n%s", txt)
	}
}

func TestCompareNoChanges(t *testing.T) {
	r := Compare([]capture.Device{dev(t, "pre.txt")}, []capture.Device{dev(t, "pre.txt")})
	if d := r.Devices[0]; d.Verdict != OK || len(d.Findings) != 0 {
		t.Fatalf("device = %+v", d)
	}
}

func TestCompareMissingAndFailed(t *testing.T) {
	pre := dev(t, "pre.txt")
	other := capture.Device{Address: "192.0.2.50", Hostname: "NUEVO", State: "completed", Outputs: map[string]string{}}
	failed := pre
	failed.State, failed.Detail, failed.Outputs = "failed", "auth", map[string]string{}
	r := Compare([]capture.Device{pre}, []capture.Device{failed, other})
	if len(r.Devices) != 2 || r.Devices[0].Verdict != Regression || !strings.Contains(r.Devices[0].Findings[0].Detail, "auth") {
		t.Fatalf("failed post = %+v", r.Devices)
	}
	if r.Devices[1].Verdict != Review || r.Devices[1].Hostname != "NUEVO" {
		t.Fatalf("post-only = %+v", r.Devices[1])
	}
	r = Compare([]capture.Device{pre}, nil)
	if r.Devices[0].Verdict != Regression {
		t.Fatalf("missing post = %+v", r.Devices[0])
	}
}

func TestMissingFacetIsReview(t *testing.T) {
	pre, post := dev(t, "pre.txt"), dev(t, "pre.txt")
	post.Outputs = map[string]string{}
	for k, v := range pre.Outputs {
		if k != "show ip bgp summary" {
			post.Outputs[k] = v
		}
	}
	d := Compare([]capture.Device{pre}, []capture.Device{post}).Devices[0]
	if d.Verdict != Review || len(d.Findings) != 1 || d.Findings[0].Facet != "bgp" {
		t.Fatalf("device = %+v", d)
	}
}

func TestPlaybookCoversFacets(t *testing.T) {
	pbs, err := playbook.Load(playbooks.FS)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, p := range pbs {
		if p.ID == "ios-xe/pre-post" {
			for _, c := range p.Commands {
				have[capture.Key(c.Text)] = true
			}
		}
	}
	for f, cmd := range facetCmd {
		if !have[capture.Key(cmd)] {
			t.Errorf("faceta %s: %q no está en ios-xe/pre-post", f, cmd)
		}
	}
}

func TestCompareSinSalidasReconocidas(t *testing.T) {
	vacio := capture.Device{Address: "192.0.2.1", Hostname: "DIST-01", State: "completed", Outputs: capture.Split("% Invalid input detected")}
	for name, c := range map[string][2]capture.Device{
		"vacio-vacio": {vacio, vacio},
		"vacio-pre":   {vacio, dev(t, "post.txt")},
		"vacio-post":  {dev(t, "pre.txt"), vacio},
	} {
		r := Compare([]capture.Device{c[0]}, []capture.Device{c[1]})
		if v := r.Devices[0].Verdict; v != Review && v != Regression {
			t.Errorf("%s: verdict = %s, quería review", name, v)
		}
	}
}
