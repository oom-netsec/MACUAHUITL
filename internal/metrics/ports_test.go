package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Los fixtures de show viven en un solo lugar: internal/parse/iosxe/testdata.
func fx(t *testing.T, n string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "parse", "iosxe", "testdata", n+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func port(ps PortStatus, name string) (Port, bool) {
	for _, p := range ps.Ports {
		if p.Name == name {
			return p, true
		}
	}
	return Port{}, false
}

func TestBuildPorts(t *testing.T) {
	ps := BuildPorts(PortTexts{Status: fx(t, "ios152_show-interfaces-status"), Trunk: fx(t, "ios152_show-interfaces-trunk"), Channels: fx(t, "iosxe_show-etherchannel-summary"), HaveTrunk: true, HaveChannels: true})
	if len(ps.Ports) != 9 || len(ps.Warnings) != 0 {
		t.Fatalf("%d puertos, avisos %v: %+v", len(ps.Ports), ps.Warnings, ps.Ports)
	}
	if _, ok := port(ps, "Po1"); ok {
		t.Fatal("un port-channel no es un puerto físico")
	}
	g1, _ := port(ps, "Gi1/0/1")
	if g1.Status != "connected" || !g1.Trunk || g1.Channel != "Po1" || g1.ChannelFlags != "P" || g1.Module != 1 || g1.Stack != 0 || g1.Number != 1 || !g1.AutoNeg || g1.SpeedMbps != 1000 || g1.DuplexMode != "full" || g1.Kind != "Gi" || g1.TrunkNative != "1" {
		t.Fatalf("Gi1/0/1 = %+v", g1)
	}
	g3, _ := port(ps, "Gi1/0/3")
	if g3.Description != "sala de juntas" || g3.VLAN != "10" || g3.Trunk || g3.Channel != "" || g3.SpeedMbps != 100 || g3.Type != "10/100/1000BaseTX" {
		t.Fatalf("Gi1/0/3 = %+v", g3)
	}
	if g, _ := port(ps, "Gi1/0/6"); g.Status != "err-disabled" || g.SpeedMbps != 0 || !g.AutoNeg || g.DuplexMode != "auto" {
		t.Fatalf("Gi1/0/6 = %+v", g)
	}
	if g, _ := port(ps, "Gi1/0/12"); g.Number != 12 || g.Module != 1 || g.Stack != 0 {
		t.Fatalf("Gi1/0/12 = %+v", g)
	}
	if g, _ := port(ps, "Gi1/1/1"); g.Stack != 1 || g.Number != 1 || g.Type != "1000BaseSX SFP" || g.AutoNeg || g.SpeedMbps != 1000 || g.DuplexMode != "full" {
		t.Fatalf("Gi1/1/1 = %+v", g)
	}
	if g, _ := port(ps, "Te1/1/2"); g.SpeedMbps != 10000 || g.VLAN != "routed" || g.Trunk {
		t.Fatalf("Te1/1/2 = %+v", g)
	}
	if len(ps.Channels) != 2 || ps.Channels[0].Name != "Po1" || ps.Channels[0].State != "SU" || len(ps.Channels[0].Members) != 2 {
		t.Fatalf("canales = %+v", ps.Channels)
	}
}

func TestBuildPortsTrunkPorVLANDelEstado(t *testing.T) {
	// sin show interfaces trunk, la columna VLAN del propio estado dice «trunk»; y se avisa
	ps := BuildPorts(PortTexts{Status: fx(t, "ios152_show-interfaces-status")})
	if g, _ := port(ps, "Gi1/0/1"); !g.Trunk || g.TrunkNative != "" {
		t.Fatalf("Gi1/0/1 = %+v", g)
	}
	w := strings.Join(ps.Warnings, "|")
	if !strings.Contains(w, "show interfaces trunk") || !strings.Contains(w, "show etherchannel summary") {
		t.Fatalf("avisos = %v", ps.Warnings)
	}
	if g, _ := port(ps, "Gi1/0/1"); g.Channel != "" {
		t.Fatalf("sin etherchannel no hay canal: %+v", g)
	}
}

func TestBuildPortsSinEstado(t *testing.T) {
	ps := BuildPorts(PortTexts{})
	if len(ps.Ports) != 0 || len(ps.Warnings) != 1 || !strings.Contains(ps.Warnings[0], "falta el comando show interfaces status") {
		t.Fatalf("= %+v", ps)
	}
	ps = BuildPorts(PortTexts{Status: "% Invalid input detected at '^' marker.\n"})
	if len(ps.Ports) != 0 || !strings.Contains(strings.Join(ps.Warnings, "|"), "no se pudo leer show interfaces status") {
		t.Fatalf("ilegible = %+v", ps)
	}
}

func TestSpeedMbps(t *testing.T) {
	for in, want := range map[string]struct {
		mbps int
		auto bool
	}{"a-1000": {1000, true}, "1000": {1000, false}, "10G": {10000, false}, "a-10G": {10000, true}, "25G": {25000, false}, "100G": {100000, false}, "auto": {0, true}, "": {0, false}, "a-100": {100, true}, "10": {10, false}, "raro": {0, false}} {
		if m, a := speedMbps(in); m != want.mbps || a != want.auto {
			t.Errorf("%q → %d %v; quería %d %v", in, m, a, want.mbps, want.auto)
		}
	}
	for in, want := range map[string]struct {
		mode string
		auto bool
	}{"a-full": {"full", true}, "full": {"full", false}, "half": {"half", false}, "a-half": {"half", true}, "auto": {"auto", true}, "": {"", false}} {
		if m := duplexMode(in); m != want.mode {
			t.Errorf("%q → %q; quería %q", in, m, want.mode)
		}
	}
}

func TestPortsDeUnTrabajo(t *testing.T) {
	dir := t.TempDir()
	dd := filepath.Join(dir, "SW1_10.0.0.1")
	os.MkdirAll(dd, 0o700)
	// dos rondas: gana la última de cada comando
	body := "===== ronda 1 · 2026-11-06T10:00:00Z · show interfaces status =====\nPort      Name               Status       Vlan       Duplex  Speed Type\nGi1/0/1   viejo              notconnect   1          auto    auto   10/100/1000BaseTX\n" +
		"===== ronda 2 · 2026-11-06T10:05:00Z · show interfaces status =====\n" + fx(t, "ios152_show-interfaces-status") +
		"===== ronda 2 · 2026-11-06T10:05:01Z · show interfaces trunk =====\n" + fx(t, "ios152_show-interfaces-trunk") +
		"===== ronda 2 · 2026-11-06T10:05:02Z · show etherchannel summary =====\n" + fx(t, "iosxe_show-etherchannel-summary")
	os.WriteFile(filepath.Join(dd, "SW1.txt"), []byte(body), 0o600)
	pd, err := PortsFromJob(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if pd.Address != "10.0.0.1" || pd.Hostname != "SW1" || pd.At.IsZero() || len(pd.Ports) != 9 || len(pd.Warnings) != 0 {
		t.Fatalf("= %+v", pd)
	}
	if g, _ := port(pd.PortStatus, "Gi1/0/1"); g.Description != "to-DIST1" || g.Status != "connected" {
		t.Fatalf("Gi1/0/1 = %+v", g)
	}
	// con dos equipos hay que decir cuál
	os.MkdirAll(filepath.Join(dir, "SW2_10.0.0.2"), 0o700)
	os.WriteFile(filepath.Join(dir, "SW2_10.0.0.2", "SW2.txt"), []byte("===== ronda 1 · 2026-11-06T10:00:00Z · show interfaces status =====\n"+fx(t, "acc1_show-interfaces-status")), 0o600)
	if _, err := PortsFromJob(dir, ""); err == nil || !strings.Contains(err.Error(), "SW1") || !strings.Contains(err.Error(), "SW2") {
		t.Fatalf("sin equipo: %v", err)
	}
	if pd, err = PortsFromJob(dir, "10.0.0.2"); err != nil || pd.Hostname != "SW2" || len(pd.Ports) == 0 || len(pd.Warnings) != 2 || !strings.Contains(strings.Join(pd.Warnings, "|"), "falta el comando show interfaces trunk") {
		t.Fatalf("SW2 = %+v %v", pd, err)
	}
	if pd, err = PortsFromJob(dir, "sw1"); err != nil || pd.Hostname != "SW1" {
		t.Fatalf("por nombre: %+v %v", pd, err)
	}
	if _, err = PortsFromJob(dir, "otro"); err == nil {
		t.Fatal("equipo que no está")
	}
	// un trabajo sin ese comando: vacío y con aviso, no error
	os.MkdirAll(filepath.Join(dir, "SW3_10.0.0.3"), 0o700)
	os.WriteFile(filepath.Join(dir, "SW3_10.0.0.3", "SW3.txt"), []byte("===== ronda 1 · 2026-11-06T10:00:00Z · show clock =====\n10:00\n"), 0o600)
	if pd, err = PortsFromJob(dir, "SW3"); err != nil || len(pd.Ports) != 0 || len(pd.Warnings) == 0 {
		t.Fatalf("SW3 = %+v %v", pd, err)
	}
}

func TestBuildPortsCasosSueltos(t *testing.T) {
	status := "Port      Name               Status       Vlan       Duplex  Speed Type\n" +
		"Gi1/0/1   a                  Connected    1          full    1000   10/100/1000BaseTX\n" +
		"Gi1/0/2   b                  connected    1          a-full  1000   10/100/1000BaseTX\n" +
		"Gi1/0/3   c                  connected    1          full    1000   10/100/1000BaseTX\n"
	trunk := "Port        Mode             Encapsulation  Status        Native vlan\nGi1/0/1     on               802.1q         trunking      7\nGi1/0/3     auto             n-802.1q       not-trunking  1\n"
	ps := BuildPorts(PortTexts{Status: status, Trunk: trunk, HaveTrunk: true})
	g1, _ := port(ps, "Gi1/0/1")
	g2, _ := port(ps, "Gi1/0/2")
	g3, _ := port(ps, "Gi1/0/3")
	if !g1.Trunk || g1.TrunkNative != "7" || g1.Status != "connected" || g1.AutoNeg {
		t.Fatalf("Gi1/0/1 = %+v", g1)
	}
	if !g2.AutoNeg || g2.SpeedMbps != 1000 {
		t.Fatalf("el dúplex negociado también cuenta: %+v", g2)
	}
	if g3.Trunk {
		t.Fatalf("not-trunking no es trunk: %+v", g3)
	}
}

func TestBuildPortsSinCanales(t *testing.T) {
	ps := BuildPorts(PortTexts{Status: fx(t, "ios152_show-interfaces-status"), Trunk: fx(t, "ios152_show-interfaces-trunk"), HaveTrunk: true,
		Channels: "Flags:  D - down\nNumber of channel-groups in use: 0\nNumber of aggregators:           0\n", HaveChannels: true})
	if len(ps.Warnings) != 0 || len(ps.Channels) != 0 {
		t.Fatalf("un switch sin canales no es una falla: %+v", ps)
	}
	ps = BuildPorts(PortTexts{Status: fx(t, "ios152_show-interfaces-status"), Channels: "% Invalid input\n", HaveChannels: true, HaveTrunk: true, Trunk: fx(t, "ios152_show-interfaces-trunk")})
	if len(ps.Warnings) != 1 || !strings.Contains(ps.Warnings[0], "no se pudo leer show etherchannel summary") {
		t.Fatalf("avisos = %v", ps.Warnings)
	}
}
