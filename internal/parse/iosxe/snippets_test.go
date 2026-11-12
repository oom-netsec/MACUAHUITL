package iosxe

import (
	"strings"
	"testing"
)

// Formatos de la documentación pública de Cisco IOS-XE 17.x. Sin validar en laboratorio.
const vlanBriefSample = `
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/3, Gi1/0/4
10   Usuarios                         active    Gi1/0/1, Gi1/0/2
                                                Gi1/0/5
20   VLAN0020                         act/unsup
1002 fddi-default                     act/unsup
`

func TestParseVlanBrief(t *testing.T) {
	rows, ok := ParseVlanBrief(vlanBriefSample)
	if !ok || len(rows) != 4 {
		t.Fatalf("ok=%v rows=%v", ok, rows)
	}
	if rows[1].ID != 10 || rows[1].Name != "Usuarios" || rows[1].Status != "active" {
		t.Errorf("fila 10: %+v", rows[1])
	}
	if rows[2].Status != "act/unsup" {
		t.Errorf("fila 20: %+v", rows[2])
	}
	// Los puertos siguen en las líneas de continuación; una VLAN sin puertos no trae ninguno.
	if got := strings.Join(rows[1].Ports, "|"); got != "Gi1/0/1|Gi1/0/2|Gi1/0/5" {
		t.Errorf("puertos de la VLAN 10 = %q", got)
	}
	if got := strings.Join(rows[0].Ports, "|"); got != "Gi1/0/3|Gi1/0/4" {
		t.Errorf("puertos de la VLAN 1 = %q", got)
	}
	if len(rows[2].Ports) != 0 || len(rows[3].Ports) != 0 {
		t.Errorf("VLAN sin puertos: %v %v", rows[2].Ports, rows[3].Ports)
	}
	if _, ok := ParseVlanBrief("% Invalid input detected at '^' marker.\n"); ok {
		t.Error("una salida sin tabla no es show vlan")
	}
	// show vlan id N también trae la tabla; una VLAN inexistente no trae filas.
	if rows, ok := ParseVlanBrief("VLAN id 77 not found in current VLAN database\n"); ok || len(rows) != 0 {
		t.Errorf("vlan inexistente: %v %v", rows, ok)
	}
}

func TestParseVTP(t *testing.T) {
	v, ok := ParseVTP("VTP Version capable             : 1 to 3\nVTP version running             : 1\nVTP Domain Name                 : CAMPUS\nVTP Operating Mode              : Server\n")
	if !ok || v.Mode != "server" || v.Domain != "CAMPUS" {
		t.Fatalf("%+v %v", v, ok)
	}
	v, ok = ParseVTP("VTP Domain Name : \nVTP Operating Mode : Transparent\n")
	if !ok || v.Mode != "transparent" || v.Domain != "" {
		t.Fatalf("%+v %v", v, ok)
	}
	if _, ok := ParseVTP("% Invalid input\n"); ok {
		t.Error("sin modo no es show vtp status")
	}
}

func TestParseVTPv3TakesTheVLANFeatureNotTheLast(t *testing.T) {
	// Sin validar en laboratorio: formato de la documentación pública de Cisco.
	for _, c := range []struct{ fx, mode string }{
		{"sw3p_show-vtp-status", "primary server"},
		{"sw3s_show-vtp-status", "secondary server"},
		{"sw3c_show-vtp-status", "client"},
	} {
		v, ok := ParseVTP(fx(t, c.fx))
		if !ok || v.Mode != c.mode || v.Domain != "CAMPUS" || v.Version != "3" || v.Ambiguous {
			t.Errorf("%s: %+v %v", c.fx, v, ok)
		}
	}
	// Sin secciones: manda la primera línea; con varias y sin sección es ambiguo.
	v, ok := ParseVTP("VTP version running : 3\nVTP Operating Mode : Server\nVTP Operating Mode : Transparent\n")
	if !ok || v.Mode != "server" || !v.Ambiguous {
		t.Errorf("sin secciones: %+v %v", v, ok)
	}
	v, _ = ParseVTP("VTP version running : 3\nFeature MST:\nVTP Operating Mode : Transparent\nFeature VLAN:\nVTP Operating Mode : Primary Server\n")
	if v.Mode != "primary server" || v.Ambiguous {
		t.Errorf("VLAN no es la primera sección: %+v", v)
	}
	v, _ = ParseVTP("VTP version running : 2\nVTP Operating Mode : Client\n")
	if v.Version != "2" || v.Ambiguous {
		t.Errorf("v2: %+v", v)
	}
}

func TestParseUsernames(t *testing.T) {
	text := `username admin privilege 15 secret 9 $9$abcDEF$ghi/jkl
username tech privilege 7 password 7 0822455D0A16
username viejo secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
username nadie nopassword
username lab privilege 15 algorithm-type scrypt secret 9 $9$zz$yy
`
	us := ParseUsernames(text)
	if len(us) != 5 {
		t.Fatalf("%d: %+v", len(us), us)
	}
	a := us[0]
	if a.Name != "admin" || a.Kind != "secret" || a.Type != "9" || a.Hash != "$9$abcDEF$ghi/jkl" || a.Privilege != "15" {
		t.Errorf("admin: %+v", a)
	}
	if us[1].Kind != "password" || us[1].Type != "7" || us[1].Hash != "0822455D0A16" {
		t.Errorf("tech: %+v", us[1])
	}
	if !us[3].NoPassword {
		t.Errorf("nadie: %+v", us[3])
	}
	if us[4].Kind != "secret" || us[4].Type != "9" || strings.Join(us[4].Extra, " ") != "algorithm-type scrypt" {
		t.Errorf("lab: %+v", us[4])
	}
	for _, i := range []int{0, 1, 2, 3} {
		if len(us[i].Extra) != 0 {
			t.Errorf("%s: Extra = %v", us[i].Name, us[i].Extra)
		}
	}
}

// Lo que no sea `privilege N` ni `secret|password tipo valor` se conserva en Extra, venga antes o después.
func TestParseUsernamesKeepsUnknownAttributes(t *testing.T) {
	for line, want := range map[string]string{
		"username bob privilege 15 view ops secret 9 H":      "view ops",
		"username bob privilege 15 secret 9 H autocommand x": "autocommand x",
		"username bob secret 9 H view ops":                   "view ops",
		"username bob privilege 15 secret 9 H":               "",
		"username bob secret H":                              "",
		"username bob secret":                                "secret",
	} {
		us := ParseUsernames(line + "\n")
		if len(us) != 1 || strings.Join(us[0].Extra, " ") != want {
			t.Errorf("%q: %+v", line, us)
		}
	}
}

func TestParseTrunkAllowed(t *testing.T) {
	c, _ := ParseInterfaceConfig("interface Gi1/0/1\n switchport mode trunk\n switchport trunk allowed vlan 1,10,20-22\n switchport trunk allowed vlan add 30,40\nend\n")
	set, all := TrunkAllowedSet(c.TrunkAllowed)
	if all || !set[1] || !set[21] || !set[40] || set[23] || set[5] {
		t.Errorf("lista: all=%v %v", all, set)
	}
	c, _ = ParseInterfaceConfig("interface Gi1/0/1\n switchport mode trunk\nend\n")
	if _, all := TrunkAllowedSet(c.TrunkAllowed); !all {
		t.Error("sin línea = todas las VLAN")
	}
	c, _ = ParseInterfaceConfig("interface Gi1/0/1\n switchport trunk allowed vlan except 10\nend\n")
	if set, all := TrunkAllowedSet(c.TrunkAllowed); all || set[10] || !set[11] {
		t.Errorf("except: all=%v", all)
	}
	c, _ = ParseInterfaceConfig("interface Gi1/0/1\n switchport trunk allowed vlan none\nend\n")
	if set, all := TrunkAllowedSet(c.TrunkAllowed); all || len(set) != 0 {
		t.Errorf("none: %v", set)
	}
}

// Formato de la documentación pública de Cisco IOS-XE. Sin validar en laboratorio.
const vlanIDSample = `VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
10   Usuarios                         active    Gi1/0/1

VLAN Type  SAID       MTU   Parent RingNo BridgeNo Stp  BrdgMode Trans1 Trans2
---- ----- ---------- ----- ------ ------ -------- ---- -------- ------ ------
10   enet  100010     1500  -      -      -        -    -        0      0

Remote SPAN VLAN
----------------
Disabled

Primary Secondary Type              Ports
------- --------- ----------------- ------------------------------------------
`

func TestParseVlanDetail(t *testing.T) {
	d, ok := ParseVlanDetail(vlanIDSample, 10)
	if !ok || d.Type != "enet" || d.MTU != 1500 || d.RSPAN || d.Private {
		t.Fatalf("ok=%v %+v", ok, d)
	}
	rspan := strings.Replace(strings.Replace(vlanIDSample, "Disabled", "Enabled", 1), "1500", "9000", 1)
	if d, ok := ParseVlanDetail(rspan, 10); !ok || !d.RSPAN || d.MTU != 9000 {
		t.Errorf("rspan/mtu: %v %+v", ok, d)
	}
	priv := vlanIDSample + "20      30        community         Gi1/0/2\n"
	if d, ok := ParseVlanDetail(priv, 10); !ok || !d.Private {
		t.Errorf("privada: %v %+v", ok, d)
	}
	// Sin la segunda tabla no se puede afirmar nada: no ok.
	if _, ok := ParseVlanDetail(strings.SplitN(vlanIDSample, "\nVLAN Type", 2)[0], 10); ok {
		t.Error("sin tabla de tipo y MTU no hay detalle")
	}
	if _, ok := ParseVlanDetail(vlanIDSample, 11); ok {
		t.Error("otra VLAN")
	}
	// La segunda tabla no se confunde con filas de la primera.
	rows, _ := ParseVlanBrief(vlanIDSample)
	if len(rows) != 1 || rows[0].Name != "Usuarios" || len(rows[0].Ports) != 1 {
		t.Errorf("filas: %+v", rows)
	}
}

func TestParseVlanBriefKeepsUnrecognisedPortTokens(t *testing.T) {
	rows, _ := ParseVlanBrief("VLAN Name Status Ports\n---- ---- ---- ----\n10   U    active    Gi1/0/1, Switch2/Weird-9, ?\n")
	if got := strings.Join(rows[0].Ports, "|"); got != "Gi1/0/1|Switch2/Weird-9|?" {
		t.Errorf("puertos = %q", got)
	}
}

const trunkSample = `Port        Mode             Encapsulation  Status        Native vlan
Gi1/0/1     on               802.1q         trunking      1
Po1         on               802.1q         trunking      30

Port        Vlans allowed on trunk
Gi1/0/1     1-4094
Po1         1-4094

Port        Vlans allowed and active in management domain
Gi1/0/1     1,10,20-22
Po1         1,10,
            23

Port        Vlans in spanning tree forwarding state and not pruned
Gi1/0/1     1,10
`

func TestParseTrunkActive(t *testing.T) {
	ts, ok := ParseTrunkActive(trunkSample)
	if !ok || len(ts) != 2 || ts[0].Port != "Gi1/0/1" || !ts[0].Vlans[21] || ts[0].Vlans[23] || !ts[1].Vlans[23] || !ts[1].Vlans[10] {
		t.Fatalf("ok=%v %+v", ok, ts)
	}
	if _, ok := ParseTrunkActive("% Invalid input detected\n"); ok {
		t.Error("sin tabla no es ok")
	}
}
