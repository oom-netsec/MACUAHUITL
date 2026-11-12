package assist

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// ---- VLAN ----

const vtpTransparent = "VTP Domain Name                 : \nVTP Operating Mode              : Transparent\n"

func vlanTable(rows ...string) string {
	return "VLAN Name                             Status    Ports\n---- -------------------------------- --------- -------------------------------\n" + strings.Join(rows, "\n") + "\n"
}

func vlanOuts(vtp string, rows ...string) map[string]string {
	return map[string]string{
		"show vlan brief": vlanTable(append([]string{"1    default                          active    Gi1/0/3"}, rows...)...),
		"show vtp status": vtp,
	}
}

func withID(m map[string]string, id int, row string) map[string]string {
	if row == "" {
		m[showVlan(id)] = fmt.Sprintf("VLAN id %d not found in current VLAN database\n", id)
	} else {
		m[showVlan(id)] = vlanTable(row)
	}
	return m
}

func TestVlanPlanCreatesAndRollbackDeletesOnlyIfAbsent(t *testing.T) {
	outs := withID(vlanOuts(vtpTransparent), 30, "")
	dp, err := VlanPlan("SW1", VlanChange{ID: 30, Name: "Cuarentena"}, outs)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dp.Apply, "|"); got != "vlan 30|name Cuarentena" {
		t.Errorf("Apply = %s", got)
	}
	if got := strings.Join(dp.Rollback, "|"); got != "no vlan 30" {
		t.Errorf("Rollback = %s", got)
	}
	if len(dp.Expect) == 0 || dp.Expect[0].Column != "vlan" || dp.Expect[0].Line != "30 Cuarentena" {
		t.Errorf("Expect = %+v", dp.Expect)
	}
	if err := Validate(Plan{Function: SnippetVlan.Name, Devices: []DevicePlan{dp}}, SnippetVlan); err != nil {
		t.Fatal(err)
	}
}

func TestVlanPlanExistingRestoresNameAndNeverDeletes(t *testing.T) {
	outs := withID(vlanOuts(vtpTransparent, "10   Usuarios                         active    Gi1/0/1"), 10, "10   Usuarios                         active    Gi1/0/1")
	dp, err := VlanPlan("SW1", VlanChange{ID: 10, Name: "Invitados"}, outs)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dp.Rollback, "|"); got != "vlan 10|name Usuarios" {
		t.Errorf("Rollback = %s", got)
	}
	for _, l := range dp.Rollback {
		if strings.HasPrefix(l, "no vlan") {
			t.Errorf("la reversa de una VLAN que ya existía no puede borrarla: %s", l)
		}
	}
	// Sin nombre nuevo no hay nada que cambiar: crear una VLAN que ya existe no es un cambio.
	if _, err := VlanPlan("SW1", VlanChange{ID: 10}, outs); err == nil {
		t.Error("vlan 10 sin nombre sobre una VLAN existente no cambia nada")
	}
	if _, err := VlanPlan("SW1", VlanChange{ID: 10, Name: "Usuarios"}, outs); err == nil {
		t.Error("el mismo nombre no cambia nada")
	}
}

func TestVlanPlanRejectsReservedAndBadNames(t *testing.T) {
	outs := withID(vlanOuts(vtpTransparent), 30, "")
	for _, id := range []int{0, 1, 1002, 1003, 1004, 1005, 4095, -3} {
		if _, err := VlanPlan("SW1", VlanChange{ID: id, Name: "x"}, withID(vlanOuts(vtpTransparent), id, "")); err == nil {
			t.Errorf("VLAN %d aceptada", id)
		}
	}
	for _, name := range []string{"con espacio", "x?", "ñandú", "a\r", strings.Repeat("a", 33), "x;y", "$x"} {
		if _, err := VlanPlan("SW1", VlanChange{ID: 30, Name: name}, outs); err == nil {
			t.Errorf("nombre %q aceptado", name)
		}
	}
}

func TestVlanPlanRefusesPropagatingVTP(t *testing.T) {
	server := "VTP Domain Name                 : CAMPUS\nVTP Operating Mode              : Server\n"
	outs := withID(vlanOuts(server), 30, "")
	if _, err := VlanPlan("SW1", VlanChange{ID: 30, Name: "x"}, outs); !errors.Is(err, ErrSnippetRefused) {
		t.Fatalf("VTP servidor con dominio debe rechazarse: %v", err)
	}
	if _, err := VlanPlan("SW1", VlanChange{ID: 30, Name: "x", AcceptVTP: true}, outs); err != nil {
		t.Errorf("con aceptación explícita: %v", err)
	}
	for _, vtp := range []string{"VTP Operating Mode : Client\nVTP Domain Name : CAMPUS\n", "% Invalid input\n", ""} {
		if _, err := VlanPlan("SW1", VlanChange{ID: 30, Name: "x"}, withID(vlanOuts(vtp), 30, "")); !errors.Is(err, ErrSnippetRefused) {
			t.Errorf("vtp %q: %v", vtp, err)
		}
	}
	for _, vtp := range []string{"VTP Operating Mode : Off\n", "VTP Operating Mode : Server\nVTP Domain Name : \n"} {
		if _, err := VlanPlan("SW1", VlanChange{ID: 30, Name: "x"}, withID(vlanOuts(vtp), 30, "")); err != nil {
			t.Errorf("vtp %q: %v", vtp, err)
		}
	}
}

// v3 trae un modo por función; el de VLAN manda. Formato de la documentación de Cisco, sin validar en laboratorio.
func vtp3(vlanMode string) string {
	return "VTP version running : 3\nVTP Domain Name : CAMPUS\n\nFeature VLAN:\n--------------\nVTP Operating Mode : " + vlanMode +
		"\n\nFeature MST:\n--------------\nVTP Operating Mode : Transparent\n\nFeature UNKNOWN:\n--------------\nVTP Operating Mode : Transparent\n"
}

func TestVlanPlanVTPv3ReadsTheVLANFeature(t *testing.T) {
	for _, mode := range []string{"Primary Server", "Secondary Server", "Client", "SERVER", "primary server"} {
		outs := withID(vlanOuts(vtp3(mode)), 30, "")
		if _, err := VlanPlan("SW1", VlanChange{ID: 30, Name: "x"}, outs); !errors.Is(err, ErrSnippetRefused) {
			t.Errorf("v3 %q debe rechazarse: %v", mode, err)
		}
		if _, err := VlanPlan("SW1", VlanChange{ID: 30, Name: "x", AcceptVTP: true}, outs); err != nil {
			t.Errorf("v3 %q con aceptación: %v", mode, err)
		}
	}
	if _, err := VlanPlan("SW1", VlanChange{ID: 30, Name: "x"}, withID(vlanOuts(vtp3("Transparent")), 30, "")); err != nil {
		t.Errorf("v3 transparente: %v", err)
	}
	// Ambiguo o ilegible en v3: se rechaza aunque la última línea sea transparente.
	for _, vtp := range []string{
		"VTP version running : 3\nVTP Operating Mode : Server\nVTP Operating Mode : Transparent\n",
		vtp3("Rarito"),
	} {
		if _, err := VlanPlan("SW1", VlanChange{ID: 30, Name: "x"}, withID(vlanOuts(vtp), 30, "")); !errors.Is(err, ErrSnippetRefused) {
			t.Errorf("v3 ambiguo %q: %v", vtp, err)
		}
	}
	// Un modo mayúscula en v2 también propaga.
	if _, err := VlanPlan("SW1", VlanChange{ID: 30, Name: "x"}, withID(vlanOuts("VTP version running : 2\nVTP Domain Name : C\nVTP Operating Mode : CLIENT\n"), 30, "")); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("v2 CLIENT: %v", err)
	}
}

func TestSnippetVlanClosedListAndInverseRollback(t *testing.T) {
	plan := func(apply, rollback []string) error {
		dp := DevicePlan{Device: "SW1", Pre: []string{"show vlan brief"}, Apply: apply, Rollback: rollback, Post: []string{"show vlan brief"},
			Expect: []Expect{{Command: "show vlan brief", Line: "30 x", Present: true, Column: "vlan"}}}
		return Validate(Plan{Function: SnippetVlan.Name, Devices: []DevicePlan{dp}}, SnippetVlan)
	}
	if err := plan([]string{"vlan 30", "name x"}, []string{"no vlan 30"}); err != nil {
		t.Fatal(err)
	}
	bad := map[string][2][]string{
		"la reversa borra otra VLAN":   {{"vlan 30", "name x"}, {"no vlan 31"}},
		"la reversa borra la VLAN 1":   {{"vlan 30", "name x"}, {"no vlan 1"}},
		"apply borra":                  {{"no vlan 30"}, {"vlan 30"}},
		"interfaz fuera de lista":      {{"interface Gi1/0/1", "shutdown"}, {"no shutdown"}},
		"VLAN reservada":               {{"vlan 1003", "name x"}, {"no vlan 1003"}},
		"rango":                        {{"vlan 30-40"}, {"no vlan 30"}},
		"vlan abreviada":               {{"vl 30"}, {"no vlan 30"}},
		"reversa que cambia otra VLAN": {{"vlan 30", "name x"}, {"vlan 31", "name x"}},
		"nombre con espacio":           {{"vlan 30", "name con espacio"}, {"no vlan 30"}},
		"borrar sin ser la creada":     {{"vlan 30", "name x"}, {"no vlan 30", "no vlan 31"}},
	}
	for name, p := range bad {
		if err := plan(p[0], p[1]); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("%s: se aceptó (%v)", name, err)
		}
	}
}

// ---- Borrar VLAN ----

const row20 = "20   Cuarentena                       active    "

// Formatos de la documentación pública de Cisco IOS-XE. Sin validar en laboratorio.
const (
	ipBriefOK = "Interface              IP-Address      OK? Method Status                Protocol\nVlan1                  unassigned      YES unset  up                    down\nGi1/0/1                unassigned      YES unset  up                    up\n"
	trunkNone = "Port        Mode             Encapsulation  Status        Native vlan\nGi1/0/48    on               802.1q         trunking      1\n\nPort        Vlans allowed on trunk\nGi1/0/48    1-4094\n\nPort        Vlans allowed and active in management domain\nGi1/0/48    1,10\n\nPort        Vlans in spanning tree forwarding state and not pruned\nGi1/0/48    1,10\n"
)

func trunkWith(native, active string) string {
	return "Port        Mode             Encapsulation  Status        Native vlan\nGi1/0/48    on               802.1q         trunking      " + native +
		"\n\nPort        Vlans allowed on trunk\nGi1/0/48    1-4094\n\nPort        Vlans allowed and active in management domain\nGi1/0/48    " + active + "\n"
}

// vlanIDDetail es show vlan id 20 completo: tabla, tipo y MTU, Remote SPAN y VLAN privadas.
func vlanIDDetail(row, typ, mtu, rspan, pvlan string) string {
	return vlanTable(row) + "\nVLAN Type  SAID       MTU   Parent RingNo BridgeNo Stp  BrdgMode Trans1 Trans2\n---- ----- ---------- ----- ------ ------ -------- ---- -------- ------ ------\n20   " + typ + "  100020     " + mtu + "  -      -      -        -    -        0      0\n\nRemote SPAN VLAN\n----------------\n" + rspan + "\n\nPrimary Secondary Type              Ports\n------- --------- ----------------- ------------------------------------------\n" + pvlan
}

func removeOuts(row string) map[string]string {
	o := vlanOuts(vtpTransparent, row)
	o[showVlan(20)] = vlanIDDetail(row, "enet", "1500", "Disabled", "")
	o["show ip interface brief"] = ipBriefOK
	o["show interfaces trunk"] = trunkNone
	return o
}

func removeErr(t *testing.T, c VlanChange, outs map[string]string) error {
	t.Helper()
	c.ID, c.Remove = 20, true
	_, err := VlanPlan("SW1", c, outs)
	return err
}

func TestVlanRemovePlanAppliesNoVlanAndRollbackRestoresName(t *testing.T) {
	dp, err := VlanPlan("SW1", VlanChange{ID: 20, Remove: true}, removeOuts(row20))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dp.Apply, "|"); got != "no vlan 20" {
		t.Errorf("Apply = %s", got)
	}
	if got := strings.Join(dp.Rollback, "|"); got != "vlan 20|name Cuarentena" {
		t.Errorf("Rollback = %s", got)
	}
	if len(dp.Expect) != 1 || dp.Expect[0].Column != "vlan-id" || dp.Expect[0].Line != "20" || dp.Expect[0].Present {
		t.Errorf("Expect = %+v", dp.Expect)
	}
	if dp.Baseline[showVlan(20)] == "" {
		t.Error("falta la línea base de show vlan id 20")
	}
	pre, err := VlanPre(VlanChange{ID: 20, Remove: true})
	if err != nil || !strings.Contains(strings.Join(pre, "|"), "show ip interface brief") || !strings.Contains(strings.Join(pre, "|"), "show interfaces trunk") {
		t.Errorf("Pre del borrado = %v %v", pre, err)
	}
	// Con el nombre por omisión la reversa solo recrea la VLAN.
	dp, err = VlanPlan("SW1", VlanChange{ID: 20, Remove: true}, removeOuts("20   VLAN0020                         active    "))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dp.Rollback, "|"); got != "vlan 20" {
		t.Errorf("Rollback con nombre por omisión = %s", got)
	}
}

func TestVlanRemoveRefusals(t *testing.T) {
	if _, err := VlanPlan("SW1", VlanChange{ID: 20, Name: "x", Remove: true}, removeOuts(row20)); err == nil {
		t.Error("--remove con nombre debe fallar")
	}
	absent := removeOuts(row20)
	absent["show vlan brief"] = vlanTable("1    default                          active    Gi1/0/3")
	absent[showVlan(20)] = "VLAN id 20 not found in current VLAN database\n"
	absent[showVlan(30)] = "VLAN id 30 not found in current VLAN database\n"
	if _, err := VlanPlan("SW1", VlanChange{ID: 30, Remove: true}, absent); err == nil || !strings.Contains(err.Error(), "la VLAN 30 no existe en SW1") {
		t.Errorf("VLAN inexistente: %v", err)
	}
	for _, id := range []int{1, 1002, 1005} {
		if _, err := VlanPre(VlanChange{ID: id, Remove: true}); err == nil {
			t.Errorf("VLAN %d no se borra", id)
		}
	}
	err := removeErr(t, VlanChange{}, removeOuts(row20+"Gi1/0/7, Gi1/0/8"))
	if !errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), "Gi1/0/7, Gi1/0/8") {
		t.Errorf("con puertos asignados: %v", err)
	}
	// Los puertos de una línea de continuación también cuentan.
	err = removeErr(t, VlanChange{}, removeOuts(row20+"\n                                                Gi1/0/9"))
	if !errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), "Gi1/0/9") {
		t.Errorf("puertos en continuación: %v", err)
	}
	// Un nombre de puerto que no se reconoce sigue siendo un puerto.
	if err := removeErr(t, VlanChange{}, removeOuts(row20+"Raro/9")); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("puerto no reconocido: %v", err)
	}
	// Una VLAN suspendida no se restauraría igual con la reversa.
	if err := removeErr(t, VlanChange{}, removeOuts("20   Cuarentena                       suspended ")); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("VLAN no activa: %v", err)
	}
	// Un nombre que la reversa no podría escribir de vuelta.
	if err := removeErr(t, VlanChange{}, removeOuts("20   Cuar;entena                      active    ")); err == nil {
		t.Error("nombre no restaurable")
	}
	// VTP igual que al crear.
	srv := "VTP Domain Name : CAMPUS\nVTP Operating Mode : Server\n"
	outs := removeOuts(row20)
	outs["show vtp status"] = srv
	if err := removeErr(t, VlanChange{}, outs); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("VTP servidor sin aceptar: %v", err)
	}
	if err := removeErr(t, VlanChange{AcceptVTP: true}, outs); err != nil {
		t.Errorf("VTP servidor aceptado: %v", err)
	}
	// show vlan brief y show vlan id no coinciden sobre si existe, en los dos sentidos.
	outs = removeOuts(row20)
	outs[showVlan(20)] = "VLAN id 20 not found in current VLAN database\n"
	if err := removeErr(t, VlanChange{}, outs); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("brief sí, id no: %v", err)
	}
	outs = removeOuts(row20)
	outs["show vlan brief"] = absent["show vlan brief"]
	if err := removeErr(t, VlanChange{}, outs); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("brief no, id sí: %v", err)
	}
}

func TestVlanRemoveRefusesTheVlanOfAnSVI(t *testing.T) {
	outs := removeOuts(row20)
	outs["show ip interface brief"] = ipBriefOK + "Vlan20                 10.0.20.2       YES NVRAM  up                    up\n"
	for _, c := range []VlanChange{{}, {AcceptVTP: true, AcceptTrunk: true}} {
		err := removeErr(t, c, outs)
		if !errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), "interface Vlan20") {
			t.Errorf("SVI con %+v: %v", c, err)
		}
	}
	// Una SVI sin dirección también existe.
	outs["show ip interface brief"] = ipBriefOK + "Vlan20                 unassigned      YES unset  down                  down\n"
	if err := removeErr(t, VlanChange{}, outs); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("SVI sin IP: %v", err)
	}
	// Si no se puede leer la lista de interfaces no se arriesga.
	outs["show ip interface brief"] = "% Invalid input detected at '^' marker.\n"
	if err := removeErr(t, VlanChange{}, outs); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("sin lectura de interfaces: %v", err)
	}
}

func TestVlanRemoveTrunkRules(t *testing.T) {
	outs := removeOuts(row20)
	outs["show interfaces trunk"] = trunkWith("1", "1,10,20")
	err := removeErr(t, VlanChange{}, outs)
	if !errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), "Gi1/0/48") {
		t.Errorf("trunk que la lleva: %v", err)
	}
	if err := removeErr(t, VlanChange{AcceptTrunk: true}, outs); err != nil {
		t.Errorf("trunk aceptado: %v", err)
	}
	// La VLAN nativa de un trunk no se borra aunque se acepte el trunk.
	outs["show interfaces trunk"] = trunkWith("20", "1,10,20")
	err = removeErr(t, VlanChange{AcceptTrunk: true}, outs)
	if !errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), "nativa") {
		t.Errorf("nativa: %v", err)
	}
	// Sin trunks (IOS no imprime nada) no hay nada que revisar; una respuesta de error sí frena.
	outs["show interfaces trunk"] = ""
	if err := removeErr(t, VlanChange{}, outs); err != nil {
		t.Errorf("sin trunks: %v", err)
	}
	outs["show interfaces trunk"] = "% Invalid input detected at '^' marker.\n"
	if err := removeErr(t, VlanChange{}, outs); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("trunks ilegibles: %v", err)
	}
	// Una lista que se parte en varias líneas también cuenta.
	outs["show interfaces trunk"] = trunkWith("1", "1,10,\n            20")
	if err := removeErr(t, VlanChange{}, outs); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("continuación: %v", err)
	}
}

func TestVlanRemoveRefusesWhatTheRollbackCannotRestore(t *testing.T) {
	for name, d := range map[string]string{
		"MTU":            vlanIDDetail(row20, "enet", "9000", "Disabled", ""),
		"tipo":           vlanIDDetail(row20, "fddi", "1500", "Disabled", ""),
		"Remote SPAN":    vlanIDDetail(row20, "enet", "1500", "Enabled", ""),
		"VLAN privada":   vlanIDDetail(row20, "enet", "1500", "Disabled", "20      30        community         Gi1/0/2\n"),
		"sin el detalle": vlanTable(row20),
	} {
		outs := removeOuts(row20)
		outs[showVlan(20)] = d
		if err := removeErr(t, VlanChange{}, outs); !errors.Is(err, ErrSnippetRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVlanRemoveExpectMatchesTheIDOnly(t *testing.T) {
	dp, err := VlanPlan("SW1", VlanChange{ID: 20, Remove: true}, removeOuts(row20))
	if err != nil {
		t.Fatal(err)
	}
	gone := map[string]string{showVlan(20): "VLAN id 20 not found in current VLAN database\n"}
	if f := EvalExpect(dp.Expect, gone); len(f) != 0 {
		t.Errorf("la VLAN ya no existe y falló: %v", f)
	}
	// Con cualquier nombre o estado la VLAN sigue ahí.
	for _, row := range []string{row20, "20   Otro                             active    ", "20   Cuarentena                       suspended ", "20   VLAN0020                         act/lshut "} {
		if f := EvalExpect(dp.Expect, map[string]string{showVlan(20): vlanTable(row)}); len(f) == 0 {
			t.Errorf("la VLAN sigue (%q) y la verificación pasó", row)
		}
	}
	// El aviso de otra VLAN no demuestra nada sobre ésta.
	if f := EvalExpect(dp.Expect, map[string]string{showVlan(20): "VLAN id 21 not found in current VLAN database\n"}); len(f) == 0 {
		t.Error("el «not found» de otra VLAN pasó")
	}
	// Y un «not found» nunca cumple una verificación de que la VLAN exista.
	create := []Expect{{Command: showVlan(20), Line: "20 Cuarentena", Present: true, Column: "vlan"}}
	if f := EvalExpect(create, gone); len(f) == 0 {
		t.Error("«not found» cumplió una verificación de presencia")
	}
	byID := []Expect{{Command: showVlan(20), Line: "20", Present: true, Column: "vlan-id"}}
	if f := EvalExpect(byID, gone); len(f) == 0 {
		t.Error("«not found» cumplió vlan-id presente")
	}
}

func TestSnippetVlanAllowsNoVlanOnlyAsDeleteWithAbsentExpect(t *testing.T) {
	plan := func(apply, rollback []string, ex Expect) error {
		dp := DevicePlan{Device: "SW1", Pre: []string{"show vlan brief"}, Apply: apply, Rollback: rollback, Post: []string{"show vlan brief"}, Expect: []Expect{ex}}
		return Validate(Plan{Function: SnippetVlan.Name, Devices: []DevicePlan{dp}}, SnippetVlan)
	}
	absent := Expect{Command: "show vlan brief", Line: "30", Present: false, Column: "vlan-id"}
	if err := plan([]string{"no vlan 30"}, []string{"vlan 30", "name x"}, absent); err != nil {
		t.Fatal(err)
	}
	if err := plan([]string{"no vlan 30"}, []string{"vlan 30"}, absent); err != nil {
		t.Fatal(err)
	}
	present := absent
	present.Present = true
	other := absent
	other.Line = "31"
	byName := Expect{Command: "show vlan brief", Line: "30 x", Present: false, Column: "vlan"}
	for name, p := range map[string]struct {
		a, r []string
		ex   Expect
	}{
		"borrar esperando que siga": {[]string{"no vlan 30"}, []string{"vlan 30"}, present},
		"verificación de otra VLAN": {[]string{"no vlan 30"}, []string{"vlan 30"}, other},
		"verificación por nombre":   {[]string{"no vlan 30"}, []string{"vlan 30"}, byName},
		"reversa de otra VLAN":      {[]string{"no vlan 30"}, []string{"vlan 31"}, absent},
		"reversa que renombra otra": {[]string{"no vlan 30"}, []string{"vlan 30", "vlan 31"}, absent},
		"borra dos":                 {[]string{"no vlan 30", "no vlan 31"}, []string{"vlan 30"}, absent},
		"borra la VLAN 1":           {[]string{"no vlan 1"}, []string{"vlan 1"}, absent},
		"reversa que también borra": {[]string{"no vlan 30"}, []string{"vlan 30", "no vlan 31"}, absent},
	} {
		if err := plan(p.a, p.r, p.ex); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("%s: se aceptó (%v)", name, err)
		}
	}
}

// ---- Trunk ----

func trunkCfg(name string, body ...string) string { return cfgOf(name, body...) }

func trunkOuts(name, cfg, switchport string) map[string]string {
	return map[string]string{showCfg(name): cfg, showSwitchport(name): switchport}
}

const swTrunk = "Name: Gi1/0/48\nSwitchport: Enabled\nAdministrative Mode: trunk\nOperational Mode: trunk\n"

func TestTrunkRejectsBareAllowedVlanInAnyForm(t *testing.T) {
	mk := func(line string, inRollback bool) error {
		apply := []string{"interface " + gi1, "switchport trunk allowed vlan add 10"}
		back := []string{"interface " + gi1, "switchport trunk allowed vlan remove 10"}
		if inRollback {
			back[1] = line
		} else {
			apply[1] = line
		}
		dp := DevicePlan{Device: "SW1", Pre: []string{showCfg(gi1)}, Apply: apply, Rollback: back, Post: []string{showCfg(gi1)},
			Expect: []Expect{{Command: showCfg(gi1), Line: "10", Column: "trunk-allowed", Present: true}}}
		return Validate(Plan{Function: SnippetTrunk.Name, Devices: []DevicePlan{dp}}, SnippetTrunk)
	}
	for _, line := range []string{
		"switchport trunk allowed vlan 10", "switchport trunk allowed vlan all", "switchport trunk allowed vlan none",
		"switchport trunk allowed vlan except 10", "switchport trunk allowed vlan 10,20", "switchport trunk allowed vlan 1-4094",
		"switchport trunk allowed vlan add 10,20", "switchport trunk allowed vlan add 10-20", "switchport trunk allowed vlan add",
		"switchport trunk allowed vlan add 10 20", "switchport trunk allowed vlan remove all", "switchport trunk allowed vlan add all",
		"switchport trunk allowed vlan remove 0", "switchport trunk allowed vlan add 4095", "switchport trunk allowed vlan",
		"sw trunk allowed vlan 10", "switchport trunk allow vlan 10", "switchport trunk allowed vlan add 10 ?",
		"SWITCHPORT TRUNK ALLOWED VLAN 10", "switchport trunk allowed vlan 10 add", "no switchport trunk allowed vlan",
		"switchport trunk allowed vlan add 010x",
	} {
		for _, inRollback := range []bool{false, true} {
			if err := mk(line, inRollback); !errors.Is(err, ErrInvalidPlan) {
				t.Errorf("%q (reversa=%v) debía rechazarse: %v", line, inRollback, err)
			}
		}
	}
	if err := mk("switchport trunk allowed vlan add 10", false); err != nil {
		t.Errorf("add válido: %v", err)
	}
	if err := mk("switchport trunk allowed vlan   remove   10", true); err != nil {
		t.Errorf("remove válido con espacios: %v", err)
	}
}

func TestSnippetTrunkPlanShapeMustBeInverse(t *testing.T) {
	v := func(apply, back []string) error {
		dp := DevicePlan{Device: "SW1", Pre: []string{showCfg(gi1)}, Apply: apply, Rollback: back, Post: []string{showCfg(gi1)},
			Expect: []Expect{{Command: showCfg(gi1), Line: "10", Column: "trunk-allowed", Present: true}}}
		return Validate(Plan{Function: SnippetTrunk.Name, Devices: []DevicePlan{dp}}, SnippetTrunk)
	}
	i := "interface " + gi1
	for name, p := range map[string][2][]string{
		"misma operación en la reversa": {{i, "switchport trunk allowed vlan add 10"}, {i, "switchport trunk allowed vlan add 10"}},
		"otra VLAN en la reversa":       {{i, "switchport trunk allowed vlan add 10"}, {i, "switchport trunk allowed vlan remove 11"}},
		"otra interfaz en la reversa":   {{i, "switchport trunk allowed vlan add 10"}, {"interface " + gi2, "switchport trunk allowed vlan remove 10"}},
		"dos líneas de trunk":           {{i, "switchport trunk allowed vlan add 10", "switchport trunk allowed vlan add 11"}, {i, "switchport trunk allowed vlan remove 10"}},
		"sin interfaz":                  {{"switchport trunk allowed vlan add 10"}, {"switchport trunk allowed vlan remove 10"}},
		"modo trunk":                    {{i, "switchport mode trunk"}, {i, "switchport mode access"}},
		"vlan de acceso":                {{i, "switchport access vlan 10"}, {i, "no switchport access vlan"}},
	} {
		if err := v(p[0], p[1]); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("%s: se aceptó (%v)", name, err)
		}
	}
	if err := v([]string{i, "switchport trunk allowed vlan remove 10"}, []string{i, "switchport trunk allowed vlan add 10"}); err != nil {
		t.Errorf("remove/add válido: %v", err)
	}
}

func TestTrunkPlanAddAndRemoveWithInverseRollback(t *testing.T) {
	outs := trunkOuts(gi1, trunkCfg(gi1, "switchport mode trunk", "switchport trunk allowed vlan 10,20"), swTrunk)
	dp, err := TrunkPlan("SW1", TrunkChange{Interface: gi1, Op: "add", Vlan: 30}, outs)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dp.Apply, "|"); got != "interface "+gi1+"|switchport trunk allowed vlan add 30" {
		t.Errorf("Apply = %s", got)
	}
	if got := strings.Join(dp.Rollback, "|"); got != "interface "+gi1+"|switchport trunk allowed vlan remove 30" {
		t.Errorf("Rollback = %s", got)
	}
	dp, err = TrunkPlan("SW1", TrunkChange{Interface: gi1, Op: "remove", Vlan: 20}, outs)
	if err != nil {
		t.Fatal(err)
	}
	if got := dp.Rollback[1]; got != "switchport trunk allowed vlan add 20" {
		t.Errorf("Rollback = %s", got)
	}
	if len(dp.Expect) == 0 || dp.Expect[0].Column != "trunk-allowed" || dp.Expect[0].Present {
		t.Errorf("tras remove la VLAN no debe estar permitida: %+v", dp.Expect)
	}
	// Ya permitida / no permitida: no hay nada que cambiar (y la reversa borraría algo que ya estaba).
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi1, Op: "add", Vlan: 10}, outs); err == nil {
		t.Error("add de una VLAN ya permitida")
	}
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi1, Op: "remove", Vlan: 99}, outs); err == nil {
		t.Error("remove de una VLAN que no está permitida")
	}
	// Con la lista en "todas" (sin línea) add no cambia nada y remove sí.
	all := trunkOuts(gi1, trunkCfg(gi1, "switchport mode trunk"), swTrunk)
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi1, Op: "add", Vlan: 10}, all); err == nil {
		t.Error("add con todas las VLAN permitidas")
	}
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi1, Op: "remove", Vlan: 10}, all); err != nil {
		t.Errorf("remove con todas permitidas: %v", err)
	}
	// Una lista larga en varias líneas (add) se lee completa.
	long := trunkOuts(gi1, trunkCfg(gi1, "switchport mode trunk", "switchport trunk allowed vlan 1-5", "switchport trunk allowed vlan add 40"), swTrunk)
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi1, Op: "add", Vlan: 40}, long); err == nil {
		t.Error("la VLAN 40 está en la segunda línea: ya permitida")
	}
}

func TestTrunkPlanNeverEmitsBareAllowedVlan(t *testing.T) {
	outs := trunkOuts(gi1, trunkCfg(gi1, "switchport mode trunk", "switchport trunk allowed vlan 10,20"), swTrunk)
	for _, op := range []string{"add", "remove"} {
		for _, v := range []int{10, 30} {
			dp, err := TrunkPlan("SW1", TrunkChange{Interface: gi1, Op: op, Vlan: v}, outs)
			if err != nil {
				continue
			}
			for _, l := range append(append([]string(nil), dp.Apply...), dp.Rollback...) {
				if strings.HasPrefix(l, "switchport trunk allowed vlan") && !strings.HasPrefix(l, "switchport trunk allowed vlan add ") && !strings.HasPrefix(l, "switchport trunk allowed vlan remove ") {
					t.Errorf("línea prohibida en el plan: %q", l)
				}
			}
		}
	}
}

func TestTrunkPlanRejectsInterfaceThatIsNotTrunk(t *testing.T) {
	access := trunkOuts(gi1, trunkCfg(gi1, "switchport mode access", "switchport access vlan 10"), "Administrative Mode: static access\n")
	dynamic := trunkOuts(gi1, trunkCfg(gi1, "description x"), "Administrative Mode: dynamic auto\n")
	routed := trunkOuts(gi1, trunkCfg(gi1, "no switchport", "ip address 10.0.0.1 255.255.255.252"), "Switchport: Disabled\n")
	member := trunkOuts(gi1, trunkCfg(gi1, "switchport mode trunk", "channel-group 1 mode active"), swTrunk)
	for name, outs := range map[string]map[string]string{"acceso": access, "dinámico": dynamic, "ruteado": routed, "miembro de canal": member} {
		if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi1, Op: "add", Vlan: 30}, outs); !errors.Is(err, ErrSnippetRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Un trunk negociado (el modo administrativo dice trunk aunque la configuración no lo fije) sí es trunk.
	neg := trunkOuts(gi1, trunkCfg(gi1, "description x"), swTrunk)
	if _, err := TrunkPlan("SW1", TrunkChange{Interface: gi1, Op: "remove", Vlan: 30}, neg); errors.Is(err, ErrSnippetRefused) {
		t.Errorf("modo administrativo trunk: %v", err)
	}
	// Una interfaz que no es de switch lógico simple se rechaza antes de leer nada.
	for _, n := range []string{"Vlan10", "Loopback0", "Tunnel1", "GigabitEthernet1/0/1.20", "range Gi1/0/1", "Gi1/0/1,Gi1/0/2"} {
		if _, err := TrunkPre(TrunkChange{Interface: n, Op: "add", Vlan: 30}); err == nil {
			t.Errorf("interfaz %q aceptada", n)
		}
	}
	for _, n := range []string{gi1, "Port-channel1", "Po2"} {
		if _, err := TrunkPre(TrunkChange{Interface: n, Op: "add", Vlan: 30}); err != nil {
			t.Errorf("interfaz %q: %v", n, err)
		}
	}
	for _, c := range []TrunkChange{{Interface: gi1, Op: "set", Vlan: 30}, {Interface: gi1, Op: "", Vlan: 30}, {Interface: gi1, Op: "add", Vlan: 0}, {Interface: gi1, Op: "add", Vlan: 4095}} {
		if _, err := TrunkPre(c); err == nil {
			t.Errorf("%+v aceptado", c)
		}
	}
}

// ---- SVI ----

const ipBriefHead = "Interface              IP-Address      OK? Method Status                Protocol\n"

func sviOuts(cfgVlan string, brief string) map[string]string {
	return map[string]string{showCfg("Vlan99"): cfgVlan, "show ip interface brief": ipBriefHead + brief}
}

const noIface = "                 ^\n% Invalid input detected at '^' marker.\n"

func TestSVIPlanNewInterfaceRollbackRemovesIt(t *testing.T) {
	d := "Servidores"
	dp, err := SVIPlan("SW1", SVIChange{VlanID: 99, Description: &d, Address: "10.9.9.1", Mask: "255.255.255.0"},
		sviOuts(noIface, "Vlan1                  unassigned      YES unset  up                    down\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dp.Apply, "|"); got != "interface Vlan99|description Servidores|ip address 10.9.9.1 255.255.255.0|no shutdown" {
		t.Errorf("Apply = %s", got)
	}
	if got := strings.Join(dp.Rollback, "|"); got != "no interface Vlan99" {
		t.Errorf("Rollback = %s", got)
	}
	if err := Validate(Plan{Function: SnippetSVI.Name, Devices: []DevicePlan{dp}}, SnippetSVI); err != nil {
		t.Fatal(err)
	}
}

func TestSVIPlanExistingWithoutIPRestoresItsConfig(t *testing.T) {
	d := "Nueva"
	cur := cfgOf("Vlan99", "description Vieja", "shutdown")
	dp, err := SVIPlan("SW1", SVIChange{VlanID: 99, Description: &d, Address: "10.9.9.1", Mask: "255.255.255.0"},
		sviOuts(cur, "Vlan99                 unassigned      YES unset  administratively down down\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dp.Rollback, "|"); got != "interface Vlan99|no ip address|description Vieja|shutdown" {
		t.Errorf("Rollback = %s", got)
	}
	for _, l := range dp.Rollback {
		if strings.HasPrefix(l, "no interface") {
			t.Errorf("la SVI ya existía: la reversa no puede borrarla (%s)", l)
		}
	}
	cur = cfgOf("Vlan99")
	dp, err = SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.9.9.1", Mask: "255.255.255.0"},
		sviOuts(cur, "Vlan99                 unassigned      YES unset  up                    down\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dp.Rollback, "|"); got != "interface Vlan99|no ip address|no description|no shutdown" {
		t.Errorf("Rollback = %s", got)
	}
}

func TestSVIPlanRefusesInterfaceThatAlreadyHasIP(t *testing.T) {
	for _, body := range [][]string{{"ip address 10.1.1.1 255.255.255.0"}, {"ip address dhcp"}, {"ipv6 address 2001:db8::1/64"}, {"ip vrf forwarding MGMT"}} {
		_, err := SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.9.9.1", Mask: "255.255.255.0"},
			sviOuts(cfgOf("Vlan99", body...), "Vlan99                 10.1.1.1        YES manual up                    up\n"))
		if !errors.Is(err, ErrSnippetRefused) {
			t.Errorf("%v: %v", body, err)
		}
	}
}

// La reversa de una SVI existente hace `no ip address`: con ip unnumbered, secundarias o IPv6 la dejaría sin dirección.
func TestSVIPlanRefusesAnyAddressingIncludingUnnumbered(t *testing.T) {
	for _, body := range [][]string{
		{"ip unnumbered Loopback0"}, {"ip address 10.1.1.2 255.255.255.0 secondary"},
		{"ipv6 address 2001:db8::1/64"}, {"ipv6 unnumbered Loopback0"}, {"ip address 10.1.1.1 255.255.255.0", "ip address 10.1.2.1 255.255.255.0 secondary"},
	} {
		_, err := SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.9.9.1", Mask: "255.255.255.0"},
			sviOuts(cfgOf("Vlan99", body...), "Vlan99                 unassigned      YES unset  up                    up\n"))
		if !errors.Is(err, ErrSnippetRefused) {
			t.Errorf("%v: %v", body, err)
		}
	}
}

func TestSVIPlanRefusesWhenExistenceIsUncertain(t *testing.T) {
	// La configuración dice que no existe, pero show ip interface brief la lista: borrarla en la reversa sería un desastre.
	_, err := SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.9.9.1", Mask: "255.255.255.0"},
		sviOuts(noIface, "Vlan99                 unassigned      YES unset  up                    down\n"))
	if !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("config sin SVI pero brief con SVI: %v", err)
	}
	// Al revés.
	_, err = SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.9.9.1", Mask: "255.255.255.0"},
		sviOuts(cfgOf("Vlan99", "description x"), "Vlan1                  unassigned      YES unset  up                    down\n"))
	if !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("config con SVI pero brief sin ella: %v", err)
	}
	// Una captura que no es ni la interfaz ni el aviso de IOS tampoco vale.
	_, err = SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.9.9.1", Mask: "255.255.255.0"}, sviOuts("hola\n", "Vlan1                  unassigned      YES unset  up                    down\n"))
	if !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("captura irreconocible: %v", err)
	}
	// Sin la salida de brief tampoco se puede decidir.
	outs := sviOuts(noIface, "")
	delete(outs, "show ip interface brief")
	if _, err := SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.9.9.1", Mask: "255.255.255.0"}, outs); err == nil {
		t.Error("sin show ip interface brief")
	}
}

func TestSVIPlanRefusesDuplicateAddressAndBadValues(t *testing.T) {
	brief := "Vlan10                 10.9.9.1        YES manual up                    up\n"
	if _, err := SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.9.9.1", Mask: "255.255.255.0"}, sviOuts(noIface, brief)); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("dirección repetida: %v", err)
	}
	for _, c := range []SVIChange{
		{VlanID: 0, Address: "10.0.0.1", Mask: "255.255.255.0"}, {VlanID: 4095, Address: "10.0.0.1", Mask: "255.255.255.0"},
		{VlanID: 99, Address: "10.0.0.1", Mask: "255.0.255.0"}, {VlanID: 99, Address: "10.0.0.1", Mask: "0.0.0.0"},
		{VlanID: 99, Address: "10.0.0.1", Mask: "255.255.255.255"}, {VlanID: 99, Address: "0.0.0.0", Mask: "255.255.255.0"},
		{VlanID: 99, Address: "127.0.0.1", Mask: "255.255.255.0"}, {VlanID: 99, Address: "224.0.0.5", Mask: "255.255.255.0"},
		{VlanID: 99, Address: "10.0.0.0", Mask: "255.255.255.0"}, {VlanID: 99, Address: "10.0.0.255", Mask: "255.255.255.0"},
		{VlanID: 99, Address: "10.0.0.1/24", Mask: "255.255.255.0"}, {VlanID: 99, Address: "::1", Mask: "255.255.255.0"},
		{VlanID: 99, Address: "10.0.0.1 secondary", Mask: "255.255.255.0"}, {VlanID: 99, Address: "", Mask: ""},
		{VlanID: 99, Address: "10.0.0.1", Mask: "24"},
	} {
		if _, err := SVIPre(c); err == nil {
			if _, err := SVIPlan("SW1", c, sviOuts(noIface, "")); err == nil {
				t.Errorf("%+v aceptado", c)
			}
		}
	}
	long := strings.Repeat("a", 201)
	for _, d := range []string{long, "x?", "ñ", "a\rb"} {
		if _, err := SVIPlan("SW1", SVIChange{VlanID: 99, Description: &d, Address: "10.0.0.1", Mask: "255.255.255.0"}, sviOuts(noIface, "")); err == nil {
			t.Errorf("descripción %q aceptada", d)
		}
	}
}

func TestSnippetSVIClosedListAndMatchingRemoval(t *testing.T) {
	plan := func(apply, rollback []string) error {
		dp := DevicePlan{Device: "SW1", Pre: []string{showCfg("Vlan99")}, Apply: apply, Rollback: rollback, Post: []string{showCfg("Vlan99")},
			Expect: []Expect{{Command: showCfg("Vlan99"), Line: "shutdown", Present: false}}}
		return Validate(Plan{Function: SnippetSVI.Name, Devices: []DevicePlan{dp}}, SnippetSVI)
	}
	ok := []string{"interface Vlan99", "ip address 10.9.9.1 255.255.255.0", "no shutdown"}
	if err := plan(ok, []string{"no interface Vlan99"}); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string][2][]string{
		"borra otra SVI":            {ok, []string{"no interface Vlan1"}},
		"borra una física":          {ok, []string{"no interface GigabitEthernet1/0/1"}},
		"apply borra":               {{"no interface Vlan99"}, []string{"interface Vlan99", "no ip address"}},
		"interfaz física":           {{"interface GigabitEthernet1/0/1", "no shutdown"}, []string{"shutdown"}},
		"ip secundaria":             {{"interface Vlan99", "ip address 10.9.9.1 255.255.255.0 secondary"}, []string{"no interface Vlan99"}},
		"helper no está en lista":   {{"interface Vlan99", "ip helper-address 10.0.0.9"}, []string{"no interface Vlan99"}},
		"no ip address en el apply": {{"interface Vlan99", "no ip address"}, []string{"no interface Vlan99"}},
		"rango de SVI":              {{"interface range Vlan10-20", "shutdown"}, []string{"no interface Vlan99"}},
		"no interface en un grupo":  {ok, []string{"no interface Vlan99", "no interface Vlan98"}},
	} {
		if err := plan(p[0], p[1]); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("%s: se aceptó (%v)", name, err)
		}
	}
}
