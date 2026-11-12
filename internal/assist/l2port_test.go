package assist

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// iosDev es un modelo mínimo de cómo IOS guarda estas líneas: las de una misma familia se sustituyen, `no` las quita y los valores de
// fábrica no se muestran. Con edge, `spanning-tree portfast` se guarda como `portfast edge`. Es un modelo de la documentación de Cisco,
// sin validar en laboratorio.
type iosDev struct {
	order  []string
	ifaces map[string][]string
	global []string
	edge   bool
	errDis map[string]bool   // puertos que show interfaces X status muestra err-disabled
	oper   map[string]string // modo operativo que show interfaces X switchport muestra, si no es el que sale del modo administrativo
}

func newDev(ifaces map[string][]string, global ...string) *iosDev {
	d := &iosDev{ifaces: ifaces, global: global, errDis: map[string]bool{}}
	for n := range ifaces {
		d.order = append(d.order, n)
	}
	slices.Sort(d.order)
	return d
}

var devFamilies = []string{"speed", "duplex", "storm-control broadcast level", "storm-control multicast level", "storm-control unicast level",
	"spanning-tree portfast", "spanning-tree bpduguard", "switchport port-security maximum", "switchport port-security violation",
	"switchport port-security aging time", "switchport port-security", "errdisable recovery interval", "switchport mode"}

func devFam(line string) string {
	best := ""
	for _, f := range devFamilies {
		if (line == f || strings.HasPrefix(line, f+" ")) && len(f) > len(best) {
			best = f
		}
	}
	return ifElse(best != "", best, line)
}

var devDefaults = []string{"speed auto", "duplex auto", "storm-control broadcast level 100.00", "storm-control multicast level 100.00", "storm-control unicast level 100.00",
	"switchport port-security maximum 1", "switchport port-security violation shutdown", "switchport port-security aging time 0", "errdisable recovery interval 300", "switchport mode dynamic auto"}

func (d *iosDev) apply(lines []string) {
	cur := ""
	for _, l := range lines {
		if n, ok := strings.CutPrefix(l, "interface "); ok {
			cur = n
			continue
		}
		list := d.global
		if cur != "" {
			list = d.ifaces[cur]
		}
		body, neg := strings.CutPrefix(l, "no ")
		if neg && strings.HasPrefix(body, "errdisable recovery cause") {
			body = strings.TrimPrefix(l, "no ")
		}
		k := devFam(body)
		if strings.HasPrefix(body, "errdisable recovery cause") {
			k = body
		}
		var out []string
		for _, x := range list {
			if devFam(x) != k && x != k {
				out = append(out, x)
			}
		}
		if !neg && !slices.Contains(devDefaults, l) {
			if d.edge && l == "spanning-tree portfast" {
				l = "spanning-tree portfast edge"
			}
			out = append(out, l)
		}
		if cur != "" {
			d.ifaces[cur] = out
		} else {
			d.global = out
		}
	}
}

func (d *iosDev) cfg(n string) string {
	l, ok := d.ifaces[n]
	if !ok {
		return "                 ^\n% Invalid input detected at '^' marker.\n"
	}
	return "Building configuration...\n\nCurrent configuration : 100 bytes\n!\ninterface " + n + "\n " + strings.Join(l, "\n ") + "\nend\n"
}

func (d *iosDev) read(cmds []string) map[string]string {
	out := map[string]string{}
	for _, c := range cmds {
		switch {
		case c == errdisableCmd:
			out[c] = strings.Join(d.global, "\n") + "\n"
		case strings.HasPrefix(c, "show running-config interface "):
			out[c] = d.cfg(strings.TrimPrefix(c, "show running-config interface "))
		case strings.HasSuffix(c, " switchport") || strings.HasSuffix(c, " switchport | include Mode:"):
			n := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(c, "show interfaces "), " | include Mode:"), " switchport")
			mode := "dynamic auto"
			for _, l := range d.ifaces[n] {
				switch l {
				case "switchport mode access":
					mode = "static access"
				case "switchport mode trunk":
					mode = "trunk"
				case "switchport mode dynamic desirable":
					mode = "dynamic desirable"
				}
			}
			oper := mode
			if strings.HasPrefix(mode, "dynamic") {
				oper = "down" // un dynamic sin vecino que negocie no opera como trunk
			}
			if o, ok := d.oper[n]; ok {
				oper = o
			}
			if strings.HasSuffix(c, "| include Mode:") { // el filtro de IOS deja solo las líneas con «Mode:»
				out[c] = "Administrative Mode: " + mode + "\nOperational Mode: " + oper + "\n"
				break
			}
			out[c] = "Name: " + n + "\nSwitchport: Enabled\nAdministrative Mode: " + mode + "\nOperational Mode: " + oper + "\n"
		case strings.HasSuffix(c, " status"):
			n := strings.TrimSuffix(strings.TrimPrefix(c, "show interfaces "), " status")
			out[c] = "Port      Name               Status       Vlan       Duplex  Speed Type\n" +
				fmt.Sprintf("%-9s %-18s %-12s %-10s a-full  a-1000 10/100/1000BaseTX\n", n, "", ifElse(d.errDis[n], "err-disabled", "connected"), "10")
		}
	}
	return out
}

// roundTrip planea con el estado del equipo, aplica, comprueba lo esperado, aplica la reversa y exige que cada comando de la línea
// base quede idéntico (el criterio de run.go), y devuelve el plan.
func roundTrip(t *testing.T, id string, v Values, dev *iosDev) DevicePlan {
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
	dp, err := tpl.Plan("SW1", v, dev.read(pre))
	if err != nil {
		t.Fatal(err)
	}
	for cmd := range dp.Baseline {
		if !slices.Contains(dp.Pre, cmd) {
			t.Errorf("la línea base cita %q, que Pre no lee: el plan caducaría siempre", cmd)
		}
	}
	dev.apply(dp.Apply)
	if fails := EvalExpect(dp.Expect, dev.read(dp.Post)); len(fails) > 0 {
		t.Errorf("tras aplicar: %v", fails)
	}
	dev.apply(dp.Rollback)
	for cmd, base := range dp.Baseline {
		if !strings.HasPrefix(cmd, "show running-config") { // como checkBase: el estado operativo no se compara línea a línea
			continue
		}
		if d := residue(base, dev.read([]string{cmd})[cmd]); d != "" {
			t.Errorf("la reversa no dejó %q como estaba: %s", cmd, d)
		}
	}
	return dp
}

func joined(l []string) string { return strings.Join(l, "|") }

func accessGi(extra ...string) []string { return append([]string{"switchport mode access"}, extra...) }

// ---- speed-duplex ----

func TestSpeedDuplexEmptyStateRollbackIsNo(t *testing.T) {
	dev := newDev(map[string][]string{gi1: accessGi(), gi2: accessGi()})
	dp := roundTrip(t, "speed-duplex", Values{"interfaces": gi1 + "," + gi2, "speed": "100", "duplex": "full"}, dev)
	if got := joined(dp.Apply); got != "interface "+gi1+"|speed 100|duplex full|interface "+gi2+"|speed 100|duplex full" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "interface "+gi2+"|no duplex|no speed|interface "+gi1+"|no duplex|no speed" {
		t.Errorf("Rollback = %s", got)
	}
	if len(dp.Notes) == 0 || !strings.Contains(dp.Notes[0], "reinicia el enlace") {
		t.Errorf("falta el aviso del rebote: %v", dp.Notes)
	}
}

func TestSpeedDuplexRestoresCapturedValues(t *testing.T) {
	dev := newDev(map[string][]string{gi1: accessGi("speed 10", "duplex half"), gi2: accessGi("speed 100")})
	dp := roundTrip(t, "speed-duplex", Values{"interfaces": gi1 + " " + gi2, "speed": "1000", "duplex": "full"}, dev)
	if got := joined(dp.Rollback); got != "interface "+gi2+"|no duplex|speed 100|interface "+gi1+"|duplex half|speed 10" {
		t.Errorf("Rollback = %s", got)
	}
	// speed auto quita la línea: lo esperado es que ya no aparezca, y la reversa vuelve a ponerla.
	dev = newDev(map[string][]string{gi1: accessGi("speed 100")})
	dp = roundTrip(t, "speed-duplex", Values{"interfaces": gi1, "speed": "auto"}, dev)
	if joined(dp.Apply) != "interface "+gi1+"|speed auto" || joined(dp.Rollback) != "interface "+gi1+"|speed 100" || dp.Expect[0].Present {
		t.Errorf("%+v", dp)
	}
}

func TestSpeedDuplexSkipsWhatIsAlreadySet(t *testing.T) {
	dev := newDev(map[string][]string{gi1: accessGi("speed 100", "duplex full"), gi2: accessGi()})
	dp, err := templatePlan(t, "speed-duplex", Values{"interfaces": gi1 + "," + gi2, "speed": "100", "duplex": "full"}, dev)
	if err != nil || strings.Contains(joined(dp.Apply), gi1) || !strings.Contains(joined(dp.Apply), gi2) {
		t.Fatalf("%v %v", dp.Apply, err)
	}
	if _, err := templatePlan(t, "speed-duplex", Values{"interfaces": gi1, "speed": "100"}, dev); err == nil || !strings.Contains(err.Error(), "nada que cambiar") {
		t.Errorf("sin cambios: %v", err)
	}
	if _, err := templatePlan(t, "speed-duplex", Values{"interfaces": gi2, "speed": "auto"}, dev); err == nil {
		t.Error("speed auto sobre un puerto sin speed no cambia nada")
	}
}

// templatePlan planea sin aplicar.
func templatePlan(t *testing.T, id string, v Values, dev *iosDev) (DevicePlan, error) {
	t.Helper()
	tpl, _ := TemplateByID(id)
	if err := ValidateValues(tpl, v); err != nil {
		t.Fatal(err)
	}
	pre, err := tpl.Pre(v)
	if err != nil {
		t.Fatal(err)
	}
	return tpl.Plan("SW1", v, dev.read(pre))
}

func wantRefused(t *testing.T, what, id string, v Values, dev *iosDev) {
	t.Helper()
	if _, err := templatePlan(t, id, v, dev); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("%s: debía rechazarse con ErrSnippetRefused y dio %v", what, err)
	}
}

func TestSpeedDuplexRefusals(t *testing.T) {
	v := Values{"interfaces": gi1, "speed": "100"}
	wantRefused(t, "miembro de canal", "speed-duplex", v, newDev(map[string][]string{gi1: accessGi("channel-group 1 mode active")}))
	wantRefused(t, "ruteado", "speed-duplex", v, newDev(map[string][]string{gi1: {"no switchport", "ip address 10.0.0.1 255.255.255.0"}}))
	wantRefused(t, "inexistente", "speed-duplex", v, newDev(map[string][]string{gi2: accessGi()}))
	wantRefused(t, "speed que la reversa no restaura", "speed-duplex", v, newDev(map[string][]string{gi1: accessGi("speed nonegotiate")}))
	wantRefused(t, "duplex half a 1000", "speed-duplex", Values{"interfaces": gi1, "speed": "1000", "duplex": "half"}, newDev(map[string][]string{gi1: accessGi()}))
	wantRefused(t, "duplex half con speed 1000 capturado", "speed-duplex", Values{"interfaces": gi1, "duplex": "half"}, newDev(map[string][]string{gi1: accessGi("speed 1000")}))
	if _, err := templatePlan(t, "speed-duplex", Values{"interfaces": gi1}, newDev(map[string][]string{gi1: accessGi()})); err == nil {
		t.Error("sin velocidad ni duplex")
	}
}

// ---- storm-control ----

func TestStormControlEmptyStateRollbackIsNo(t *testing.T) {
	dev := newDev(map[string][]string{gi1: accessGi()})
	dp := roundTrip(t, "storm-control", Values{"interfaces": gi1, "broadcast": "20", "multicast": "5.5", "action": "shutdown"}, dev)
	if got := joined(dp.Apply); got != "interface "+gi1+"|storm-control broadcast level 20.00|storm-control multicast level 5.50|storm-control action shutdown" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "interface "+gi1+"|no storm-control action shutdown|no storm-control multicast level|no storm-control broadcast level" {
		t.Errorf("Rollback = %s", got)
	}
}

func TestStormControlRestoresCapturedLines(t *testing.T) {
	dev := newDev(map[string][]string{gi1: accessGi("storm-control broadcast level 30.00 10.00", "storm-control action trap")})
	dp := roundTrip(t, "storm-control", Values{"interfaces": gi1, "broadcast": "50", "unicast": "0", "action": "shutdown"}, dev)
	// shutdown y trap son banderas independientes: la reversa quita solo la que se agregó y deja trap.
	if got := joined(dp.Rollback); got != "interface "+gi1+"|no storm-control action shutdown|no storm-control unicast level|storm-control broadcast level 30.00 10.00" {
		t.Errorf("Rollback = %s", got)
	}
	// 100.00 es el nivel de fábrica: IOS no lo muestra y lo esperado es que la línea no aparezca.
	dp = roundTrip(t, "storm-control", Values{"interfaces": gi1, "broadcast": "100"}, newDev(map[string][]string{gi1: accessGi("storm-control broadcast level 30.00")}))
	if dp.Expect[0].Present || !dp.Expect[0].Prefix {
		t.Errorf("%+v", dp.Expect[0])
	}
}

// Con las dos acciones en la línea base: la que ya está no se toca, y pedir una nueva no pisa ni quita la otra.
func TestStormControlActionsAreIndependentFlags(t *testing.T) {
	both := func() *iosDev {
		return newDev(map[string][]string{gi1: accessGi("storm-control action shutdown", "storm-control action trap")})
	}
	if _, err := templatePlan(t, "storm-control", Values{"interfaces": gi1, "action": "shutdown"}, both()); err == nil || !strings.Contains(err.Error(), "nada que cambiar") {
		t.Errorf("shutdown ya estaba: %v", err)
	}
	dp := roundTrip(t, "storm-control", Values{"interfaces": gi1, "action": "trap", "broadcast": "20"}, both())
	if joined(dp.Apply) != "interface "+gi1+"|storm-control broadcast level 20.00" {
		t.Errorf("Apply = %v", dp.Apply)
	}
	only := newDev(map[string][]string{gi1: accessGi("storm-control action trap")})
	dp = roundTrip(t, "storm-control", Values{"interfaces": gi1, "action": "shutdown"}, only)
	if joined(dp.Rollback) != "interface "+gi1+"|no storm-control action shutdown" {
		t.Errorf("Rollback = %v", dp.Rollback)
	}
	if only.ifaces[gi1][len(only.ifaces[gi1])-1] != "storm-control action trap" {
		t.Errorf("la reversa no dejó trap: %v", only.ifaces[gi1])
	}
	wantRefused(t, "acción desconocida", "storm-control", Values{"interfaces": gi1, "action": "shutdown"}, newDev(map[string][]string{gi1: accessGi("storm-control action filter")}))
	wantRefused(t, "forma desconocida", "storm-control", Values{"interfaces": gi1, "broadcast": "5"}, newDev(map[string][]string{gi1: accessGi("storm-control broadcast foo")}))
}

func TestStormControlRefusals(t *testing.T) {
	v := Values{"interfaces": gi1, "broadcast": "20"}
	wantRefused(t, "canal", "storm-control", v, newDev(map[string][]string{gi1: accessGi("channel-group 2 mode on")}))
	wantRefused(t, "ruteado", "storm-control", v, newDev(map[string][]string{gi1: {"no switchport"}}))
	wantRefused(t, "umbral en bps", "storm-control", v, newDev(map[string][]string{gi1: accessGi("storm-control broadcast level bps 1m")}))
	wantRefused(t, "inexistente", "storm-control", v, newDev(map[string][]string{gi2: accessGi()}))
	if _, err := templatePlan(t, "storm-control", Values{"interfaces": gi1}, newDev(map[string][]string{gi1: accessGi()})); err == nil {
		t.Error("sin umbral ni acción")
	}
	if _, err := templatePlan(t, "storm-control", v, newDev(map[string][]string{gi1: accessGi("storm-control broadcast level 20.00")})); err == nil {
		t.Error("el mismo umbral no cambia nada")
	}
}

// ---- portfast-bpduguard ----

func TestPortfastBpduguardEmptyStateRollbackIsNo(t *testing.T) {
	for _, edge := range []bool{false, true} { // IOS puede guardar `portfast` como `portfast edge`
		dev := newDev(map[string][]string{gi1: accessGi("switchport access vlan 10"), gi2: accessGi()})
		dev.edge = edge
		dp := roundTrip(t, "portfast-bpduguard", Values{"interfaces": gi1 + "," + gi2, "portfast": "true", "bpduguard": "true"}, dev)
		if got := joined(dp.Rollback); got != "interface "+gi2+"|no spanning-tree bpduguard|no spanning-tree portfast|interface "+gi1+"|no spanning-tree bpduguard|no spanning-tree portfast" {
			t.Errorf("edge=%v Rollback = %s", edge, got)
		}
	}
}

func TestPortfastBpduguardRestoresAndSkips(t *testing.T) {
	// Ya tiene portfast edge: solo se agrega la guardia, y la reversa deja la guardia en disable como estaba.
	dev := newDev(map[string][]string{gi1: accessGi("spanning-tree portfast edge", "spanning-tree bpduguard disable")})
	dp := roundTrip(t, "portfast-bpduguard", Values{"interfaces": gi1, "portfast": "true", "bpduguard": "true"}, dev)
	if joined(dp.Apply) != "interface "+gi1+"|spanning-tree bpduguard enable" || joined(dp.Rollback) != "interface "+gi1+"|spanning-tree bpduguard disable" {
		t.Errorf("%v %v", dp.Apply, dp.Rollback)
	}
	if _, err := templatePlan(t, "portfast-bpduguard", Values{"interfaces": gi1, "bpduguard": "true"}, newDev(map[string][]string{gi1: accessGi("spanning-tree bpduguard enable")})); err == nil {
		t.Error("la guardia ya estaba activa")
	}
	// Un puerto sin la línea «switchport mode access» pero con Administrative Mode static access también es de acceso.
	tpl, _ := TemplateByID("portfast-bpduguard")
	v := Values{"interfaces": gi1, "portfast": "true"}
	outs := map[string]string{showCfg(gi1): cfgOf(gi1, "switchport access vlan 10"), showSwitchport(gi1): "Name: Gi1/0/1\nSwitchport: Enabled\nAdministrative Mode: static access\nOperational Mode: down\n",
		showStatus(gi1): newDev(map[string][]string{gi1: nil}).read([]string{showStatus(gi1)})[showStatus(gi1)]}
	if dp, err := tpl.Plan("SW1", v, outs); err != nil || joined(dp.Rollback) != "interface "+gi1+"|no spanning-tree portfast" {
		t.Errorf("%v %v", dp.Rollback, err)
	}
	// Uno dynamic (el modelo lo muestra dynamic auto) se rechaza: no es un puerto de acceso explícito.
	wantRefused(t, "dynamic auto de fábrica", "portfast-bpduguard", v, newDev(map[string][]string{gi1: {"switchport access vlan 10"}}))
}

func TestPortfastBpduguardRefusals(t *testing.T) {
	v := Values{"interfaces": gi1, "portfast": "true"}
	wantRefused(t, "trunk", "portfast-bpduguard", v, newDev(map[string][]string{gi1: {"switchport mode trunk"}}))
	wantRefused(t, "dynamic desirable", "portfast-bpduguard", v, newDev(map[string][]string{gi1: {"switchport mode dynamic desirable"}}))
	wantRefused(t, "canal", "portfast-bpduguard", v, newDev(map[string][]string{gi1: accessGi("channel-group 1 mode on")}))
	wantRefused(t, "ruteado", "portfast-bpduguard", v, newDev(map[string][]string{gi1: {"no switchport", "ip address 10.0.0.1 255.255.255.0"}}))
	wantRefused(t, "portfast trunk", "portfast-bpduguard", v, newDev(map[string][]string{gi1: accessGi("spanning-tree portfast trunk")}))
	wantRefused(t, "portfast disable", "portfast-bpduguard", v, newDev(map[string][]string{gi1: accessGi("spanning-tree portfast disable")}))
	if _, err := templatePlan(t, "portfast-bpduguard", Values{"interfaces": gi1}, newDev(map[string][]string{gi1: accessGi()})); err == nil {
		t.Error("sin portfast ni guardia")
	}
}

// ---- port-security ----

func TestPortSecurityEmptyStateRollbackUndoesEverySubcommandInReverse(t *testing.T) {
	dev := newDev(map[string][]string{gi1: accessGi("switchport access vlan 10")})
	dp := roundTrip(t, "port-security", Values{"interfaces": gi1, "maximum": "3", "violation": "restrict", "aging_time": "10"}, dev)
	// Los subcomandos van primero y port-security se activa al final (sin ventana con el máximo de fábrica); la reversa lo apaga primero.
	if got := joined(dp.Apply); got != "interface "+gi1+"|switchport port-security maximum 3|switchport port-security violation restrict|switchport port-security aging time 10|switchport port-security" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "interface "+gi1+"|no switchport port-security|no switchport port-security aging time|no switchport port-security violation|no switchport port-security maximum" {
		t.Errorf("Rollback = %s", got)
	}
	// Con los valores de fábrica IOS no muestra las líneas: lo esperado es que no aparezcan, y la reversa igual las deshace.
	dev = newDev(map[string][]string{gi1: accessGi()})
	dp = roundTrip(t, "port-security", Values{"interfaces": gi1, "maximum": "1", "violation": "shutdown", "aging_time": "0"}, dev)
	absent := 0
	for _, e := range dp.Expect {
		if !e.Present && e.Prefix {
			absent++
		}
	}
	if absent != 3 {
		t.Errorf("Expect = %+v", dp.Expect)
	}
	roundTrip(t, "port-security", Values{"interfaces": gi1}, newDev(map[string][]string{gi1: accessGi()})) // solo activarlo
}

func TestPortSecurityRefusals(t *testing.T) {
	v := Values{"interfaces": gi1, "maximum": "2"}
	wantRefused(t, "sin mode access explícito", "port-security", v, newDev(map[string][]string{gi1: {"switchport access vlan 10"}}))
	wantRefused(t, "dynamic", "port-security", v, newDev(map[string][]string{gi1: {"switchport mode dynamic desirable"}}))
	wantRefused(t, "trunk", "port-security", v, newDev(map[string][]string{gi1: {"switchport mode trunk"}}))
	wantRefused(t, "ruteado", "port-security", v, newDev(map[string][]string{gi1: {"no switchport"}}))
	wantRefused(t, "mode access con líneas de trunk", "port-security", v, newDev(map[string][]string{gi1: accessGi("switchport trunk native vlan 5")}))
	wantRefused(t, "canal", "port-security", v, newDev(map[string][]string{gi1: accessGi("channel-group 1 mode on")}))
	for _, had := range []string{"switchport port-security", "switchport port-security maximum 5", "switchport port-security mac-address sticky", "switchport port-security violation restrict"} {
		wantRefused(t, "ya tiene "+had, "port-security", v, newDev(map[string][]string{gi1: accessGi(had)}))
	}
}

// ---- errdisable-recovery ----

func TestErrdisableRecoveryEmptyAndCaptured(t *testing.T) {
	dev := newDev(nil)
	dp := roundTrip(t, "errdisable-recovery", Values{"cause_bpduguard": "true", "cause_psecure_violation": "true", "interval": "600"}, dev)
	if got := joined(dp.Apply); got != "errdisable recovery cause bpduguard|errdisable recovery cause psecure-violation|errdisable recovery interval 600" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "no errdisable recovery interval|no errdisable recovery cause psecure-violation|no errdisable recovery cause bpduguard" {
		t.Errorf("Rollback = %s", got)
	}
	// Con estado previo: la causa que ya estaba no se toca y el intervalo capturado se restaura.
	dev = newDev(nil, "errdisable recovery cause bpduguard", "errdisable recovery cause udld", "errdisable recovery interval 900")
	dp = roundTrip(t, "errdisable-recovery", Values{"cause_bpduguard": "true", "cause_link_flap": "true", "interval": "120"}, dev)
	if got := joined(dp.Apply); got != "errdisable recovery cause link-flap|errdisable recovery interval 120" {
		t.Errorf("Apply = %s", got)
	}
	if got := joined(dp.Rollback); got != "errdisable recovery interval 900|no errdisable recovery cause link-flap" {
		t.Errorf("Rollback = %s", got)
	}
	// El intervalo de fábrica (300) no sale en el running-config.
	dp = roundTrip(t, "errdisable-recovery", Values{"interval": "300"}, newDev(nil, "errdisable recovery interval 900"))
	if dp.Expect[0].Present || !dp.Expect[0].Prefix {
		t.Errorf("%+v", dp.Expect)
	}
}

func TestErrdisableRecoveryRefusalsAndNoops(t *testing.T) {
	if _, err := templatePlan(t, "errdisable-recovery", Values{"cause_udld": "true"}, newDev(nil, "errdisable recovery cause udld")); err == nil || !strings.Contains(err.Error(), "nada que cambiar") {
		t.Errorf("causa ya activa: %v", err)
	}
	if _, err := templatePlan(t, "errdisable-recovery", Values{"interval": "300"}, newDev(nil)); err == nil {
		t.Error("300 sin intervalo capturado es el valor de fábrica: no cambia nada")
	}
	if _, err := templatePlan(t, "errdisable-recovery", Values{}, newDev(nil)); err == nil {
		t.Error("sin causa ni intervalo")
	}
	wantRefused(t, "cause all", "errdisable-recovery", Values{"cause_udld": "true"}, newDev(nil, "errdisable recovery cause all"))
	tpl, _ := TemplateByID("errdisable-recovery")
	if _, err := tpl.Plan("SW1", Values{"cause_udld": "true"}, map[string]string{errdisableCmd: "% Invalid input detected at '^' marker.\n"}); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("salida ilegible: %v", err)
	}
	if _, err := tpl.Plan("SW1", Values{"cause_udld": "true"}, map[string]string{}); err == nil {
		t.Error("sin salida capturada")
	}
}

// ---- la reversa debe ser la inversa del apply, contra lo capturado ----

func TestL2CheckDeviceRejectsAReversaThatIsNotTheInverse(t *testing.T) {
	dev := newDev(map[string][]string{gi1: accessGi("speed 10"), gi2: accessGi()})
	good, err := templatePlan(t, "speed-duplex", Values{"interfaces": gi1 + "," + gi2, "speed": "100", "duplex": "full"}, dev)
	if err != nil {
		t.Fatal(err)
	}
	tamper := func(name string, mod func(d *DevicePlan)) {
		d := good
		d.Apply, d.Rollback = slices.Clone(good.Apply), slices.Clone(good.Rollback)
		d.Baseline = good.Baseline
		mod(&d)
		if err := Validate(Plan{Function: SnippetSpeedDuplex.Name, Devices: []DevicePlan{d}}, SnippetSpeedDuplex); err == nil {
			t.Errorf("%s: la reversa torcida pasó Validate", name)
		}
	}
	if err := Validate(Plan{Function: SnippetSpeedDuplex.Name, Devices: []DevicePlan{good}}, SnippetSpeedDuplex); err != nil {
		t.Fatalf("el plan bueno no valida: %v", err)
	}
	idx := slices.Index(good.Rollback, "speed 10")
	tamper("no restaura lo capturado", func(d *DevicePlan) { d.Rollback[idx] = "speed 100" })
	tamper("manda no en vez de restaurar", func(d *DevicePlan) { d.Rollback[idx] = "no speed" })
	tamper("restaura donde no había nada", func(d *DevicePlan) { d.Rollback[slices.Index(d.Rollback, "no speed")] = "speed 10" })
	tamper("otro puerto", func(d *DevicePlan) { d.Rollback[0] = "interface " + gi1 })
	tamper("sin una línea de la reversa", func(d *DevicePlan) { d.Rollback = slices.Delete(d.Rollback, idx, idx+1) })
	tamper("orden directo", func(d *DevicePlan) {
		d.Rollback = slices.Concat(good.Rollback[len(good.Rollback)/2:], good.Rollback[:len(good.Rollback)/2])
	})
	tamper("apply con no", func(d *DevicePlan) { d.Apply[1] = "no speed" })
	tamper("línea de otra función", func(d *DevicePlan) { d.Apply = append(d.Apply, "switchport port-security") })
}

func TestL2FunctionsAreClosedLists(t *testing.T) {
	deny := map[string][]string{
		"snippet-speed-duplex":        {"speed 10000", "speed nonegotiate", "duplex quarter", "speed", "no speed 100 x", "shutdown", "interface Port-channel1", "interface Gi1/0/1 Gi1/0/2"},
		"snippet-storm-control":       {"storm-control broadcast level 100.01", "storm-control broadcast level bps 1m", "storm-control action filter", "storm-control broadcast", "no storm-control action", "storm-control broadcast level 5.123"},
		"snippet-portfast-bpduguard":  {"spanning-tree portfast trunk", "spanning-tree portfast disable", "spanning-tree bpduguard", "no spanning-tree portfast edge", "spanning-tree bpdufilter enable"},
		"snippet-port-security":       {"switchport port-security maximum 0", "switchport port-security maximum 3073", "switchport port-security violation drop", "switchport port-security aging time 1441", "switchport port-security mac-address sticky", "no switchport port-security mac-address sticky", "switchport port-security maximum 2 vlan 10"},
		"snippet-errdisable-recovery": {"errdisable recovery cause all", "errdisable recovery cause", "errdisable recovery interval 29", "errdisable recovery interval 86401", "no errdisable recovery interval 300", "errdisable detect cause all"},
	}
	for _, fn := range []Function{SnippetSpeedDuplex, SnippetStormControl, SnippetPortfast, SnippetPortSecurity, SnippetErrdisable} {
		for _, l := range deny[fn.Name] {
			if err := fn.configLine(l); err == nil {
				t.Errorf("%s aceptó %q", fn.Name, l)
			}
		}
		for _, l := range []string{"reload", "write memory", "do show run", "no username x", "end"} {
			if err := fn.configLine(l); err == nil {
				t.Errorf("%s aceptó %q", fn.Name, l)
			}
		}
	}
}

// ---- revisión independiente de 28b ----

// Las tres plantillas que pueden dejar el puerto err-disabled leen su estado en Pre, lo guardan en la línea base y avisan que la reversa no lo recupera.
func TestGuardTemplatesBaselineThePortStatus(t *testing.T) {
	for id, v := range map[string]Values{
		"port-security":      {"interfaces": gi1, "maximum": "2"},
		"portfast-bpduguard": {"interfaces": gi1, "bpduguard": "true"},
		"storm-control":      {"interfaces": gi1, "action": "shutdown"},
	} {
		dev := newDev(map[string][]string{gi1: accessGi()})
		dp := roundTrip(t, id, v, dev)
		st := showStatus(gi1)
		if _, ok := dp.Baseline[st]; !ok || !slices.Contains(dp.Pre, st) || !slices.Contains(dp.Post, st) {
			t.Errorf("%s: el estado del puerto debe estar en Pre, Post y la línea base: %+v", id, dp)
		}
		if len(dp.Notes) == 0 || !strings.Contains(dp.Notes[0], "err-disabled") {
			t.Errorf("%s: falta el aviso de err-disabled: %v", id, dp.Notes)
		}
	}
	// speed-duplex no lo lee: el enlace sigue renegociando cuando corre el post-check.
	dp := roundTrip(t, "speed-duplex", Values{"interfaces": gi1, "speed": "100"}, newDev(map[string][]string{gi1: accessGi()}))
	if _, ok := dp.Baseline[showStatus(gi1)]; ok || slices.Contains(dp.Pre, showStatus(gi1)) || slices.Contains(dp.Post, showStatus(gi1)) {
		t.Errorf("speed-duplex: %+v", dp)
	}
	// Sin poder leer el estado no se promete que la reversa lo deje igual.
	tpl, _ := TemplateByID("port-security")
	dev := newDev(map[string][]string{gi1: accessGi()})
	v := Values{"interfaces": gi1}
	pre, _ := tpl.Pre(v)
	outs := dev.read(pre)
	outs[showStatus(gi1)] = "% Invalid input detected at '^' marker.\n"
	if _, err := tpl.Plan("SW1", v, outs); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("estado ilegible: %v", err)
	}
	delete(outs, showStatus(gi1))
	if _, err := tpl.Plan("SW1", v, outs); err == nil {
		t.Error("sin la salida del estado")
	}
}

func TestSpeedDuplexRefusesWhatTheReversaCannotRestoreAsRefusal(t *testing.T) {
	for _, had := range []string{"speed auto 10 100", "duplex auto full", "speed nonegotiate"} {
		wantRefused(t, had, "speed-duplex", Values{"interfaces": gi1, "speed": "100", "duplex": "full"}, newDev(map[string][]string{gi1: accessGi(had)}))
	}
	wantRefused(t, "bpduguard sin argumento", "portfast-bpduguard", Values{"interfaces": gi1, "bpduguard": "true"}, newDev(map[string][]string{gi1: accessGi("spanning-tree bpduguard")}))
}

func TestSpeedDuplexHalfAt1000UsesTheEffectiveValues(t *testing.T) {
	// Pedir speed 1000 con duplex half capturado (y el duplex no tocado) es la misma combinación que IOS rechaza.
	wantRefused(t, "speed 1000 sobre duplex half capturado", "speed-duplex", Values{"interfaces": gi1, "speed": "1000"}, newDev(map[string][]string{gi1: accessGi("duplex half")}))
	// Pero si el duplex pedido lo cambia, es válido.
	roundTrip(t, "speed-duplex", Values{"interfaces": gi1, "speed": "1000", "duplex": "full"}, newDev(map[string][]string{gi1: accessGi("duplex half")}))
}

func TestErrdisableRecoveryIntervalHasNoDefaultAndKeepsUnknownCauses(t *testing.T) {
	tpl, _ := TemplateByID("errdisable-recovery")
	for _, f := range tpl.Fields {
		if f.Name == "interval" && f.Default != "" {
			t.Errorf("el intervalo no puede traer valor sugerido (pisaría uno existente): %q", f.Default)
		}
	}
	// Una causa que el parser no conoce no rechaza el equipo ni se toca.
	dev := newDev(nil, "errdisable recovery cause channel-misconfig (STP)", "errdisable recovery interval 600")
	dp := roundTrip(t, "errdisable-recovery", Values{"cause_udld": "true"}, dev)
	if joined(dp.Apply) != "errdisable recovery cause udld" || joined(dp.Rollback) != "no errdisable recovery cause udld" {
		t.Errorf("%v %v", dp.Apply, dp.Rollback)
	}
}

func TestStormControlActionHelpSaysEmptyDoesNotTouch(t *testing.T) {
	tpl, _ := TemplateByID("storm-control")
	for _, f := range tpl.Fields {
		if f.Name == "action" && (!strings.Contains(f.Help, "Vacío no la toca") || strings.Contains(f.Help, "filtrar")) {
			t.Errorf("ayuda = %q", f.Help)
		}
	}
}
