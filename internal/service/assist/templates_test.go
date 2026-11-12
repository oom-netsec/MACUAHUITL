package assist

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/assist"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func tplReq(id string, vals map[string]string) *v1.PlanSnippetRequest {
	return &v1.PlanSnippetRequest{Snippet: &v1.PlanSnippetRequest_Template{Template: &v1.TemplateSnippet{Id: id, Values: vals}}}
}

func TestListSnippetTemplatesMapsTheCatalog(t *testing.T) {
	r := newRig(t, simulator.Config{})
	all, err := r.svc.ListSnippetTemplates(context.Background(), &v1.ListSnippetTemplatesRequest{})
	if err != nil || len(all.Templates) < 9 {
		t.Fatalf("%v %d", err, len(all.Templates))
	}
	ids := map[string]*v1.SnippetTemplate{}
	for _, tp := range all.Templates {
		ids[tp.Id] = tp
	}
	st := ids["storm-control"]
	if st == nil || st.Tech != "l2" || st.Name == "" || !reflect.DeepEqual(st.Platforms, []string{"ios", "ios-xe"}) {
		t.Fatalf("storm-control = %+v", st)
	}
	var bc, act *v1.SnippetField
	for _, f := range st.Fields {
		switch f.Name {
		case "broadcast":
			bc = f
		case "action":
			act = f
		}
	}
	if bc == nil || bc.Type != "decimal" || bc.Min != 0 || bc.Max != 100 || bc.Label == "" || act == nil || !reflect.DeepEqual(act.Choices, []string{"shutdown", "trap"}) {
		t.Fatalf("campos %+v %+v", bc, act)
	}
	if ids["svi"].Tech != "l3" || ids["vlan"].Fields[0].Type != "vlan_id" {
		t.Fatalf("%+v", ids["svi"])
	}
	// El filtro por plataforma: ninguna plantilla de este lote es de otra.
	ios, _ := r.svc.ListSnippetTemplates(context.Background(), &v1.ListSnippetTemplatesRequest{Platform: "ios"})
	none, _ := r.svc.ListSnippetTemplates(context.Background(), &v1.ListSnippetTemplatesRequest{Platform: "nxos"})
	if len(ios.Templates) != len(all.Templates) || len(none.Templates) != 0 {
		t.Fatalf("ios=%d nxos=%d", len(ios.Templates), len(none.Templates))
	}
}

func TestPlanSnippetTemplateRejectsUnknownAndInvalidBeforeConnecting(t *testing.T) {
	r := newRig(t, simulator.Config{})
	for name, req := range map[string]*v1.PlanSnippetRequest{
		"desconocida":      tplReq("no-existe", nil),
		"sin id":           tplReq("", nil),
		"sin plantilla":    {Snippet: &v1.PlanSnippetRequest_Template{}},
		"valor inválido":   tplReq("speed-duplex", map[string]string{"interfaces": gi1, "speed": "9999"}),
		"falta puertos":    tplReq("speed-duplex", map[string]string{"speed": "100"}),
		"campo de más":     tplReq("speed-duplex", map[string]string{"interfaces": gi1, "speed": "100", "otro": "x"}),
		"no ASCII":         tplReq("port-security", map[string]string{"interfaces": gi1, "maximum": "2Ê"}),
		"puerto no físico": tplReq("port-security", map[string]string{"interfaces": "Port-channel1"}),
	} {
		if _, err := r.snippet(req); code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(r.rec.Lines()) != 0 {
		t.Fatalf("se configuró algo: %q", r.rec.Lines())
	}
}

func TestPlanSnippetTemplateRefusalIsFailedPrecondition(t *testing.T) {
	r := newRig(t, simulator.Config{Interfaces: map[string][]string{gi1: {"switchport mode trunk"}}})
	if _, err := r.snippet(tplReq("port-security", map[string]string{"interfaces": gi1})); code(err) != codes.FailedPrecondition {
		t.Fatalf("trunk: %v", err)
	}
}

// Plan completo contra el simulador; la ejecución falla a mitad y la reversa deja el puerto idéntico a la línea base (el motor lo verifica:
// si sobrara o faltara una línea la ejecución no pasaría a rolled-back).
func TestPlanSnippetTemplateEndToEndRollbackMatchesTheBaseline(t *testing.T) {
	r := newRig(t, simulator.Config{Interfaces: map[string][]string{gi1: {"description Impresora", "switchport access vlan 10", "switchport mode access", "speed 10"}},
		ConfigErrors: map[string]string{"duplex full": "% Invalid input detected at '^' marker."}})
	res, err := r.snippet(tplReq("speed-duplex", map[string]string{"interfaces": gi1, "speed": "100", "duplex": "full"}))
	if err != nil {
		t.Fatal(err)
	}
	dp := res.Plan.Devices[0]
	if !reflect.DeepEqual(dp.Apply, []string{"interface " + gi1, "speed 100", "duplex full"}) ||
		!reflect.DeepEqual(dp.Rollback, []string{"interface " + gi1, "no duplex", "speed 10"}) || len(dp.Notes) == 0 {
		t.Fatalf("plan = %+v", dp)
	}
	if len(r.rec.Lines()) != 0 {
		t.Fatalf("planear no configura: %q", r.rec.Lines())
	}
	run := r.runToState(res.PlanId, "failed")
	r.rollback(run)
	if got := strings.Join(r.rec.Lines(), "|"); got != "interface "+gi1+"|speed 100|duplex full|end|interface "+gi1+"|no duplex|speed 10|end" {
		t.Fatalf("el equipo recibió %s", got)
	}
}

func TestPlanSnippetTemplatePortSecurityAppliesAndAuditsValues(t *testing.T) {
	r := newRig(t, simulator.Config{})
	res, err := r.snippet(tplReq("port-security", map[string]string{"interfaces": gi1, "maximum": "3", "violation": "restrict"}))
	if err != nil {
		t.Fatal(err)
	}
	run := r.runToState(res.PlanId, "done")
	r.waitDone(run)
	if got := strings.Join(r.rec.Lines(), "|"); got != "interface "+gi1+"|switchport port-security maximum 3|switchport port-security violation restrict|switchport port-security|end" {
		t.Fatalf("el equipo recibió %s", got)
	}
	if a := r.d.AuditText(); !strings.Contains(a, "plantilla=port-security") || !strings.Contains(a, "maximum=3") {
		t.Fatalf("la auditoría no dice qué plantilla ni con qué valores: %s", a)
	}
	// Con port-security ya puesto, el siguiente plan lo rechaza: la reversa no restauraría lo aprendido.
	if _, err := r.snippet(tplReq("port-security", map[string]string{"interfaces": gi1})); code(err) != codes.FailedPrecondition {
		t.Fatalf("segundo plan: %v", err)
	}
}

func TestPlanSnippetTemplateErrdisableOnRunningModel(t *testing.T) {
	const running = "hostname SW1\nerrdisable recovery cause udld\nerrdisable recovery interval 900\n!\ninterface GigabitEthernet1/0/1\n shutdown\n!\nend\n"
	r := newRig(t, simulator.Config{Running: running, ConfigErrors: map[string]string{"errdisable recovery interval 120": "% Invalid input detected at '^' marker."}})
	res, err := r.snippet(tplReq("errdisable-recovery", map[string]string{"cause_bpduguard": "true", "cause_udld": "true", "interval": "120"}))
	if err != nil {
		t.Fatal(err)
	}
	dp := res.Plan.Devices[0]
	if !reflect.DeepEqual(dp.Apply, []string{"errdisable recovery cause bpduguard", "errdisable recovery interval 120"}) ||
		!reflect.DeepEqual(dp.Rollback, []string{"errdisable recovery interval 900", "no errdisable recovery cause bpduguard"}) {
		t.Fatalf("plan = %+v", dp)
	}
	run := r.runToState(res.PlanId, "failed")
	r.rollback(run)
	if got := strings.Join(r.rec.Lines(), "|"); got != "errdisable recovery cause bpduguard|errdisable recovery interval 120|end|errdisable recovery interval 900|no errdisable recovery cause bpduguard|end" {
		t.Fatalf("el equipo recibió %s", got)
	}
}

func TestPortKeysLockTheErrdisableConfig(t *testing.T) {
	rec := &planRec{t: target{host: "10.0.0.1", port: 22}}
	rec.plan.Devices = append(rec.plan.Devices, devicePlanOf("errdisable recovery cause udld"))
	other := &planRec{t: rec.t}
	other.plan.Devices = append(other.plan.Devices, devicePlanOf("errdisable recovery interval 120"))
	a, b := portKeys(rec), portKeys(other)
	if len(a) != 1 || len(b) != 1 || !keysConflict(a[0], b[0]) {
		t.Fatalf("%v %v", a, b)
	}
}

func devicePlanOf(apply ...string) assist.DevicePlan { return assist.DevicePlan{Apply: apply} }

// El equipo debe ser de una plataforma que la plantilla soporte: si no, se rechaza antes de armar nada.
func TestPlanWithRefusesAPlatformTheTemplateDoesNotSupport(t *testing.T) {
	r := newRig(t, simulator.Config{})
	r.target.Name = "SW1"
	fn := assist.SnippetSpeedDuplex
	built := false
	build := func(string, map[string]string) (assist.DevicePlan, error) {
		built = true
		return assist.DevicePlan{}, nil
	}
	_, _, err := r.svc.planWith(context.Background(), r.target, []string{r.fp}, []string{"show version"}, nil, &fn, []string{"nxos"}, false, "x", nil, build)
	if code(err) != codes.FailedPrecondition || built || !strings.Contains(err.Error(), "nxos") {
		t.Fatalf("err=%v built=%v", err, built)
	}
	// Con la del equipo en la lista (el simulador es IOS-XE) sí sigue hasta armar el plan.
	_, _, _ = r.svc.planWith(context.Background(), r.target, []string{r.fp}, []string{"show version"}, nil, &fn, []string{"ios", "ios-xe"}, false, "x", nil, build)
	if !built {
		t.Fatal("una plataforma soportada no debe rechazarse")
	}
}

// shutdown y trap son banderas independientes: con trap ya puesto, pedir shutdown agrega la suya y la reversa quita solo esa. El motor
// verifica la reversa contra la línea base (rolled-back), así que si trap hubiera desaparecido no pasaría.
func TestPlanSnippetTemplateStormActionRollbackKeepsTheOtherFlag(t *testing.T) {
	r := newRig(t, simulator.Config{Interfaces: map[string][]string{gi1: {"switchport mode access", "storm-control action trap"}}})
	res, err := r.snippet(tplReq("storm-control", map[string]string{"interfaces": gi1, "action": "shutdown"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Plan.Devices[0].Rollback; !reflect.DeepEqual(got, []string{"interface " + gi1, "no storm-control action shutdown"}) {
		t.Fatalf("reversa = %v", got)
	}
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	if s := r.waitState(run, "waiting-confirm"); s.Pending.GetKind() != "close" {
		t.Fatalf("pendiente %+v", s.Pending)
	}
	if _, err := r.svc.Rollback(context.Background(), &v1.RollbackRequest{RunId: run}); err != nil {
		t.Fatal(err)
	}
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "rollback-1")
	r.waitState(run, "rolled-back")
	r.waitDone(run)
	if got := strings.Join(r.rec.Lines(), "|"); got != "interface "+gi1+"|storm-control action shutdown|end|interface "+gi1+"|no storm-control action shutdown|end" {
		t.Fatalf("el equipo recibió %s", got)
	}
	// El puerto quedó con trap, como estaba: un plan nuevo para trap no tiene nada que cambiar.
	if _, err := r.snippet(tplReq("storm-control", map[string]string{"interfaces": gi1, "action": "trap"})); code(err) != codes.InvalidArgument {
		t.Fatalf("trap ya estaba: %v", err)
	}
}

// ---- lote L3 y gestión (fase 28d) ----

// templateRoundTrip planea, aplica, pide la reversa y espera rolled-back: el motor verifica la reversa contra la línea base, así que si el
// equipo quedara distinto la ejecución no llegaría ahí.
func (r *rig) templateRoundTrip(id string, vals map[string]string) *v1.AssistDevicePlan {
	r.t.Helper()
	res, err := r.snippet(tplReq(id, vals))
	if err != nil {
		r.t.Fatal(err)
	}
	if n := len(r.rec.Lines()); n != 0 {
		r.t.Fatalf("planear no configura: %q", r.rec.Lines())
	}
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	if s := r.waitState(run, "waiting-confirm"); s.Pending.GetKind() != "close" {
		r.t.Fatalf("pendiente %+v", s.Pending)
	}
	if _, err := r.svc.Rollback(context.Background(), &v1.RollbackRequest{RunId: run}); err != nil {
		r.t.Fatal(err)
	}
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "rollback-1")
	r.waitState(run, "rolled-back")
	r.waitDone(run)
	return res.Plan.Devices[0]
}

func TestPlanSnippetNTPServerEndToEndRolledBack(t *testing.T) {
	r := newRig(t, simulator.Config{Running: "hostname SW1\nntp server 10.0.0.9\n!\nend\n"})
	dp := r.templateRoundTrip("ntp-server", map[string]string{"address": "10.0.0.1", "prefer": "true"})
	if !reflect.DeepEqual(dp.Apply, []string{"ntp server 10.0.0.1 prefer"}) || !reflect.DeepEqual(dp.Rollback, []string{"no ntp server 10.0.0.1"}) {
		t.Fatalf("plan = %+v", dp)
	}
	if got := strings.Join(r.rec.Lines(), "|"); got != "ntp server 10.0.0.1 prefer|end|no ntp server 10.0.0.1|end" {
		t.Fatalf("el equipo recibió %s", got)
	}
	// El mismo servidor con otras opciones: se rechaza antes de tocar nada.
	r2 := newRig(t, simulator.Config{Running: "hostname SW1\nntp server 10.0.0.1 key 3\n!\nend\n"})
	if _, err := r2.snippet(tplReq("ntp-server", map[string]string{"address": "10.0.0.1"})); code(err) != codes.FailedPrecondition {
		t.Fatalf("servidor con opciones: %v", err)
	}
}

func TestPlanSnippetSNMPCommunityEndToEndNeverLeaksTheCommunity(t *testing.T) {
	const comm = "Zx9-Secreta.Comm"
	r := newRig(t, simulator.Config{Running: "hostname SW1\nsnmp-server community otra RO\n!\nend\n"})
	res, err := r.snippet(tplReq("snmp-community", map[string]string{"community": comm}))
	if err != nil {
		t.Fatal(err)
	}
	dp := res.Plan.Devices[0]
	if text := fmt.Sprintf("%+v", res.Plan); strings.Contains(text, comm) {
		t.Fatalf("el plan que ve el cliente cita la community: %s", text)
	}
	if len(dp.Apply) != 1 || !strings.HasPrefix(dp.Apply[0], "snmp-server community <") {
		t.Fatalf("Apply = %v", dp.Apply)
	}
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	r.waitState(run, "waiting-confirm")
	if _, err := r.svc.Rollback(context.Background(), &v1.RollbackRequest{RunId: run}); err != nil {
		t.Fatal(err)
	}
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "rollback-1")
	r.waitState(run, "rolled-back")
	r.waitDone(run)
	// El equipo sí recibió la community real, y la auditoría (con cada línea enviada) no la guarda.
	if got := strings.Join(r.rec.Lines(), "|"); got != "snmp-server community "+comm+" RO|end|no snmp-server community "+comm+"|end" {
		t.Fatalf("el equipo recibió %s", got)
	}
	if a := r.d.AuditText(); strings.Contains(a, comm) || !strings.Contains(a, "plantilla=snmp-community") {
		t.Fatalf("auditoría: %s", a)
	}
	// Una community que ya existe se rechaza sin citarla.
	r2 := newRig(t, simulator.Config{Running: "hostname SW1\nsnmp-server community " + comm + " RW\n!\nend\n"})
	_, err = r2.snippet(tplReq("snmp-community", map[string]string{"community": comm}))
	if code(err) != codes.FailedPrecondition || strings.Contains(err.Error(), comm) {
		t.Fatalf("community existente: %v", err)
	}
	// El campo secreto inválido tampoco se cita.
	_, err = r2.snippet(tplReq("snmp-community", map[string]string{"community": comm + " con espacio"}))
	if code(err) != codes.InvalidArgument || strings.Contains(err.Error(), comm) {
		t.Fatalf("community inválida: %v", err)
	}
}

const vtyRunning = "hostname SW1\nline vty 0 4\n transport input ssh\n login local\n!\nline vty 5 15\n login local\n!\nend\n"

func TestPlanSnippetVtyACLEndToEndRolledBack(t *testing.T) {
	// El simulador escucha en 127.0.0.1, y esa es la IP de origen de la sesión de la app.
	r := newRig(t, simulator.Config{Running: vtyRunning, Commands: map[string]string{"show ip access-lists MGMT": "Standard IP access list MGMT\n    10 permit 127.0.0.1\n    20 deny   any\n", "show users": showUsersFrom("127.0.0.1")}})
	dp := r.templateRoundTrip("vty-acl", map[string]string{"acl": "MGMT", "lines": "0 15"})
	if !reflect.DeepEqual(dp.Apply, []string{"line vty 0 4", "access-class MGMT in", "line vty 5 15", "access-class MGMT in"}) ||
		!reflect.DeepEqual(dp.Rollback, []string{"line vty 5 15", "no access-class MGMT in", "line vty 0 4", "no access-class MGMT in"}) {
		t.Fatalf("plan = %+v", dp)
	}
	if len(dp.Notes) == 0 || !strings.Contains(dp.Notes[0], "127.0.0.1") {
		t.Fatalf("la nota debe decir la IP validada: %v", dp.Notes)
	}
	if got := strings.Join(r.rec.Lines(), "|"); got != "line vty 0 4|access-class MGMT in|line vty 5 15|access-class MGMT in|end|line vty 5 15|no access-class MGMT in|line vty 0 4|no access-class MGMT in|end" {
		t.Fatalf("el equipo recibió %s", got)
	}
}

func showUsersFrom(ip string) string {
	return "    Line       User       Host(s)              Idle       Location\n   0 con 0                idle                 00:00:00\n*  2 vty 0     admin      idle                 00:00:00 " + ip + "\n"
}

// Revisión de 28d: con NAT el equipo ve otra IP que la local de la app; la ACL que solo permite la local se rechaza.
func TestPlanSnippetVtyACLRefusesWhenTheDeviceSeesAnotherIP(t *testing.T) {
	r := newRig(t, simulator.Config{Running: vtyRunning, Commands: map[string]string{
		"show ip access-lists MGMT": "Standard IP access list MGMT\n    10 permit 127.0.0.1\n",
		"show users":                showUsersFrom("203.0.113.9")}})
	_, err := r.snippet(tplReq("vty-acl", map[string]string{"acl": "MGMT", "lines": "0 4"}))
	if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "203.0.113.9") || len(r.rec.Lines()) != 0 {
		t.Fatalf("%v %q", err, r.rec.Lines())
	}
}

func TestPlanSnippetLoggingHostEndToEndReversaIsTheFactoryLevel(t *testing.T) {
	r := newRig(t, simulator.Config{Running: "hostname SW1\nlogging host 10.0.0.9\n!\nend\n"})
	dp := r.templateRoundTrip("logging-host", map[string]string{"address": "10.0.0.1", "level": "warnings"})
	if !reflect.DeepEqual(dp.Rollback, []string{"logging trap informational", "no logging host 10.0.0.1"}) {
		t.Fatalf("plan = %+v", dp)
	}
	if got := strings.Join(r.rec.Lines(), "|"); got != "logging host 10.0.0.1|logging trap warnings|end|logging trap informational|no logging host 10.0.0.1|end" {
		t.Fatalf("el equipo recibió %s", got)
	}
}

// Fase 28g: el destino con puerto alto (receptor de la app) pasa por el simulador con su forma completa y su `no` completo.
func TestPlanSnippetLoggingHostWithPortEndToEnd(t *testing.T) {
	r := newRig(t, simulator.Config{Running: "hostname SW1\nlogging host 10.0.0.9\n!\nend\n"})
	dp := r.templateRoundTrip("logging-host", map[string]string{"address": "10.0.0.1", "port": "5514"})
	if !reflect.DeepEqual(dp.Rollback, []string{"no logging host 10.0.0.1 transport udp port 5514"}) {
		t.Fatalf("plan = %+v", dp)
	}
	if got := strings.Join(r.rec.Lines(), "|"); got != "logging host 10.0.0.1 transport udp port 5514|end|no logging host 10.0.0.1 transport udp port 5514|end" {
		t.Fatalf("el equipo recibió %s", got)
	}
}

func TestPlanSnippetVtyACLRefusesAnACLThatLocksTheSessionOut(t *testing.T) {
	for name, acl := range map[string]string{
		"no menciona la IP de origen": "Standard IP access list MGMT\n    10 permit 10.9.9.9\n",
		"la niega":                    "Standard IP access list MGMT\n    10 deny   127.0.0.1\n    20 permit any\n",
		"no existe":                   "",
	} {
		r := newRig(t, simulator.Config{Running: vtyRunning, Commands: map[string]string{"show ip access-lists MGMT": acl, "show users": showUsersFrom("127.0.0.1")}})
		_, err := r.snippet(tplReq("vty-acl", map[string]string{"acl": "MGMT", "lines": "0 4"}))
		if code(err) != codes.FailedPrecondition {
			t.Errorf("%s: %v", name, err)
		}
		if len(r.rec.Lines()) != 0 {
			t.Errorf("%s: se configuró algo: %q", name, r.rec.Lines())
		}
	}
}

func TestPortKeysLockEachGlobalFamily(t *testing.T) {
	plan := func(apply ...string) *planRec {
		rec := &planRec{t: target{host: "10.0.0.1", port: 22}}
		rec.plan.Devices = append(rec.plan.Devices, devicePlanOf(apply...))
		return rec
	}
	for _, c := range [][]string{{"ntp server 10.0.0.1", "ntp server 10.0.0.2 prefer"}, {"ip route 10.1.0.0 255.255.0.0 10.0.0.1", "ip route 10.2.0.0 255.255.0.0 10.0.0.1"},
		{"logging host 10.0.0.1", "logging trap warnings"}, {"snmp-server community a RO", "snmp-server group G v3 priv"}, {"banner motd #a#", "banner motd #b#"},
		{"line vty 0 4", "line vty 5 15"}} {
		a, b := portKeys(plan(c[0])), portKeys(plan(c[1]))
		if len(a) != 1 || len(b) != 1 || !keysConflict(a[0], b[0]) {
			t.Errorf("%v: %v %v", c, a, b)
		}
	}
	if a, b := portKeys(plan("ntp server 10.0.0.1")), portKeys(plan("logging host 10.0.0.1")); keysConflict(a[0], b[0]) {
		t.Errorf("NTP y syslog no deben estorbarse: %v %v", a, b)
	}
}
