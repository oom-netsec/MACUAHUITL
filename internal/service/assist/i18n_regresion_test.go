package assist

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/backup"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// Fase 30c, bloque B: el texto en es de cada RPC tocado (notas, negativas, errores y motivo de fallo) es el de siempre, byte por byte.
// El golden se generó con el código de antes del cambio (GOLDEN_UPDATE=1 solo para regenerarlo a propósito).
const goldenFile = "testdata/regresion_es.json"

func msg(err error) string { return status.Convert(err).Message() }

func ctxIn(loc string) context.Context {
	if loc == "" {
		return context.Background()
	}
	return i18n.WithLocale(context.Background(), loc)
}

const vtyRunning30c = "hostname SW1\nline vty 0 4\n transport input ssh\n login local\n!\nline vty 5 15\n login local\n!\nend\n"

const gi2 = "GigabitEthernet1/0/2"

// planSnippet pide el plan de una plantilla y devuelve sus avisos (o el error) como texto.
func planSnippet(ctx context.Context, r *rig, req *v1.PlanSnippetRequest) string {
	req.Target, req.AcceptedHostKeyFingerprints = r.target, []string{r.fp}
	res, err := r.svc.PlanSnippet(ctx, req)
	if err != nil {
		return "ERR " + msg(err)
	}
	return strings.Join(res.Plan.Devices[0].Notes, "\n")
}

func planPorts(ctx context.Context, r *rig, req *v1.PlanPortsRequest) string {
	req.Target, req.AcceptedHostKeyFingerprints = r.target, []string{r.fp}
	if len(req.Interfaces) == 0 {
		req.Interfaces = []string{gi1}
	}
	res, err := r.svc.PlanPorts(ctx, req)
	if err != nil {
		return "ERR " + msg(err)
	}
	return strings.Join(res.Plan.Devices[0].Notes, "\n")
}

// escenarios corre cada RPC en el idioma loc ("" = sin idioma) y devuelve nombre -> texto. Cada escenario prueba lo que dice su nombre.
func escenarios(t *testing.T, loc string) map[string]string {
	out := map[string]string{}
	ctx := ctxIn(loc)
	two := map[string][]string{gi1: {"description Impresora", "switchport access vlan 10", "switchport mode access", "shutdown"}, gi2: {"switchport mode dynamic desirable"}}

	// Avisos de los planes.
	r := newRig(t, simulator.Config{})
	out["nota speed-duplex"] = planSnippet(ctx, r, tplReq("speed-duplex", map[string]string{"interfaces": gi1, "speed": "100"}))
	out["nota port-security"] = planSnippet(ctx, r, tplReq("port-security", map[string]string{"interfaces": gi1}))
	out["nota modo-puerto"] = planSnippet(ctx, r, tplReq("modo-puerto", map[string]string{"interfaces": gi1, "mode": "dynamic auto"}))
	r2 := newRig(t, simulator.Config{Interfaces: two})
	out["nota modo-puerto ya estaba"] = planSnippet(ctx, r2, tplReq("modo-puerto", map[string]string{"interfaces": gi1 + "," + gi2, "mode": "access"}))
	// Errores de armado y de uso.
	out["snippet vacío"] = planSnippet(ctx, r, &v1.PlanSnippetRequest{})
	out["plantilla desconocida"] = planSnippet(ctx, r, tplReq("no-existe", nil))
	out["svi dirección inválida"] = planSnippet(ctx, r, sviReq(40, nil, "10.0.0.1/24"))
	out["ports sin interfaces"] = planPorts(ctx, r, &v1.PlanPortsRequest{Vlan: 20, Interfaces: []string{"Port-channel1"}})
	out["ports nada que cambiar"] = planPorts(ctx, r, &v1.PlanPortsRequest{})
	out["ports vlan inexistente"] = planPorts(ctx, r, &v1.PlanPortsRequest{Vlan: 999})
	out["ports descripción no ASCII"] = planPorts(ctx, r, &v1.PlanPortsRequest{Description: ptr("Teléfono")})
	rv := newRig(t, simulator.Config{Vlans: []int{1, 10}, Commands: map[string]string{"show vtp status": "VTP Domain Name : CAMPUS\nVTP Operating Mode : Transparent\n"}})
	out["vlan ya existe"] = planSnippet(ctx, rv, vlanReq(10, "VLAN0010"))
	// Negativas por el estado del equipo.
	rt := newRig(t, simulator.Config{Interfaces: map[string][]string{gi1: {"switchport mode trunk"}}})
	out["negativa port-security trunk"] = planSnippet(ctx, rt, tplReq("port-security", map[string]string{"interfaces": gi1}))
	out["negativa ports trunk"] = planPorts(ctx, rt, &v1.PlanPortsRequest{Vlan: 20})
	rg := newRig(t, simulator.Config{Interfaces: map[string][]string{gi1: {"description Impresora", "switchport access vlan dynamic", "switchport mode access"}}})
	out["negativa ports vlan dinámica"] = planPorts(ctx, rg, &v1.PlanPortsRequest{Vlan: 20})
	rs := newRig(t, simulator.Config{Vlans: []int{1, 10}, Commands: map[string]string{"show vtp status": "VTP Domain Name : CAMPUS\nVTP Operating Mode : Server\n"}})
	out["negativa vlan vtp"] = planSnippet(ctx, rs, vlanReq(30, "x"))
	ri := newRig(t, simulator.Config{
		Interfaces: map[string][]string{"Vlan99": {"ip address 10.1.1.1 255.255.255.0"}},
		Commands:   map[string]string{"show ip interface brief": briefHdr + "Vlan99                 10.1.1.1        YES manual up                    up\n"}})
	out["negativa svi con ip"] = planSnippet(ctx, ri, sviReq(99, nil, "10.9.9.1"))

	// vty-acl: nota con una y con dos IP, y el selector de la frase de la IP en las tres negativas que la citan.
	acl := func(entries string) map[string]string {
		return map[string]string{"show ip access-lists MGMT": "Standard IP access list MGMT\n" + entries + "    90 deny   any\n"}
	}
	vty := func(users string, aclText string) *rig {
		c := map[string]string{"show users": showUsersFrom(users)}
		for k, v := range acl(aclText) {
			c[k] = v
		}
		return newRig(t, simulator.Config{Running: vtyRunning30c, Commands: c})
	}
	vq := func() *v1.PlanSnippetRequest {
		return tplReq("vty-acl", map[string]string{"acl": "MGMT", "lines": "0 15"})
	}
	out["nota vty-acl una IP"] = planSnippet(ctx, vty("127.0.0.1", "    10 permit 127.0.0.1\n"), vq())
	out["nota vty-acl dos IP"] = planSnippet(ctx, vty("203.0.113.9", "    10 permit 203.0.113.9\n    20 permit 127.0.0.1\n"), vq())
	out["negativa vty-acl IP del equipo"] = planSnippet(ctx, vty("127.0.0.1", "    10 permit 10.9.9.9\n"), vq())
	out["negativa vty-acl IP local"] = planSnippet(ctx, vty("203.0.113.9", "    10 permit 203.0.113.9\n"), vq())
	out["negativa vty-acl IPv6"] = planSnippet(ctx, vty("2001:db8::1", "    10 permit 127.0.0.1\n"), vq())
	rr := newRig(t, simulator.Config{Commands: map[string]string{"show users": showUsersFrom("203.0.113.9"), "show running-config | include ^ip route": "ip route 10.5.0.0 255.255.0.0 10.0.0.9\n"}})
	out["negativa ruta que cubre la IP del equipo"] = planSnippet(ctx, rr, tplReq("ruta-estatica", map[string]string{"network": "203.0.113.0", "mask": "255.255.255.0", "next_hop": "10.0.0.2"}))
	out["negativa ruta que cubre la IP local"] = planSnippet(ctx, rr, tplReq("ruta-estatica", map[string]string{"network": "126.0.0.0", "mask": "254.0.0.0", "next_hop": "10.0.0.2"}))

	// Rotación de credenciales.
	ro := newRotRig(t, simulator.Config{})
	rot := func(req *v1.PlanCredRotateRequest) string {
		req.Target, req.AcceptedHostKeyFingerprints = ro.target, []string{ro.fp}
		_, err := ro.svc.PlanCredRotate(ctx, req)
		return "ERR " + strings.ReplaceAll(msg(err), ro.target.CredentialId, "<id>") // el id de la credencial es aleatorio
	}
	out["rotar usuario de la sesión"] = rot(&v1.PlanCredRotateRequest{User: "admin", NewSecret: newSec})
	out["rotar usuario inexistente"] = rot(&v1.PlanCredRotateRequest{User: "nadie", NewSecret: newSec})
	out["rotar secreto corto"] = rot(&v1.PlanCredRotateRequest{User: "tech", NewSecret: "corto"})
	out["rotar sin secreto"] = rot(&v1.PlanCredRotateRequest{User: "tech"})
	out["rotar usuario inválido"] = rot(&v1.PlanCredRotateRequest{User: "te ch", NewSecret: newSec})
	out["rotar credencial de otro usuario"] = rot(&v1.PlanCredRotateRequest{User: "tech", NewSecret: newSec, UpdateCredentialId: ro.target.CredentialId})

	// Restauración desde un respaldo.
	rb := newRestoreRig(t, restoreRunning, nil)
	rest := func(id string, mod func(*v1.PlanRestoreRequest)) string {
		req := &v1.PlanRestoreRequest{Target: rb.target, BackupId: id, AcceptedHostKeyFingerprints: []string{rb.fp}}
		if mod != nil {
			mod(req)
		}
		res, err := rb.svc.PlanRestore(ctx, req)
		if err != nil {
			return "ERR " + msg(err)
		}
		return "reason=" + res.Reason
	}
	masked := rb.saveBackup(strings.Replace(restoreBackup, "ntp server 10.0.0.2", "ntp server 10.0.0.2\nsnmp-server community <MASKED:snmp-community> RO", 1), true)
	out["restaurar enmascarado"] = rest(masked, nil)
	out["restaurar tope de líneas"] = rest(masked, func(q *v1.PlanRestoreRequest) { q.MaxLines = 99999 })
	out["restaurar de otro equipo"] = rest(rb.saveBackup(strings.Replace(restoreBackup, "hostname SW1", "hostname SW2", 1), false), nil)
	out["restaurar otra serie"] = rest(rb.saveBackupWith(restoreBackup, false, true, func(e *backup.Entry) { e.Serial = "FOC9999Z9ZZ" }), nil)
	out["restaurar sin end"] = rest(rb.saveBackup(strings.TrimSuffix(restoreBackup, "end\n"), false), nil)
	out["restaurar recortado"] = rest(rb.saveBackupWith(restoreBackup, false, true, func(e *backup.Entry) { e.Truncated = true }), nil)
	out["restaurar con lo rechazado"] = rest(rb.saveBackup(strings.Replace(restoreBackup, "!\nntp server", "!\nvtp mode client\nntp server", 1), false), nil)
	out["restaurar inexistente"] = rest("SW1_127.0.0.1/20200101T000000Z-running", nil)

	// Errores del servicio y de la máquina de estados.
	re := newRig(t, simulator.Config{})
	_, err := re.svc.Confirm(ctx, &v1.ConfirmRequest{RunId: "nope", StepId: "apply-1"})
	out["confirm sin ejecución"] = "ERR " + msg(err)
	_, err = re.svc.StartRun(ctx, &v1.StartRunRequest{PlanId: "x"})
	out["start sin assisted"] = "ERR " + msg(err)
	_, err = re.svc.StartRun(ctx, &v1.StartRunRequest{PlanId: "x", Assisted: true})
	out["start sin plan"] = "ERR " + msg(err)
	pl, _ := re.plan(&v1.PlanPortsRequest{Vlan: 20})
	run := re.start(pl.PlanId)
	re.waitState(run, "waiting-confirm")
	_, err = re.svc.Confirm(ctx, &v1.ConfirmRequest{RunId: run, StepId: "apply-9"})
	out["confirm paso equivocado"] = "ERR " + msg(err)
	_, err = re.svc.Rollback(ctx, &v1.RollbackRequest{RunId: run})
	out["rollback sin cambios"] = "ERR " + msg(err)
	re.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
	re.waitDone(run)

	// Motivo de la parada y su evento: el equipo rechaza una línea; el post-check no se cumple.
	fail := func(name string, c simulator.Config, plan func(rf *rig) (*v1.PlanSnippetResponse, error)) {
		rf := newRig(t, c)
		first, err := plan(rf)
		if err != nil {
			out[name] = "ERR " + msg(err)
			return
		}
		run := rf.start(first.PlanId)
		rf.waitState(run, "waiting-confirm")
		rf.confirm(run, "apply-1")
		rf.waitState(run, "failed")
		got, _ := rf.svc.GetAssistRun(ctx, &v1.GetAssistRunRequest{RunId: run})
		out[name] = got.Run.FailReason
		rf.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
		rf.waitDone(run) // con la ejecución terminada WatchRun entrega lo emitido y cierra
		st := &stream{ctx: ctx}
		_ = rf.svc.WatchRun(&v1.WatchRunRequest{RunId: run}, st)
		for _, e := range st.events {
			if e.Kind == "fail" {
				out[name+" (evento)"] = e.Text
			}
		}
	}
	fail("fallo de configuración", simulator.Config{ConfigErrors: map[string]string{"description Telefono": "% Invalid input detected at '^' marker."}},
		func(rf *rig) (*v1.PlanSnippetResponse, error) {
			p, err := rf.plan(&v1.PlanPortsRequest{Vlan: 20, Description: ptr("Telefono"), Shutdown: ptr(false)})
			if err != nil {
				return nil, err
			}
			return &v1.PlanSnippetResponse{PlanId: p.PlanId}, nil
		})
	// La lectura de Post es una salida fija: lo aplicado no aparece y el post-check falla.
	fail("fallo de post-check", simulator.Config{Commands: map[string]string{"show running-config | include ^ntp": "ntp clock-period 17180000\n"}},
		func(rf *rig) (*v1.PlanSnippetResponse, error) {
			req := tplReq("ntp-server", map[string]string{"address": "10.0.0.1"})
			req.Target, req.AcceptedHostKeyFingerprints = rf.target, []string{rf.fp}
			return rf.svc.PlanSnippet(context.Background(), req)
		})
	return out
}

func TestRegresionEsByteAByte(t *testing.T) {
	got := escenarios(t, "es")
	if os.Getenv("GOLDEN_UPDATE") == "1" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenFile, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s:\n  hoy:   %q\n  antes: %q", k, got[k], w)
		}
	}
}

// Con es-MX la respuesta es la misma que con es.
func TestRegresionEsExplicito(t *testing.T) {
	a, b := escenarios(t, "es"), escenarios(t, "es-MX")
	for k := range a {
		if a[k] != b[k] {
			t.Errorf("%s: %q != %q", k, a[k], b[k])
		}
	}
}

var enSinEspanolRe = regexp.MustCompile(`[áéíóúñ¿¡«»]`)

var valores = regexp.MustCompile(`"[^"]*"`)

var espanol = regexp.MustCompile(`[áéíóúñ¿¡«»]|\b(el equipo|la VLAN|no se pudo|nada que cambiar|la reversa|ya existe|puerto|solo se)\b`)

// Con en no queda español en lo que el núcleo escribe (los datos del equipo sí pueden venir como son).
func TestEnSinEspanol(t *testing.T) {
	es, en := escenarios(t, "es"), escenarios(t, "en")
	names := make([]string, 0, len(en))
	for k := range en {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if k == "restaurar inexistente" { // el error es del paquete de respaldos, fuera de este bloque
			continue
		}
		if espanol.MatchString(valores.ReplaceAllString(en[k], `""`)) { // lo citado entre comillas es un dato del usuario
			t.Errorf("%s: queda español en en: %q", k, en[k])
		}
		if en[k] == es[k] && !strings.HasPrefix(k, "fallo de configuración") {
			t.Errorf("%s: en no se tradujo: %q", k, en[k])
		}
	}
}

// El motivo de la parada y su evento salen en inglés con en (la salida del equipo queda como viene).
func TestMotivoDeFalloEnEn(t *testing.T) {
	en := escenarios(t, "en")
	const want = `device SW1 rejected "description Telefono": ^ % Invalid input detected at '^' marker.`
	if en["fallo de configuración"] != want || en["fallo de configuración (evento)"] != want {
		t.Fatalf("motivo %q, evento %q", en["fallo de configuración"], en["fallo de configuración (evento)"])
	}
	if p := en["fallo de post-check"]; !strings.HasPrefix(p, "the post-check of SW1 does not meet expectations: ") || !strings.Contains(p, "should appear in") || enSinEspanolRe.MatchString(p) {
		t.Fatalf("post-check en: %q", p)
	}
}

// Los avisos estructurados reproducen el texto es y la metadata del error no trae valores sensibles.
func TestNotasEstructuradas(t *testing.T) {
	r := newRig(t, simulator.Config{})
	req := tplReq("modo-puerto", map[string]string{"interfaces": gi1, "mode": "dynamic auto"})
	req.Target, req.AcceptedHostKeyFingerprints = r.target, []string{r.fp}
	res, err := r.svc.PlanSnippet(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	d := res.Plan.Devices[0]
	if len(d.NotesStructured) != len(d.Notes) || len(d.Notes) == 0 {
		t.Fatalf("%d claves y %d notas", len(d.NotesStructured), len(d.Notes))
	}
	for i, n := range d.NotesStructured {
		if got := i18n.Msg(i18n.Es, n.Key, n.Args); got != d.Notes[i] || !strings.HasPrefix(n.Key, "assist.note.") {
			t.Errorf("nota %d: %q (%s) no es %q", i, got, n.Key, d.Notes[i])
		}
	}
}

// La frase de la IP de origen ({what|…}) sale en el idioma pedido en las tres negativas que la citan y en la nota de dos IP.
func TestSelectorDeLaIPEnEn(t *testing.T) {
	en := escenarios(t, "en")
	for name, want := range map[string]string{
		"negativa vty-acl IP del equipo":           "does not permit the IP the device sees (127.0.0.1)",
		"negativa vty-acl IP local":                "does not permit the session's local IP (app side) (127.0.0.1)",
		"negativa vty-acl IPv6":                    "is the IP the device sees and",
		"negativa ruta que cubre la IP del equipo": "(the IP the device sees)",
		"negativa ruta que cubre la IP local":      "(the session's local IP (app side))",
		"nota vty-acl dos IP":                      "203.0.113.9 (the IP the device sees) and 127.0.0.1 (the session's local IP (app side))",
	} {
		if !strings.Contains(en[name], want) {
			t.Errorf("%s: falta %q en %q", name, want, en[name])
		}
	}
}

// Los errores de armado llevan un reason estable en inglés y su metadata declarada; el de la descripción lleva field.
func TestReasonsDeErroresDeArmado(t *testing.T) {
	r := newRig(t, simulator.Config{})
	for name, tc := range map[string]struct {
		req              *v1.PlanPortsRequest
		reason, key, val string
	}{
		"puerto no físico": {&v1.PlanPortsRequest{Vlan: 20, Interfaces: []string{"Port-channel1"}}, "assist.err.not_physical_port", "", ""},
		"descripción":      {&v1.PlanPortsRequest{Description: ptr("Teléfono")}, "assist.err.description_invalid", "field", "description"},
		"nada que cambiar": {&v1.PlanPortsRequest{}, "assist.err.ports_nothing_to_change", "", ""},
	} {
		tc.req.Target, tc.req.AcceptedHostKeyFingerprints = r.target, []string{r.fp}
		if len(tc.req.Interfaces) == 0 {
			tc.req.Interfaces = []string{gi1}
		}
		_, err := r.svc.PlanPorts(ctxIn("en"), tc.req)
		var ei *errdetails.ErrorInfo
		for _, d := range status.Convert(err).Details() {
			if x, ok := d.(*errdetails.ErrorInfo); ok {
				ei = x
			}
		}
		if ei == nil || ei.Reason != tc.reason {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if tc.key != "" && ei.Metadata[tc.key] != tc.val {
			t.Errorf("%s: metadata %v", name, ei.Metadata)
		}
		if _, leaked := ei.Metadata["why"]; leaked {
			t.Errorf("%s: la metadata no es la de assist.invalid_value: %v", name, ei.Metadata)
		}
	}
}
