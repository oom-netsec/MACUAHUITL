package assist

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
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

// escenarios corre cada RPC en el idioma loc ("" = sin idioma) y devuelve nombre -> texto.
func escenarios(t *testing.T, loc string) map[string]string {
	out := map[string]string{}
	ctx := ctxIn(loc)

	// Notas de los planes.
	r := newRig(t, simulator.Config{})
	plan := func(name string, req *v1.PlanSnippetRequest) {
		req.Target, req.AcceptedHostKeyFingerprints = r.target, []string{r.fp}
		res, err := r.svc.PlanSnippet(ctx, req)
		if err != nil {
			out[name] = "ERR " + msg(err)
			return
		}
		out[name] = strings.Join(res.Plan.Devices[0].Notes, "\n")
		for i, n := range res.Plan.Devices[0].GetNotesStructured() {
			out[name+"/key"+string(rune('0'+i))] = n.Key
		}
	}
	plan("nota speed-duplex", tplReq("speed-duplex", map[string]string{"interfaces": gi1, "speed": "100"}))
	plan("nota port-security", tplReq("port-security", map[string]string{"interfaces": gi1}))
	plan("nota modo-puerto", tplReq("modo-puerto", map[string]string{"interfaces": gi1, "mode": "dynamic auto"}))
	plan("nota modo-puerto igual", tplReq("modo-puerto", map[string]string{"interfaces": gi1, "mode": "access"}))
	// Negativas y errores de armado.
	plan("snippet vacío", &v1.PlanSnippetRequest{})
	plan("plantilla desconocida", tplReq("no-existe", nil))
	plan("vlan ya existe", vlanReq(10, ""))
	plan("svi sin vlan", sviReq(40, nil, "10.0.0.1/24"))
	pp := func(name string, req *v1.PlanPortsRequest) {
		req.Target, req.AcceptedHostKeyFingerprints = r.target, []string{r.fp}
		_, err := r.svc.PlanPorts(ctx, req)
		out[name] = "ERR " + msg(err)
	}
	pp("ports sin interfaces válidas", &v1.PlanPortsRequest{Vlan: 20, Interfaces: []string{"Port-channel1"}})
	pp("ports vlan inexistente", &v1.PlanPortsRequest{Vlan: 999})
	pp("ports nada que cambiar", &v1.PlanPortsRequest{})

	rt := newRig(t, simulator.Config{Interfaces: map[string][]string{gi1: {"switchport mode trunk"}}})
	req := tplReq("port-security", map[string]string{"interfaces": gi1})
	req.Target, req.AcceptedHostKeyFingerprints = rt.target, []string{rt.fp}
	_, err := rt.svc.PlanSnippet(ctx, req)
	out["negativa port-security trunk"] = "ERR " + msg(err)
	_, err = rt.svc.PlanPorts(ctx, &v1.PlanPortsRequest{Target: rt.target, AcceptedHostKeyFingerprints: []string{rt.fp}, Vlan: 20})
	out["negativa ports trunk"] = "ERR " + msg(err)

	rv := newRig(t, simulator.Config{Vlans: []int{1, 10}, Commands: map[string]string{"show vtp status": "VTP Domain Name : CAMPUS\nVTP Operating Mode : Server\n"}})
	vr := vlanReq(30, "x")
	vr.Target, vr.AcceptedHostKeyFingerprints = rv.target, []string{rv.fp}
	_, err = rv.svc.PlanSnippet(ctx, vr)
	out["negativa vlan vtp"] = "ERR " + msg(err)

	// vty-acl: nota con las IP validadas y negativa cuando el equipo ve otra IP.
	rb := newRig(t, simulator.Config{Running: vtyRunning30c, Commands: map[string]string{"show ip access-lists MGMT": "Standard IP access list MGMT\n    10 permit 127.0.0.1\n    20 deny   any\n", "show users": showUsersFrom("127.0.0.1")}})
	vq := tplReq("vty-acl", map[string]string{"acl": "MGMT", "lines": "0 15"})
	vq.Target, vq.AcceptedHostKeyFingerprints = rb.target, []string{rb.fp}
	res, err := rb.svc.PlanSnippet(ctx, vq)
	if err != nil {
		out["nota vty-acl"] = "ERR " + msg(err)
	} else {
		out["nota vty-acl"] = strings.Join(res.Plan.Devices[0].Notes, "\n")
	}
	rd := newRig(t, simulator.Config{Running: vtyRunning30c, Commands: map[string]string{"show ip access-lists MGMT": "Standard IP access list MGMT\n    10 permit 10.9.9.9\n    20 deny   any\n", "show users": showUsersFrom("127.0.0.1")}})
	vq.Target, vq.AcceptedHostKeyFingerprints = rd.target, []string{rd.fp}
	_, err = rd.svc.PlanSnippet(ctx, vq)
	out["negativa vty-acl"] = "ERR " + msg(err)

	// Errores del servicio y de la máquina de estados.
	re := newRig(t, simulator.Config{})
	_, err = re.svc.Confirm(ctx, &v1.ConfirmRequest{RunId: "nope", StepId: "apply-1"})
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

	// Motivo de la parada: el equipo rechaza una línea.
	rf := newRig(t, simulator.Config{ConfigErrors: map[string]string{"description Telefono": "% Invalid input detected at '^' marker."}})
	first, _ := rf.plan(&v1.PlanPortsRequest{Vlan: 20, Description: ptr("Telefono"), Shutdown: ptr(false)})
	run = rf.start(first.PlanId)
	rf.waitState(run, "waiting-confirm")
	rf.confirm(run, "apply-1")
	rf.waitState(run, "failed")
	got, _ := rf.svc.GetAssistRun(ctx, &v1.GetAssistRunRequest{RunId: run})
	out["fallo de configuración"] = got.Run.FailReason
	rf.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
	rf.waitDone(run) // con la ejecución terminada WatchRun entrega lo emitido y cierra
	st := &stream{ctx: ctx}
	_ = rf.svc.WatchRun(&v1.WatchRunRequest{RunId: run}, st)
	for _, e := range st.events {
		if e.Kind == "fail" {
			out["evento fail"] = e.Text
		}
	}
	return out
}

func TestRegresionEsByteAByte(t *testing.T) {
	got := escenarios(t, "")
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
		if strings.HasSuffix(k, "/key0") || strings.Contains(k, "/key") {
			continue // los campos nuevos no existen en el golden
		}
		if got[k] != w {
			t.Errorf("%s:\n  hoy:   %q\n  antes: %q", k, got[k], w)
		}
	}
}

// Con es explícito (o con un idioma desconocido) la respuesta es la misma que sin idioma.
func TestRegresionEsExplicito(t *testing.T) {
	a, b := escenarios(t, ""), escenarios(t, "es-MX")
	for k := range a {
		if a[k] != b[k] {
			t.Errorf("%s: %q != %q", k, a[k], b[k])
		}
	}
}

var espanol = regexp.MustCompile(`[áéíóúñ¿¡«»]|\b(el equipo|la VLAN|no se pudo|nada que cambiar|la reversa|ya existe|puerto|solo se)\b`)

// Con en no queda español en lo que el núcleo escribe (los datos del equipo sí pueden venir como son).
func TestEnSinEspanol(t *testing.T) {
	es, en := escenarios(t, ""), escenarios(t, "en")
	names := make([]string, 0, len(en))
	for k := range en {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if strings.Contains(k, "/key") {
			continue
		}
		if espanol.MatchString(en[k]) {
			t.Errorf("%s: queda español en en: %q", k, en[k])
		}
		if en[k] == es[k] && !strings.HasPrefix(k, "fallo de configuración") && k != "evento fail" {
			t.Errorf("%s: en no se tradujo: %q", k, en[k])
		}
	}
}

// El motivo de la parada y su evento salen en inglés con en (la salida del equipo queda como viene).
func TestMotivoDeFalloEnEn(t *testing.T) {
	en := escenarios(t, "en")
	const want = `device SW1 rejected "description Telefono": ^ % Invalid input detected at '^' marker.`
	if en["fallo de configuración"] != want || en["evento fail"] != want {
		t.Fatalf("motivo %q, evento %q", en["fallo de configuración"], en["evento fail"])
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
