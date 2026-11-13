package core

import (
	"encoding/json"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

var (
	portRe   = regexp.MustCompile(`<ip>:\d+`)
	volatile = regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]+|\b[0-9a-f]{16}\b|127\.0\.0\.1:\d+|\[::1\]:\d+|\bport \d+\b`)
)

// patrolCasos recorre los RPC de Patrol que devuelven texto (errores, Login Test, eventos) con el idioma lang.
func patrolCasos(t *testing.T, lang string) map[string]string {
	t.Helper()
	out := map[string]string{}
	norm := func(h *harness, s string) string {
		s = strings.ReplaceAll(s, filepath.Dir(h.out), "<root>")
		s = strings.ReplaceAll(s, h.target.Address, "<ip>")
		return portRe.ReplaceAllString(volatile.ReplaceAllString(s, "<v>"), "<ip>:<p>")
	}
	h := newHarness(t, nil)
	put := func(n string, err error) {
		if err != nil {
			out[n] = norm(h, "ERROR: "+err.Error())
		} else {
			out[n] = "ok"
		}
	}
	// Sin bóveda.
	_, err := h.patrol.CreateJob(con(t, lang), &v1.CreateJobRequest{Spec: h.spec("x")})
	put("sin_boveda", err)
	cred := h.ready(t)
	mut := map[string]func(s *v1.JobSpec){
		"tipo":         func(s *v1.JobSpec) { s.Kind = "x" },
		"sin_equipos":  func(s *v1.JobSpec) { s.Targets = nil },
		"sin_cred":     func(s *v1.JobSpec) { s.DefaultCredentialId = "" },
		"ventana_0":    func(s *v1.JobSpec) { s.WindowHours = 0 },
		"ventana_97":   func(s *v1.JobSpec) { s.WindowHours = 97 },
		"sin_comandos": func(s *v1.JobSpec) { s.CustomCommands = "" },
		"comando_malo": func(s *v1.JobSpec) { s.CustomCommands = "configure terminal\n" },
		"playbook":     func(s *v1.JobSpec) { s.PlaybookIds = []string{"no-existe"} },
		"cred_no_esta": func(s *v1.JobSpec) { s.DefaultCredentialId = "zzz" },
		"override":     func(s *v1.JobSpec) { s.Overrides = []*v1.DeviceOverride{{DeviceId: "sw1", CredentialId: "zzz"}} },
		"excluyentes":  func(s *v1.JobSpec) { s.Schedule = &v1.Schedule{IntervalSeconds: 5, Cron: "* * * * *"} },
		"cron":         func(s *v1.JobSpec) { s.Schedule = &v1.Schedule{Cron: "x"} },
		"fin_pasado": func(s *v1.JobSpec) {
			s.Schedule = &v1.Schedule{IntervalSeconds: 5, Until: timestamppb.New(time.Now().Add(-time.Hour))}
		},
		"salida_no_dir": func(s *v1.JobSpec) { s.OutputDir = filepath.Join(h.out, "no-existe-aun") },
	}
	for n, f := range mut {
		s := h.spec(cred)
		f(s)
		_, err := h.patrol.CreateJob(con(t, lang), &v1.CreateJobRequest{Spec: s})
		put("crear_"+n, err)
	}
	// Login Test: llave desconocida y puerto cerrado.
	cj, err := h.patrol.CreateJob(con(t, lang), &v1.CreateJobRequest{Spec: h.spec(cred)})
	if err != nil {
		t.Fatal(err)
	}
	login := func(n, job string) []*v1.LoginTestResponse {
		s, err := h.patrol.LoginTest(con(t, lang), &v1.LoginTestRequest{JobId: job})
		var rs []*v1.LoginTestResponse
		for err == nil {
			var r *v1.LoginTestResponse
			if r, err = s.Recv(); err == nil {
				rs = append(rs, r)
			}
		}
		if err != io.EOF {
			put(n, err)
			return nil
		}
		for i, r := range rs {
			out[fmt.Sprintf("%s_%d", n, i)] = norm(h, fmt.Sprintf("passed=%v step=%v detail=%q platform=%q", r.Passed, r.FailedStep, r.Detail, r.DetectedPlatform))
		}
		return rs
	}
	lt := login("login_llave", cj.JobId)
	bad := h.spec(cred)
	bad.Targets = []*v1.Target{{Address: "127.0.0.1", Port: 1, DeviceId: "x"}}
	cb, _ := h.patrol.CreateJob(con(t, lang), &v1.CreateJobRequest{Spec: bad})
	login("login_cerrado", cb.JobId)
	// Armar: sin aceptar la llave, y sin equipos.
	_, err = h.patrol.ArmJob(con(t, lang), &v1.ArmJobRequest{JobId: cj.JobId})
	put("armar_sin_llave", err)
	_, err = h.patrol.ArmJob(con(t, lang), &v1.ArmJobRequest{JobId: cj.JobId, ExcludedDeviceIds: []string{"sw1"}})
	put("armar_sin_equipos", err)
	// Armar bien, y volver a probar o armar un trabajo ya armado.
	if _, err = h.patrol.ArmJob(con(t, lang), &v1.ArmJobRequest{JobId: cj.JobId, AcceptedHostKeyFingerprints: []string{lt[0].HostKeyFingerprint}}); err != nil {
		t.Fatal(err)
	}
	login("login_armado", cj.JobId)
	_, err = h.patrol.ArmJob(con(t, lang), &v1.ArmJobRequest{JobId: cj.JobId})
	put("armar_armado", err)
	h.waitJob(t, cj.JobId, "closed")
	return out
}

// failingRun arma un trabajo contra un equipo que corta la sesión a media salida y devuelve el detalle del evento y de GetRun.
func failingRun(t *testing.T, lang string, reasons ...map[string]string) map[string]string {
	t.Helper()
	out := map[string]string{}
	h := newHarness(t, nil)
	cred := h.ready(t)
	addr, _ := simulator.Start(t, simulator.Config{Hostname: "SW-LAB-02", Username: "admin", Password: "MARKER-PW", Enable: "MARKER-EN", Transcripts: transcripts(), DropDuringCommand: "show running-config"})
	ap := netip.MustParseAddrPort(addr)
	h.target = &v1.Target{Address: ap.Addr().String(), Port: uint32(ap.Port()), DeviceId: "sw2"}
	cj, err := h.patrol.CreateJob(con(t, lang), &v1.CreateJobRequest{Spec: h.spec(cred)})
	if err != nil {
		t.Fatal(err)
	}
	lt := h.loginTest(t, cj.JobId)
	if _, err := h.patrol.ArmJob(con(t, lang), &v1.ArmJobRequest{JobId: cj.JobId, AcceptedHostKeyFingerprints: []string{lt[0].HostKeyFingerprint}}); err != nil {
		t.Fatal(err)
	}
	s, err := h.events.Subscribe(con(t, lang), &v1.SubscribeRequest{JobIds: []string{cj.JobId}})
	if err != nil {
		t.Fatal(err)
	}
	var details []string
	for {
		e, err := s.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if d := e.GetDeviceStateChanged(); d != nil && d.Detail != "" {
			details = append(details, d.Detail)
			if len(reasons) > 0 {
				reasons[0]["evento"] = d.Reason
			}
		}
		if e.GetJobStateChanged().GetState() == "closed" {
			break
		}
	}
	norm := func(s string) string {
		return portRe.ReplaceAllString(volatile.ReplaceAllString(strings.ReplaceAll(s, h.target.Address, "<ip>"), "<v>"), "<ip>:<p>")
	}
	b, _ := json.Marshal(details)
	out["evento"] = norm(string(b))
	run, err := h.patrol.GetRun(con(t, lang), &v1.GetRunRequest{JobId: cj.JobId, Round: 1})
	if err != nil || len(run.Devices) != 1 {
		t.Fatalf("%v %v", run, err)
	}
	out["getrun"] = norm(run.Devices[0].Detail)
	if len(reasons) > 0 {
		reasons[0]["getrun"] = run.Devices[0].Reason
		reasons[0]["auditoria"] = h.auditText(t)
	}
	return out
}

// Regresión: sin idioma, con es o con uno desconocido, los RPC de Patrol devuelven lo mismo que antes del catálogo.
func TestPatrolRegresionEs(t *testing.T) {
	base := patrolCasos(t, "")
	i18ntest.Golden(t, "testdata/patrol_es.golden.json", base)
	fb := failingRun(t, "")
	i18ntest.Golden(t, "testdata/patrol_fallo_es.golden.json", fb)
	for _, lang := range []string{"es", "fr"} {
		for k, v := range patrolCasos(t, lang) {
			if base[k] != v {
				t.Errorf("%s con %q difiere de sin idioma: %q vs %q", k, lang, v, base[k])
			}
		}
		for k, v := range failingRun(t, lang) {
			if fb[k] != v {
				t.Errorf("%s con %q difiere de sin idioma: %q vs %q", k, lang, v, fb[k])
			}
		}
	}
	_ = i18n.En
}

// bovedaCasos recorre los errores del servicio de la bóveda que llevan texto; lang fija el idioma.
func bovedaCasos(t *testing.T, lang string) map[string]string {
	t.Helper()
	out := map[string]string{}
	put := func(n string, err error) {
		out[n] = "ok"
		if err != nil {
			out[n] = "ERROR: " + err.Error()
		}
	}
	h := newHarness(t, nil)
	_, err := h.vault.ListCredentials(con(t, lang), &v1.ListCredentialsRequest{})
	put("sin_boveda", err)
	_, err = h.vault.Create(con(t, lang), &v1.CreateRequest{MasterPassword: []byte("maestra")})
	put("crear", err)
	_, err = h.vault.Create(con(t, lang), &v1.CreateRequest{MasterPassword: []byte("maestra")})
	put("crear_otra_vez", err)
	_, err = h.vault.PutCredential(con(t, lang), &v1.PutCredentialRequest{Label: "macuahuitl:x", Username: "a", Password: []byte("b")})
	put("etiqueta_reservada", err)
	return out
}

func TestBovedaRegresionEs(t *testing.T) {
	base := bovedaCasos(t, "")
	i18ntest.Golden(t, "testdata/boveda_es.golden.json", base)
	for _, lang := range []string{"es", "fr"} {
		for k, v := range bovedaCasos(t, lang) {
			if base[k] != v {
				t.Errorf("%s con %q difiere de sin idioma: %q vs %q", k, lang, v, base[k])
			}
		}
	}
}

var spanishRe = regexp.MustCompile(`[áéíóúñ¿]|\b(bóveda|equipos?|trabajo|falló|sin|hay|quedan|está|armar|debe)\b`)

// Con en, lo que traduce Patrol sale sin español; los textos de otros dominios (playbook, Ajustes) quedan fuera.
func TestPatrolEnSinEspanol(t *testing.T) {
	skip := map[string]bool{"crear_comando_malo": true, "crear_salida_no_dir": true}
	for _, set := range []map[string]string{patrolCasos(t, "en"), failingRun(t, "en"), bovedaCasos(t, "en")} {
		for k, v := range set {
			if m := spanishRe.FindString(v); m != "" && !skip[k] {
				t.Errorf("%s: queda español (%q): %s", k, m, v)
			}
		}
	}
}

// El código y los argumentos del error viajan en cualquier idioma; el texto sigue al idioma.
func TestPatrolCodigosYArgumentos(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	s := h.spec(cred)
	s.WindowHours = 0
	for lang, want := range map[string]string{"": "patrol: window_hours: debe estar entre 1 y 96, es 0", "en": "patrol: window_hours: must be between 1 and 96, it is 0"} {
		_, err := h.patrol.CreateJob(con(t, lang), &v1.CreateJobRequest{Spec: s})
		if status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != want {
			t.Errorf("%q: %v", lang, err)
		}
		if r, m := reasonOf(err); r != "patrol.field.window" || m["field"] != "window_hours" || m["n"] != "0" {
			t.Errorf("%q: reason %q metadata %v", lang, r, m)
		}
	}
	cj, _ := h.patrol.CreateJob(con(t, ""), &v1.CreateJobRequest{Spec: h.spec(cred)})
	for lang, want := range map[string]string{"": "transport: llave de host desconocida de", "en": "transport: unknown host key from"} {
		st, err := h.patrol.LoginTest(con(t, lang), &v1.LoginTestRequest{JobId: cj.JobId})
		if err != nil {
			t.Fatal(err)
		}
		r, err := st.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(r.Detail, want) || r.Reason != "transport.hostkey.unknown" || r.Args["fingerprint"] != r.HostKeyFingerprint || r.Args["host"] == "" {
			t.Errorf("%q: %+v", lang, r)
		}
		for st.RecvMsg(new(v1.LoginTestResponse)) == nil {
		}
	}
}

// El equipo que corta la sesión: el detalle del evento y de GetRun sale en el idioma pedido y trae su código.
func TestPatrolDetalleDeEquipoEnYCodigo(t *testing.T) {
	reasons := map[string]string{}
	got := failingRun(t, "en", reasons)
	if a := reasons["auditoria"]; !strings.Contains(a, `error=\"platform: the device closed the session`) || strings.Contains(a, "cerró la sesión") {
		t.Errorf("la auditoría del equipo debe ir en inglés:\n%s", a)
	}
	for _, k := range []string{"evento", "getrun"} {
		if reasons[k] != "platform.err.closed" || !strings.Contains(got[k], "platform: the device closed the session: EOF") {
			t.Errorf("%s: reason %q detalle %q", k, reasons[k], got[k])
		}
	}
}

// CreateChange valida con el idioma de la llamada: con en, el error de validación sale en inglés.
func TestCreateChangeValidaEnElIdiomaPedido(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	ch := v1.NewChangeServiceClient(h.conn)
	for lang, want := range map[string]string{"": "patrol: credential: sin credencial por defecto", "en": "patrol: credential: no default credential"} {
		_, err := ch.CreateChange(con(t, lang), &v1.CreateChangeRequest{Spec: &v1.JobSpec{Targets: []*v1.Target{h.target}}})
		if status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != want {
			t.Errorf("%q: %v", lang, err)
		}
	}
}
