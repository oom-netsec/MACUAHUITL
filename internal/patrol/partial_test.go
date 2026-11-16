package patrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"errors"

	"github.com/oom-netsec/MACUAHUITL/internal/mask"
	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/platform/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// cutState es lo que comparten los drivers de una prueba: qué comandos se cortan (una vez cada uno), qué corrió y
// cuántas sesiones se abrieron y se cerraron.
type cutState struct {
	mu            sync.Mutex
	cut           map[string]error // comando -> error que devuelve la primera vez que corre
	ran           []string
	opened, close int
	failOpenFrom  int      // desde esta sesión (1 = la primera), Open falla
	onCut         func()   // se llama al cortar un comando
	hostFrom2     string   // desde la segunda sesión el prompt dice este nombre (el mismo equipo con otro prompt, p. ej. prompt hostname state)
	serialsFrom2  []string // desde la segunda sesión el driver dice estas series (otro equipo tras la misma IP)
}

type cutDrv struct {
	platform.Driver
	st *cutState
	n  int // número de sesión de este driver (1 = la primera)
}

func newCut(t *testing.T, e *env, cut map[string]error) *cutState {
	t.Helper()
	st := &cutState{cut: cut}
	e.d.NewDriver = func() platform.Driver {
		st.mu.Lock()
		defer st.mu.Unlock()
		st.opened++
		return &cutDrv{Driver: iosxe.New(), st: st, n: st.opened}
	}
	return st
}

func (p *cutDrv) Open(ctx context.Context, r io.Reader, w io.Writer, en *secret.Secret) error {
	p.st.mu.Lock()
	fail := p.st.failOpenFrom > 0 && p.st.opened >= p.st.failOpenFrom
	p.st.mu.Unlock()
	if fail {
		en.Destroy()
		return platform.ErrEnableFailed
	}
	return p.Driver.Open(ctx, r, w, en)
}

func (p *cutDrv) Hostname() string {
	p.st.mu.Lock()
	defer p.st.mu.Unlock()
	if p.n >= 2 && p.st.hostFrom2 != "" {
		return p.st.hostFrom2
	}
	return p.Driver.Hostname()
}

func (p *cutDrv) Serials() []string {
	p.st.mu.Lock()
	defer p.st.mu.Unlock()
	if p.n >= 2 && p.st.serialsFrom2 != nil {
		return p.st.serialsFrom2
	}
	return p.Driver.(interface{ Serials() []string }).Serials()
}

func (p *cutDrv) Close() {
	p.st.mu.Lock()
	p.st.close++
	p.st.mu.Unlock()
	p.Driver.Close()
}

func (p *cutDrv) Run(ctx context.Context, cmd string, timeout time.Duration) (platform.Output, error) {
	p.st.mu.Lock()
	p.st.ran = append(p.st.ran, cmd)
	err, cut := p.st.cut[cmd]
	delete(p.st.cut, cmd)
	hook := p.st.onCut
	p.st.mu.Unlock()
	if cut {
		if hook != nil {
			hook()
		}
		return platform.Output{Command: cmd, Text: "parcial\n", Started: time.Now()}, err
	}
	return p.Driver.Run(ctx, cmd, timeout)
}

func (s *cutState) count(cmd string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.ran {
		if c == cmd {
			n++
		}
	}
	return n
}

func runPartial(t *testing.T, e *env, ctx context.Context) (DeviceResult, *Writer) {
	t.Helper()
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	return RunDevice(ctx, e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {}), w
}

func evidence(w *Writer) string {
	var all string
	for _, f := range w.Files() {
		b, _ := os.ReadFile(filepath.Join(w.Dir(), f))
		all += string(b)
	}
	return all
}

func TestComandoCortadoDejaElEquipoParcial(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	var states []string
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(p Progress) { states = append(states, p.State) })
	if res.State != "partial" || res.Reconnects != 1 || !slices.Equal(res.CutCommands, []string{"show running-config"}) {
		t.Fatalf("res = %+v", res)
	}
	var c interface{ Reason() string }
	if !errors.As(res.DetailErr, &c) || c.Reason() != "patrol.dev.partial" || res.Detail != "1 comando cortado y 1 reconexión; el primero: show running-config" {
		t.Fatalf("detalle = %q %v", res.Detail, res.DetailErr)
	}
	if st.count("show running-config") != 1 || st.count("show ip interface brief") != 1 {
		t.Fatalf("corrida: %v", st.ran)
	}
	if st.opened != 2 || st.close != 2 {
		t.Fatalf("sesiones abiertas=%d cerradas=%d", st.opened, st.close)
	}
	if !strings.Contains(evidence(w), "show running-config · incomplete =====") {
		t.Fatal("el cortado no quedó marcado incompleto")
	}
	if n := slices.Index(states, "connecting"); n < 0 || slices.Index(states[n+1:], "connecting") < 0 {
		t.Fatalf("falta el connecting de la reconexión: %v", states)
	}
	var buf bytes.Buffer
	e.d.Audit.Export(context.Background(), &buf, time.Time{}, time.Now().Add(time.Hour))
	out := buf.String()
	if !strings.Contains(out, "device.reconnect") || !strings.Contains(out, `command=\"show running-config\"`) || !strings.Contains(out, "attempt=1") || !strings.Contains(out, "state=partial") {
		t.Fatalf("auditoría:\n%s", out)
	}
}

func TestTresCortesFallanElEquipo(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	newCut(t, e, map[string]error{"show version": platform.ErrPromptTimeout, "show running-config": platform.ErrClosed, "show ip interface brief": platform.ErrPromptTimeout})
	res, _ := runPartial(t, e, context.Background())
	if res.State != "failed" || res.Reconnects != maxReconnects || !errors.Is(res.DetailErr, platform.ErrPromptTimeout) {
		t.Fatalf("res = %+v", res)
	}
}

func TestFinDeVentanaNoReconecta(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	st := newCut(t, e, map[string]error{"show running-config": fmt.Errorf("%w: %w", platform.ErrPromptTimeout, context.Canceled)})
	ctx, cancel := context.WithCancelCause(context.Background())
	st.onCut = func() { cancel(ErrWindowEnded) }
	res, _ := runPartial(t, e, ctx)
	if res.State != "failed" || !errors.Is(res.DetailErr, ErrWindowEnded) || st.opened != 1 || res.Reconnects != 0 {
		t.Fatalf("res = %+v opened=%d", res, st.opened)
	}
}

func TestErrorDeEvidenciaNoReconecta(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	st.onCut = func() { // la evidencia ya no se puede escribir
		filepath.Walk(w.Dir(), func(p string, fi os.FileInfo, _ error) error {
			if fi != nil && !fi.IsDir() {
				os.Chmod(p, 0o400)
			}
			return nil
		})
	}
	res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
	if res.State != "failed" || st.opened != 1 || res.Reconnects != 0 {
		t.Fatalf("res = %+v opened=%d", res, st.opened)
	}
}

func TestReconexionFallidaFallaElEquipo(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	st.failOpenFrom = 2
	res, _ := runPartial(t, e, context.Background())
	if res.State != "failed" || !errors.Is(res.DetailErr, platform.ErrEnableFailed) {
		t.Fatalf("res = %+v", res)
	}
	if res.Reconnects != 1 || len(res.CutCommands) != 1 { // el manifest conserva el rastro aunque el equipo falle
		t.Fatalf("rastro: %+v", res)
	}
	if st.close != 2 {
		t.Fatalf("cerradas = %d", st.close)
	}
}

func TestPreVuelveACorrerEnLaSesionNueva(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	e.d.Playbooks = append(e.d.Playbooks, playbook.Playbook{ID: "ios-xe/pre-prueba", Platform: "ios-xe", Name: "pre", Pre: []string{"show clock"},
		Commands: []playbook.Command{{Text: "show version", Timeout: time.Minute}, {Text: "show running-config", Timeout: time.Minute}, {Text: "show ip interface brief", Timeout: time.Minute}}})
	e.spec.PlaybookIDs, e.spec.CustomCommands = []string{"ios-xe/pre-prueba"}, ""
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	res, w := runPartial(t, e, context.Background())
	if res.State != "partial" || st.count("show clock") != 2 {
		t.Fatalf("res = %+v ran=%v", res, st.ran)
	}
	if n := strings.Count(evidence(w), "show clock"); n != 1 {
		t.Fatalf("el Pre repetido no debe ir a la evidencia: %d", n)
	}
}

func TestCorteEnElUltimoComandoNoReconecta(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	e.spec.CustomCommands = "show version\nshow running-config"
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	res, _ := runPartial(t, e, context.Background())
	if res.State != "partial" || res.Reconnects != 0 || st.opened != 1 || !slices.Equal(res.CutCommands, []string{"show running-config"}) {
		t.Fatalf("res = %+v opened=%d", res, st.opened)
	}
}

func TestPreCortadoNoSeRepite(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	e.d.Playbooks = append(e.d.Playbooks, playbook.Playbook{ID: "ios-xe/pre-prueba", Platform: "ios-xe", Name: "pre", Pre: []string{"show clock"},
		Commands: []playbook.Command{{Text: "show version", Timeout: time.Minute}, {Text: "show running-config", Timeout: time.Minute}}})
	e.spec.PlaybookIDs, e.spec.CustomCommands = []string{"ios-xe/pre-prueba"}, ""
	st := newCut(t, e, map[string]error{"show clock": platform.ErrPromptTimeout})
	res, _ := runPartial(t, e, context.Background())
	if res.State != "partial" || st.count("show clock") != 1 {
		t.Fatalf("res = %+v ran=%v", res, st.ran)
	}
}

func TestCancelacionNoSeAnotaComoCorte(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	st := newCut(t, e, map[string]error{"show running-config": fmt.Errorf("%w: %w", platform.ErrPromptTimeout, context.Canceled)})
	ctx, cancel := context.WithCancel(context.Background())
	st.onCut = cancel
	res, _ := runPartial(t, e, ctx)
	if res.State != "failed" || len(res.CutCommands) != 0 {
		t.Fatalf("res = %+v", res)
	}
}

func TestReconexionAOtroEquipoFalla(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	st.serialsFrom2 = []string{"OTRA-SERIE"} // mismo prompt, otra unidad (un par en failover con prompt por omisión)
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
	if res.State != "failed" || !strings.Contains(res.Detail, "FOC0000X0XX") || !strings.Contains(res.Detail, "OTRA-SERIE") {
		t.Fatalf("res = %+v", res)
	}
	var c interface{ Reason() string }
	if !errors.As(res.DetailErr, &c) || c.Reason() != "patrol.err.reconnect_other_device" {
		t.Fatalf("razón: %v", res.DetailErr)
	}
	if st.count("show ip interface brief") != 0 || st.opened != 2 || st.close != 2 {
		t.Fatalf("no debe correr nada en el otro equipo: ran=%v opened=%d closed=%d", st.ran, st.opened, st.close)
	}
}

// El mismo equipo con otro prompt (prompt hostname state, %n de la línea vty) no es otro equipo: sigue.
func TestReconexionMismaSerieConOtroPromptSigue(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	st.hostFrom2 = "OTRO-PROMPT"
	res, _ := runPartial(t, e, context.Background())
	if res.State != "partial" || res.Reconnects != 1 {
		t.Fatalf("res = %+v", res)
	}
}

func TestReconexionConservaLaPrimeraLlaveCambiada(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	_, k1 := simulator.Start(t, e.simCfg)
	_, k2 := simulator.Start(t, e.simCfg)
	hp := hostport(e.spec.Targets[0])
	e.d.Hosts.Add(hp, k1)
	e.spec.AcceptChangedHostKeys = true
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	st.onCut = func() { e.d.Hosts.Add(hp, k2) } // la reconexión ve otra llave cambiada
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
	if res.State != "partial" || res.ChangedHostKey == nil || res.ChangedHostKey.Old != fp(k1.Marshal()) {
		t.Fatalf("la primera llave cambiada se perdió: %+v", res.ChangedHostKey)
	}
}

func TestCorteEnElUltimoConReconexionesAgotadasYUnaSalidaCompletaEsParcial(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	e.spec.CustomCommands = "show version\nshow clock\nshow users\nshow running-config"
	newCut(t, e, map[string]error{"show clock": platform.ErrPromptTimeout, "show users": platform.ErrClosed, "show running-config": platform.ErrPromptTimeout})
	res, _ := runPartial(t, e, context.Background())
	if res.State != "partial" || res.Reconnects != maxReconnects || len(res.CutCommands) != 3 { // show version salió completo
		t.Fatalf("res = %+v", res)
	}
}

// Un comando cortado con secreto (uno personalizado) no deja el valor en la auditoría, el detalle, el manifest ni la cabecera.
func TestComandoCortadoSecretoVaEnmascarado(t *testing.T) {
	const cmd, val = "show running-config interface Gi1 key 7 0822455D0A16", "0822455D0A16"
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	e.spec.CustomCommands = "show version\n" + cmd + "\nshow clock"
	newCut(t, e, map[string]error{cmd: platform.ErrPromptTimeout})
	res, w := runPartial(t, e, context.Background())
	if res.State != "partial" || len(res.CutCommands) != 1 {
		t.Fatalf("res = %+v", res)
	}
	m, _ := Finish(context.Background(), e.d, w, e.spec, 1, []DeviceResult{res})
	mj, _ := json.Marshal(m)
	var buf bytes.Buffer
	e.d.Audit.Export(context.Background(), &buf, time.Time{}, time.Now().Add(time.Hour))
	for name, txt := range map[string]string{"detalle": res.Detail, "cortados": strings.Join(res.CutCommands, "|"), "manifest": string(mj), "auditoría": buf.String(), "evidencia": evidence(w)} {
		if strings.Contains(txt, val) {
			t.Errorf("%s trae el valor: %s", name, txt)
		}
	}
	if !strings.Contains(evidence(w), "show running-config interface Gi1 key 7 <MASKED:secret> · incomplete") {
		t.Fatalf("cabecera: %s", evidence(w))
	}
}

// Enmascarar el comando de la cabecera no debe tocar ningún comando de los playbooks.
func TestCmdNoTocaLosComandosDeLosPlaybooks(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	for _, p := range e.d.Playbooks {
		for _, c := range p.Commands {
			if got := mask.Cmd(p.Platform, c.Text); got != c.Text {
				t.Errorf("%s: %q -> %q", p.ID, c.Text, got)
			}
		}
	}
}

// fp es la huella SHA256 de una llave pública en wire format (como la de ssh.FingerprintSHA256).
func fp(b []byte) string {
	h := sha256.Sum256(b)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}

// Partial solo con al menos una salida completa que no sea inválida: si todo se cortó (o lo demás fue inválido) el equipo
// queda failed, con 1, 2 o 3 comandos y sin importar las reconexiones.
func TestTodoCortadoOSoloInvalidoFalla(t *testing.T) {
	cortes := func(cs ...string) map[string]error {
		m := map[string]error{}
		for _, c := range cs {
			m[c] = platform.ErrPromptTimeout
		}
		return m
	}
	for name, c := range map[string]struct {
		cmds string
		cut  map[string]error
	}{
		"uno":                     {"show version", cortes("show version")},
		"dos":                     {"show version\nshow users", cortes("show version", "show users")},
		"tres":                    {"show version\nshow users\nshow running-config", cortes("show version", "show users", "show running-config")},
		"un invalido y dos":       {"show clock\nshow version\nshow users", cortes("show version", "show users")},
		"uno completo y un corte": {"show version\nshow users", cortes("show users")}, // este sí es partial
	} {
		e := newEnv(t, simulator.Config{})
		e.trust(t)
		e.spec.CustomCommands = c.cmds
		newCut(t, e, c.cut)
		res, _ := runPartial(t, e, context.Background())
		want := "failed"
		if strings.HasPrefix(name, "uno completo") {
			want = "partial"
		}
		if res.State != want || (want == "failed" && res.DetailErr == nil) {
			t.Errorf("%s: res = %+v", name, res)
		}
	}
}

// Qué hace la reconexión con las series de las dos sesiones (fixtures inventadas: un stack de 3 con switchover, un par ASA
// en failover, una sesión sin serie y un FTD con UUID).
func TestOtroEquipoSegunLasSeries(t *testing.T) {
	stack := []string{"FCW2233A0AA", "FCW2233A0BB", "FCW2233A0CC"}
	for name, c := range map[string]struct {
		hostA, platA string
		serA         []string
		hostB, platB string
		serB         []string
		other, note  bool
	}{
		"stack con switchover: interseccion, sigue y se audita": {"SW1", "ios-xe", stack, "SW1", "ios-xe", []string{"FCW2233A0BB", "FCW2233A0CC"}, false, true},
		"stack igual: sigue sin nota":                           {"SW1", "ios-xe", stack, "SW1", "ios-xe", stack, false, false},
		"par asa: disjuntos":                                    {"asa", "asa", []string{"JAD2233A0AA"}, "asa", "asa", []string{"JAD2233A0BB"}, true, false},
		"sin serie, mismo hostname: sigue":                      {"WLC1", "wlc-aireos", nil, "WLC1", "wlc-aireos", nil, false, false},
		"sin serie, otro hostname: otro":                        {"ISE1", "ise", nil, "ISE2", "ise", nil, true, false},
		"a una le falta la serie, otro hostname: otro":          {"SW1", "ios-xe", stack, "SW2", "ios-xe", nil, true, false},
		"ftd con uuid":                                          {"fw", "ftd", []string{"1b2c3d4e-0000"}, "fw", "ftd", []string{"1b2c3d4e-0000"}, false, false},
		"otra plataforma":                                       {"fw", "asa", []string{"X"}, "fw", "ftd", []string{"X"}, true, false},
	} {
		other, note := otherDevice(c.hostA, c.platA, c.serA, c.hostB, c.platB, c.serB)
		if other != c.other || note != c.note {
			t.Errorf("%s: other=%v note=%v", name, other, note)
		}
	}
}

// Un switchover que cambia el conjunto de series pero conserva alguna: la ronda sigue y la auditoría deja la nota.
func TestReconexionConInterseccionDeSeriesSeAudita(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	st.serialsFrom2 = []string{"FOC0000X0XX", "FOC0000X0YY"}
	res, _ := runPartial(t, e, context.Background())
	var buf bytes.Buffer
	e.d.Audit.Export(context.Background(), &buf, time.Time{}, time.Now().Add(time.Hour))
	if res.State != "partial" || !strings.Contains(buf.String(), "serial set changed") {
		t.Fatalf("res = %+v\n%s", res, buf.String())
	}
}
