package assist

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeExec registra todo lo que el motor le pide y responde según su guion.
type fakeExec struct {
	mu       sync.Mutex
	calls    []string
	failCfg  map[string]string // equipo -> línea que el equipo rechaza
	readFunc func(dev, cmd string) string
	changed  map[string]bool
	closed   bool
	cfgErr   map[string]int // equipo -> veces que Configure devuelve un error de conexión sin mandar nada
	// cutAfter: equipo -> veces que Configure manda solo la primera línea y la sesión se corta (el equipo queda a medias).
	cutAfter map[string]int
	// endErr: equipo -> veces que Configure aplica todo y aun así falla (el `end` o el prompt final).
	endErr      map[string]int
	partial     map[string]bool
	onConfigure func(dev string, lines []string)
	echo        bool // la respuesta de cada línea repite la línea, como el eco de la terminal
	readErr     func(dev string) error
	omit        string // comando cuya salida no llega
}

func (f *fakeExec) log(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }
func (f *fakeExec) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}
func (f *fakeExec) count(prefix string) int {
	n := 0
	for _, c := range f.Calls() {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (f *fakeExec) Read(_ context.Context, dev string, cmds []string) ([]Output, error) {
	f.mu.Lock()
	re := f.readErr
	f.mu.Unlock()
	if re != nil {
		if err := re(dev); err != nil {
			return nil, err
		}
	}
	var out []Output
	for _, c := range cmds {
		f.log("read " + dev + ": " + c)
		f.mu.Lock()
		text := "base"
		if f.changed[dev] { // tras configurar, el equipo muestra la VLAN nueva (cumple el Expect de okPlan)
			text = "interface Gi1\n switchport access vlan 20"
		}
		f.mu.Unlock()
		f.mu.Lock()
		if f.partial[dev] {
			text = "interface Gi1\n a medias"
		}
		f.mu.Unlock()
		if f.readFunc != nil {
			text = f.readFunc(dev, c)
		}
		f.mu.Lock()
		skip := c == f.omit
		f.mu.Unlock()
		if !skip {
			out = append(out, Output{Command: c, Text: text})
		}
	}
	return out, nil
}

func (f *fakeExec) Configure(_ context.Context, dev string, lines []string) ([]Sent, error) {
	var sent []Sent
	f.mu.Lock()
	hook := f.onConfigure
	f.mu.Unlock()
	if hook != nil {
		hook(dev, lines)
	}
	f.mu.Lock()
	if f.cutAfter[dev] > 0 {
		f.cutAfter[dev]--
		if f.partial == nil {
			f.partial = map[string]bool{}
		}
		f.partial[dev] = true
		f.mu.Unlock()
		f.log("cfg " + dev + ": " + lines[0])
		return []Sent{{Line: lines[0]}}, errors.New("platform: la sesión se cortó")
	}
	endErr := f.endErr[dev] > 0
	if endErr {
		f.endErr[dev]--
	}
	delete(f.partial, dev)
	if f.cfgErr[dev] > 0 {
		f.cfgErr[dev]--
		f.mu.Unlock()
		f.log("cfgerr " + dev)
		return nil, errors.New("platform: el equipo cerró la sesión")
	}
	if f.changed == nil {
		f.changed = map[string]bool{}
	}
	f.changed[dev] = lines[len(lines)-1] != "switchport access vlan 10" // la reversa devuelve el estado original
	f.mu.Unlock()
	for _, l := range lines {
		f.log("cfg " + dev + ": " + l)
		s := Sent{Line: l, Output: ""}
		if f.echo {
			s.Output = l + "\nSW1(config)#"
		}
		if f.failCfg[dev] == l {
			s.Output, s.Failed = "% Invalid input detected at '^' marker.", true
			sent = append(sent, s)
			return sent, nil
		}
		sent = append(sent, s)
	}
	if endErr {
		return sent, errors.New("platform: falló el end")
	}
	return sent, nil
}

func (f *fakeExec) Save(_ context.Context, dev string) (string, error) {
	f.log("save " + dev)
	return "[OK]", nil
}
func (f *fakeExec) Close() { f.mu.Lock(); f.closed = true; f.mu.Unlock() }

type auditRec struct {
	mu      sync.Mutex
	entries []string
}

func (a *auditRec) add(action, target, detail string) {
	a.mu.Lock()
	a.entries = append(a.entries, action+" | "+target+" | "+detail)
	a.mu.Unlock()
}
func (a *auditRec) text() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.Join(a.entries, "\n")
}

func twoDevices() Plan {
	p := okPlan()
	d2 := okPlan().Devices[0]
	d2.Device = "SW2"
	p.Devices = append(p.Devices, d2)
	for i := range p.Devices {
		p.Devices[i].Baseline = map[string]string{p.Devices[i].Pre[0]: "base"}
	}
	return p
}

func newRun(t *testing.T, p Plan, ex *fakeExec) (*Run, *auditRec) {
	t.Helper()
	return newRunT(t, p, ex, 0)
}

func newRunT(t *testing.T, p Plan, ex *fakeExec, timeout time.Duration) (*Run, *auditRec) {
	t.Helper()
	a := &auditRec{}
	r, err := NewRun(Options{ID: "run1", Plan: p, Fn: Ports, Assisted: true, Exec: ex, Audit: a.add, DecisionTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return r, a
}

func wait(t *testing.T, r *Run, want State) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r.State() == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("estado %s, se esperaba %s", r.State(), want)
}

func pending(t *testing.T, r *Run, id string) {
	t.Helper()
	wait(t, r, WaitingConfirm)
	if p := r.Pending(); p == nil || p.ID != id {
		t.Fatalf("pendiente %+v, se esperaba %s", p, id)
	}
}

// Regla 1: sin assisted no existe la ejecución y no se habló con ningún equipo.
func TestNewRunRequiresAssisted(t *testing.T) {
	ex := &fakeExec{}
	_, err := NewRun(Options{ID: "r", Plan: twoDevices(), Fn: Ports, Assisted: false, Exec: ex, Audit: func(a, b, c string) {}})
	if !errors.Is(err, ErrNotAssisted) {
		t.Fatalf("err = %v", err)
	}
	if len(ex.Calls()) != 0 {
		t.Fatalf("hubo llamadas: %v", ex.Calls())
	}
}

// Regla 2 y 3 también en el motor: un plan sin reversa o con una línea fuera de lista no arranca.
func TestNewRunValidatesPlan(t *testing.T) {
	ex := &fakeExec{}
	p := twoDevices()
	p.Devices[1].Rollback = nil
	if _, err := NewRun(Options{ID: "r", Plan: p, Fn: Ports, Assisted: true, Exec: ex, Audit: func(a, b, c string) {}}); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("err = %v", err)
	}
	p = twoDevices()
	p.Devices[0].Apply = append(p.Devices[0].Apply, "reload")
	if _, err := NewRun(Options{ID: "r", Plan: p, Fn: Ports, Assisted: true, Exec: ex, Audit: func(a, b, c string) {}}); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("err = %v", err)
	}
	if len(ex.Calls()) != 0 {
		t.Fatalf("hubo llamadas: %v", ex.Calls())
	}
}

// Regla 4: nada cambia sin Confirm del paso exacto; Abort detiene lo que falta.
func TestRunWaitsForConfirmBeforeEachChange(t *testing.T) {
	ex := &fakeExec{}
	r, _ := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	if ex.count("read SW1") != 1 || ex.count("read SW2") != 1 {
		t.Fatalf("los pre-checks de todos los equipos van antes de aplicar: %v", ex.Calls())
	}
	time.Sleep(30 * time.Millisecond)
	if ex.count("cfg") != 0 {
		t.Fatalf("se configuró sin confirmar: %v", ex.Calls())
	}
	if err := r.Confirm("apply-2"); !errors.Is(err, ErrWrongStep) {
		t.Fatalf("confirmar otro paso: %v", err)
	}
	if err := r.Confirm("apply-1"); err != nil {
		t.Fatal(err)
	}
	if err := r.Confirm("apply-1"); err == nil {
		t.Fatal("la confirmación se pudo repetir")
	}
	pending(t, r, "apply-2")
	if ex.count("cfg SW1") != 2 || ex.count("cfg SW2") != 0 {
		t.Fatalf("llamadas: %v", ex.Calls())
	}
	if err := r.Abort(); err != nil {
		t.Fatal(err)
	}
	wait(t, r, Aborted)
	<-r.Done()
	if ex.count("cfg SW2") != 0 {
		t.Fatalf("Abort aplicó algo más: %v", ex.Calls())
	}
	if !ex.closed {
		t.Fatal("no se cerraron las conexiones")
	}
}

func TestRunHappyPathAndRollbackOrder(t *testing.T) {
	ex := &fakeExec{}
	p := twoDevices()
	r, _ := newRun(t, p, ex)
	r.Start(context.Background())
	for _, id := range []string{"apply-1", "apply-2"} {
		pending(t, r, id)
		if id == "apply-2" {
			break
		}
		r.Confirm(id)
	}
	// Con SW1 ya cambiado y SW2 por aplicar, se pide revertir: solo SW1, y con confirmación.
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	if ex.count("cfg SW1: switchport access vlan 10") != 0 {
		t.Fatal("la reversa se aplicó sin confirmar")
	}
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
	if ex.count("cfg SW2") != 0 {
		t.Fatalf("SW2 nunca se tocó: %v", ex.Calls())
	}
	if !strings.Contains(strings.Join(ex.Calls(), "\n"), "cfg SW1: switchport access vlan 10") {
		t.Fatalf("falta la reversa: %v", ex.Calls())
	}

	// Ambos cambiados: la reversa va en orden inverso.
	ex2 := &fakeExec{}
	r2, _ := newRun(t, twoDevices(), ex2)
	r2.Start(context.Background())
	pending(t, r2, "apply-1")
	r2.Confirm("apply-1")
	pending(t, r2, "apply-2")
	r2.Confirm("apply-2")
	pending(t, r2, "close")
	r2.Confirm("close")
	wait(t, r2, Done)
	if err := r2.Rollback(); !errors.Is(err, ErrBadState) {
		t.Fatalf("revertir una ejecución terminada: %v", err)
	}
}

func TestRollbackReverseOrderAfterFailure(t *testing.T) {
	ex := &fakeExec{failCfg: map[string]string{"SW2": "switchport access vlan 20"}}
	r, _ := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "apply-2")
	r.Confirm("apply-2")
	wait(t, r, Failed)
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-2")
	r.Confirm("rollback-2")
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
	calls := strings.Join(ex.Calls(), "\n")
	if strings.Index(calls, "cfg SW2: switchport access vlan 10") > strings.Index(calls, "cfg SW1: switchport access vlan 10") ||
		!strings.Contains(calls, "cfg SW2: switchport access vlan 10") {
		t.Fatalf("la reversa debe ir SW2 y luego SW1:\n%s", calls)
	}
}

// Regla 5: un error de configuración detiene todo y propone la reversa; no sigue con el siguiente equipo.
func TestConfigErrorStopsAndOffersRollback(t *testing.T) {
	ex := &fakeExec{failCfg: map[string]string{"SW1": "switchport access vlan 20"}}
	r, _ := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	wait(t, r, Failed)
	if r.Pending() != nil {
		t.Fatal("no debe quedar paso pendiente salvo que se pida la reversa")
	}
	time.Sleep(30 * time.Millisecond)
	if ex.count("cfg SW2") != 0 {
		t.Fatalf("siguió con otro equipo: %v", ex.Calls())
	}
	if !strings.Contains(r.FailReason(), "Invalid input") {
		t.Fatalf("motivo: %q", r.FailReason())
	}
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
}

func TestExpectFailureStopsAndOffersRollback(t *testing.T) {
	ex := &fakeExec{}
	// El post-check no muestra la VLAN nueva.
	ex.readFunc = func(dev, cmd string) string {
		if ex.count("cfg") > 0 {
			return "interface Gi1\n switchport access vlan 10"
		}
		return "base"
	}
	r, _ := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	wait(t, r, Failed)
	time.Sleep(30 * time.Millisecond)
	if ex.count("cfg SW2") != 0 {
		t.Fatalf("siguió con otro equipo: %v", ex.Calls())
	}
	if !strings.Contains(r.FailReason(), "switchport access vlan 20") {
		t.Fatalf("motivo: %q", r.FailReason())
	}
	if err := r.Abort(); err != nil {
		t.Fatal(err)
	}
	<-r.Done()
	if r.State() != Failed || ex.count("cfg SW1: switchport access vlan 10") != 0 {
		t.Fatalf("Abort no debe revertir solo: %s %v", r.State(), ex.Calls())
	}
}

func TestStalePlanStopsBeforeChanging(t *testing.T) {
	ex := &fakeExec{readFunc: func(_, _ string) string { return "otra cosa" }}
	r, _ := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	wait(t, r, Failed)
	<-r.Done()
	if ex.count("cfg") != 0 || !strings.Contains(r.FailReason(), "vuelve a planear") {
		t.Fatalf("%q %v", r.FailReason(), ex.Calls())
	}
	if err := r.Rollback(); err == nil {
		t.Fatal("no había nada que revertir")
	}
}

// Regla 6: cada línea, su respuesta, cada confirmación, el aborto y la reversa quedan con el runID.
func TestRunAuditsEverything(t *testing.T) {
	ex := &fakeExec{failCfg: map[string]string{"SW2": "switchport access vlan 20"}}
	r, a := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "apply-2")
	r.Confirm("apply-2")
	wait(t, r, Failed)
	r.Rollback()
	pending(t, r, "rollback-2")
	r.Confirm("rollback-2")
	pending(t, r, "rollback-1")
	r.Abort()
	<-r.Done()
	text := a.text()
	for _, want := range []string{
		"assist.start | run1", "assist.confirm | run1 | apply-1", "assist.line | SW1 | run=run1 line=switchport access vlan 20",
		"assist.line | SW2 | run=run1 line=switchport access vlan 20 response=% Invalid input", "assist.fail | run1",
		"assist.rollback | run1", "assist.confirm | run1 | rollback-2", "assist.line | SW2 | run=run1 line=switchport access vlan 10",
		"assist.abort | run1",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("falta en la bitácora %q\n%s", want, text)
		}
	}
	// La respuesta se recorta.
	long := strings.Repeat("x", 1000)
	if got := trim(long); len(got) > 260 {
		t.Fatalf("respuesta de %d caracteres", len(got))
	}
}

// Regla 7: sin guardar en NVRAM salvo el paso explícito, al final y confirmado.
func TestWriteMemoryOnlyWhenPlannedAndConfirmed(t *testing.T) {
	ex := &fakeExec{}
	r, _ := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	for _, id := range []string{"apply-1", "apply-2", "close"} {
		pending(t, r, id)
		r.Confirm(id)
	}
	wait(t, r, Done)
	if ex.count("save") != 0 {
		t.Fatalf("guardó sin pedirlo: %v", ex.Calls())
	}

	p := twoDevices()
	p.WriteMemory = true
	ex2 := &fakeExec{}
	r2, _ := newRun(t, p, ex2)
	r2.Start(context.Background())
	for _, id := range []string{"apply-1", "apply-2"} {
		pending(t, r2, id)
		r2.Confirm(id)
	}
	pending(t, r2, "save-1")
	if ex2.count("save") != 0 {
		t.Fatal("guardó antes de confirmar")
	}
	r2.Confirm("save-1")
	pending(t, r2, "save-2")
	r2.Confirm("save-2")
	wait(t, r2, Done)
	if ex2.count("save") != 2 {
		t.Fatalf("llamadas: %v", ex2.Calls())
	}
	_ = fmt.Sprint()
}

func TestEventsReplayAndFinish(t *testing.T) {
	ex := &fakeExec{}
	r, _ := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Abort()
	<-r.Done()
	evs, _ := r.Events(0)
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, string(e.Kind))
	}
	if len(evs) == 0 || evs[len(evs)-1].State != Aborted {
		t.Fatalf("eventos: %v", kinds)
	}
}

// Al verse el estado failed, Rollback y Abort ya deben ser aceptados: un cliente que reacciona al
// evento de fallo no puede toparse con un motor que todavía no espera la decisión.
func TestFailedStateAcceptsDecisionImmediately(t *testing.T) {
	for i := 0; i < 300; i++ {
		ex := &fakeExec{failCfg: map[string]string{"SW1": "switchport access vlan 20"}}
		r, _ := newRun(t, twoDevices(), ex)
		r.Start(context.Background())
		pending(t, r, "apply-1")
		r.Confirm("apply-1")
		for r.State() != Failed {
		}
		if err := r.Rollback(); err != nil {
			t.Fatalf("iteración %d: %v", i, err)
		}
		pending(t, r, "rollback-1")
		r.Abort()
		<-r.Done()
	}
}

// Hallazgo 1: si la reversa falla, la ejecución no termina: espera reintentar la reversa o abortar.
func TestRollbackFailureWaitsForDecision(t *testing.T) {
	ex := &fakeExec{cfgErr: map[string]int{}}
	r, a := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "apply-2")
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	ex.cfgErr["SW1"] = 1
	r.Confirm("rollback-1")
	wait(t, r, Failed)
	select {
	case <-r.Done():
		t.Fatal("la ejecución terminó con la reversa fallida")
	case <-time.After(30 * time.Millisecond):
	}
	if err := r.Rollback(); err != nil { // reintentar
		t.Fatalf("no se puede reintentar la reversa: %v", err)
	}
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
	<-r.Done()
	if got := r.Changed(); len(got) != 0 {
		t.Fatalf("cambiados tras revertir: %v", got)
	}
	if !strings.Contains(a.text(), "assist.fail") {
		t.Fatal("el fallo de la reversa no se auditó")
	}
}

func TestRollbackFailureThenAbortReportsChanged(t *testing.T) {
	ex := &fakeExec{cfgErr: map[string]int{"SW1": 5}}
	r, a := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	ex.cfgErr["SW1"] = 0
	r.Confirm("apply-1")
	pending(t, r, "apply-2")
	r.Rollback()
	pending(t, r, "rollback-1")
	ex.cfgErr["SW1"] = 5
	r.Confirm("rollback-1")
	wait(t, r, Failed)
	if err := r.Abort(); err != nil {
		t.Fatal(err)
	}
	<-r.Done()
	if r.State() != Aborted || !reflect.DeepEqual(r.Changed(), []string{"SW1"}) {
		t.Fatalf("estado %s cambiados %v", r.State(), r.Changed())
	}
	if !strings.Contains(a.text(), "changed=SW1") {
		t.Fatalf("la auditoría no dice qué equipo quedó cambiado:\n%s", a.text())
	}
}

// Hallazgo 9: un equipo al que no se le mandó ninguna línea (no hubo conexión o no entró a configuración) no cuenta como cambiado.
func TestNoLinesSentMeansNotChanged(t *testing.T) {
	ex := &fakeExec{cfgErr: map[string]int{"SW1": 1}}
	r, _ := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	wait(t, r, Failed)
	select {
	case <-r.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("la ejecución sigue esperando una decisión que no existe")
	}
	if len(r.Changed()) != 0 {
		t.Fatalf("cambiados = %v", r.Changed())
	}
	if err := r.Rollback(); err == nil {
		t.Fatal("no había nada que revertir")
	}
}

// La línea base se compara otra vez tras Confirm: si el equipo cambió mientras se decidía, no se aplica nada.
func TestBaselineRecheckedAfterConfirm(t *testing.T) {
	ex := &fakeExec{}
	reads := 0
	ex.readFunc = func(dev, cmd string) string {
		if dev != "SW1" {
			return "base"
		}
		reads++ // solo lo llama el motor, en un hilo
		if reads == 1 {
			return "base"
		}
		return "alguien cambió el puerto"
	}
	r, _ := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	wait(t, r, Failed)
	select {
	case <-r.Done():
	case <-time.After(500 * time.Millisecond):
	}
	if ex.count("cfg") != 0 || len(r.Changed()) != 0 || !strings.Contains(r.FailReason(), "cambió desde que se hizo el plan") {
		t.Fatalf("%q %v %v", r.FailReason(), r.Changed(), ex.Calls())
	}
}

// Antes de la reversa se compara con lo que dejó nuestro cambio: si alguien más tocó el puerto, no se pisa.
func TestRollbackStopsIfDeviceChangedSinceOurChange(t *testing.T) {
	ex := &fakeExec{}
	r, a := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "apply-2")
	ex.readFunc = func(dev, cmd string) string { return "otro ingeniero tocó el puerto" }
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, Failed)
	if ex.count("cfg SW1: switchport access vlan 10") != 0 || !strings.Contains(r.FailReason(), "pisaría un cambio ajeno") {
		t.Fatalf("%q %v", r.FailReason(), ex.Calls())
	}
	r.Abort()
	<-r.Done()
	if r.State() != Aborted || !reflect.DeepEqual(r.Changed(), []string{"SW1"}) || !strings.Contains(a.text(), "changed=SW1") {
		t.Fatalf("%s %v", r.State(), r.Changed())
	}
}

// Hallazgo 6: sin decisión en el tope, o con el contexto cancelado, la ejecución pasa a abandoned y dice qué quedó cambiado.
func TestRunAbandonedOnTimeoutAndOnCancel(t *testing.T) {
	for _, byCancel := range []bool{false, true} {
		ex := &fakeExec{}
		a := &auditRec{}
		o := Options{ID: "run1", Plan: twoDevices(), Fn: Ports, Assisted: true, Exec: ex, Audit: a.add}
		if !byCancel {
			o.DecisionTimeout = 40 * time.Millisecond
		}
		r, err := NewRun(o)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		r.Start(ctx)
		pending(t, r, "apply-1")
		r.Confirm("apply-1")
		pending(t, r, "apply-2")
		if byCancel {
			cancel()
		}
		wait(t, r, Abandoned)
		<-r.Done()
		cancel()
		if !reflect.DeepEqual(r.Changed(), []string{"SW1"}) || !ex.closed || r.Pending() != nil {
			t.Fatalf("byCancel=%v changed=%v closed=%v", byCancel, r.Changed(), ex.closed)
		}
		if !strings.Contains(a.text(), "assist.abandoned") || !strings.Contains(a.text(), "changed=SW1") {
			t.Fatalf("auditoría:\n%s", a.text())
		}
		if err := r.Confirm("apply-2"); err == nil {
			t.Fatal("se pudo confirmar una ejecución abandonada")
		}
		if err := r.Rollback(); err == nil {
			t.Fatal("se pudo revertir una ejecución abandonada")
		}
	}
}

// Segunda revisión A: una reversa cortada a mitad deja el equipo distinto de lo que dejó el apply; el reintento
// no debe tomarlo por un cambio ajeno.
func TestRollbackCutMidwayCanBeRetried(t *testing.T) {
	ex := &fakeExec{cutAfter: map[string]int{}}
	r, _ := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "apply-2")
	r.Rollback()
	pending(t, r, "rollback-1")
	ex.cutAfter["SW1"] = 1
	r.Confirm("rollback-1")
	wait(t, r, Failed)
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
	if len(r.Changed()) != 0 || ex.partial["SW1"] {
		t.Fatalf("cambiados %v, a medias %v", r.Changed(), ex.partial)
	}
}

// Segunda revisión A: la reversa se aplicó completa y solo falló el cierre: el equipo ya está como al inicio.
func TestRollbackAppliedButEndFailedCountsAsReverted(t *testing.T) {
	ex := &fakeExec{endErr: map[string]int{}}
	r, _ := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "apply-2")
	r.Rollback()
	pending(t, r, "rollback-1")
	ex.endErr["SW1"] = 1
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
	if len(r.Changed()) != 0 {
		t.Fatalf("cambiados %v", r.Changed())
	}
}

// Segunda revisión B: si el apply falla a mitad, lo que quedó en el equipo es la referencia de la reversa.
func TestRollbackAfterFailedApplyRefusesForeignChange(t *testing.T) {
	ex := &fakeExec{failCfg: map[string]string{"SW1": "switchport access vlan 20"}}
	r, _ := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	wait(t, r, Failed)
	ex.readFunc = func(dev, cmd string) string { return "otro ingeniero tocó el puerto" }
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, Failed)
	if ex.count("cfg SW1: switchport access vlan 10") != 0 || !strings.Contains(r.FailReason(), "pisaría un cambio ajeno") {
		t.Fatalf("%q %v", r.FailReason(), ex.Calls())
	}
}

func hook(ex *fakeExec, f func(dev string, lines []string)) {
	ex.mu.Lock()
	ex.onConfigure = f
	ex.mu.Unlock()
}

func aborted(t *testing.T, r *Run, a *auditRec, changed []string) {
	t.Helper()
	select {
	case <-r.Done():
	case <-time.After(200 * time.Millisecond): // el tope de decisión es 300 ms: debe terminar antes
		t.Fatalf("la ejecución no terminó sola: estado %s", r.State())
	}
	if r.State() != Aborted || !reflect.DeepEqual(r.Changed(), changed) || !strings.Contains(a.text(), "changed="+strings.Join(changed, ",")) {
		t.Fatalf("estado %s cambiados %v\n%s", r.State(), r.Changed(), a.text())
	}
}

// Segunda revisión C: un Abort aceptado mientras corría el apply no se pierde si el apply falla.
func TestAbortDuringApplyThatFailsEndsAborted(t *testing.T) {
	ex := &fakeExec{failCfg: map[string]string{"SW1": "switchport access vlan 20"}}
	r, a := newRunT(t, twoDevices(), ex, 300*time.Millisecond)
	hook(ex, func(string, []string) { r.Abort() })
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	aborted(t, r, a, []string{"SW1"})
}

// Segunda revisión C: un Abort durante la reversa de un equipo no pide la del siguiente.
func TestAbortDuringRollbackDoesNotAskNextDevice(t *testing.T) {
	ex := &fakeExec{failCfg: map[string]string{"SW2": "switchport access vlan 20"}}
	r, a := newRunT(t, twoDevices(), ex, 300*time.Millisecond)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "apply-2")
	r.Confirm("apply-2")
	wait(t, r, Failed)
	r.Rollback()
	pending(t, r, "rollback-2")
	hook(ex, func(dev string, _ []string) { r.Abort() })
	r.Confirm("rollback-2")
	aborted(t, r, a, []string{"SW1"})
	if ex.count("cfg SW1: switchport access vlan 10") != 0 {
		t.Fatalf("revirtió SW1 tras el Abort: %v", ex.Calls())
	}
}

// Segunda revisión C: un Abort durante una reversa que falla tampoco deja la espera armada.
func TestAbortDuringFailingRollbackEndsAborted(t *testing.T) {
	ex := &fakeExec{cfgErr: map[string]int{}}
	r, a := newRunT(t, twoDevices(), ex, 300*time.Millisecond)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "apply-2")
	r.Rollback()
	pending(t, r, "rollback-1")
	ex.mu.Lock()
	ex.cfgErr["SW1"] = 1
	ex.mu.Unlock()
	hook(ex, func(string, []string) { r.Abort() })
	r.Confirm("rollback-1")
	aborted(t, r, a, []string{"SW1"})
}

// Sin write memory el motor no termina solo tras el último equipo: se detiene en un paso de cierre
// donde el ingeniero deja el cambio (solo en running-config) o pide la reversa de todos los equipos.
func TestCloseStepWithoutWriteMemoryOffersRollback(t *testing.T) {
	ex := &fakeExec{}
	r, a := newRun(t, twoDevices(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "apply-2")
	r.Confirm("apply-2")
	pending(t, r, "close")
	if p := r.Pending(); p.Kind != StepClose {
		t.Fatalf("paso de cierre = %+v", p)
	}
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-2") // en orden inverso
	r.Confirm("rollback-2")
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
	if ex.count("save") != 0 || !strings.Contains(a.text(), "assist.rollback") {
		t.Fatalf("%v\n%s", ex.Calls(), a.text())
	}
}

// Confirmar el cierre termina en done sin write memory.
func TestCloseStepConfirmEndsDone(t *testing.T) {
	ex := &fakeExec{}
	r, _ := newRun(t, okPlan(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "close")
	r.Confirm("close")
	wait(t, r, Done)
	if ex.count("save") != 0 {
		t.Fatalf("guardó sin pedirlo: %v", ex.Calls())
	}
}

// En el cierre se puede revertir, y abortar ahí deja el cambio (estado aborted con los equipos cambiados).
func TestCloseStepAbortKeepsChange(t *testing.T) {
	ex := &fakeExec{}
	r, _ := newRun(t, okPlan(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "close")
	if !r.Snapshot().CanRollback {
		t.Fatal("en el cierre debe poder revertirse")
	}
	r.Abort()
	<-r.Done()
	if r.State() != Aborted || !reflect.DeepEqual(r.Changed(), []string{"SW1"}) {
		t.Fatalf("%s %v", r.State(), r.Changed())
	}
}

// Revisión de 28d: lo que el motor emite de una lectura pasa siempre por las reglas de enmascarado, aunque la función no pida Scrub.
// La comparación con la línea base (drift) sigue con el texto crudo; esto es solo lo que sale del motor.
func TestRunEventsAlwaysMaskReadOutputEvenWithoutScrub(t *testing.T) {
	const pw, key = "0822455D0A16", "LlaveNtpSecreta"
	if Ports.Scrub {
		t.Fatal("la prueba necesita una función sin Scrub")
	}
	ex := &fakeExec{}
	ex.readFunc = func(string, string) string {
		return "hostname SW1\nntp authentication-key 1 md5 " + key + " 7\nline vty 0 4\n password 7 " + pw + "\n login\ninterface GigabitEthernet1/0/1\n switchport access vlan 20\n"
	}
	r, a := newRun(t, okPlan(), ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	evs, _ := r.Events(0)
	var all strings.Builder
	for _, e := range evs {
		all.WriteString(e.Text + "\n")
	}
	if !strings.Contains(all.String(), "hostname SW1") {
		t.Fatalf("la lectura debe salir (enmascarada):\n%s", all.String())
	}
	for _, s := range []string{pw, key} {
		if strings.Contains(all.String(), s) || strings.Contains(a.text(), s) {
			t.Errorf("un evento o la auditoría llevan %q:\n%s", s, all.String())
		}
	}
}
