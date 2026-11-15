package assist

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// persistRec anota lo último que recibió Persist.
type persistRec struct {
	mu   sync.Mutex
	last *Leftover
	n    int
}

func (p *persistRec) set(l *Leftover) { p.mu.Lock(); p.last, p.n = l, p.n+1; p.mu.Unlock() }
func (p *persistRec) get() *Leftover  { p.mu.Lock(); defer p.mu.Unlock(); return p.last }

// pendingRotation comprueba que lo que dejó una rotación sin terminar se puede revertir: el equipo tiene el secreto nuevo, la bóveda
// todavía el anterior, y la reversa pendiente devuelve el hash previo.
func pendingRotation(t *testing.T, r *Run, pr *persistRec) {
	t.Helper()
	for _, l := range []*Leftover{r.Leftover(), pr.get()} {
		if l == nil || len(l.Devices) != 1 || !strings.Contains(strings.Join(l.Devices[0].Rollback, "\n"), oldHash9) {
			t.Fatalf("la rotación sin terminar no ofrece reversa: %+v", l)
		}
	}
	plan, fn, err := RollbackPlan(*r.Leftover())
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(plan, fn); err != nil {
		t.Fatal(err)
	}
}

// B1: un Abort aceptado mientras corre el apply de una rotación deja el secreto nuevo en el equipo: debe quedar la reversa.
func TestRotacionAbortadaEnElApplyOfreceReversa(t *testing.T) {
	var r *Run
	r, _, _ = rotationRun(t, nil, func(fx *fakeExec) {
		prev := fx.onConfigure
		fx.onConfigure = func(d string, l []string) { prev(d, l); r.Abort() }
	})
	pr := &persistRec{}
	r.persist = pr.set
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	wait(t, r, Aborted)
	<-r.Done()
	pendingRotation(t, r, pr)
}

// B1: sin decisión en write memory la rotación queda abandonada con el secreto nuevo en el equipo y la bóveda sin tocar.
func TestRotacionAbandonadaEnElSaveOfreceReversa(t *testing.T) {
	r, vx, _ := rotationRun(t, nil)
	pr := &persistRec{}
	r.persist = pr.set
	r.timeout = 150 * time.Millisecond
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "save-1")
	wait(t, r, Abandoned)
	<-r.Done()
	if vx.saved != 0 {
		t.Fatalf("la bóveda no debe tocarse: saved=%d", vx.saved)
	}
	pendingRotation(t, r, pr)
}

// B1: con la rotación completa (write memory y bóveda al día) ya no queda reversa: revertir dejaría la bóveda desfasada.
func TestRotacionCompletaNoDejaReversa(t *testing.T) {
	r, _, _ := rotationRun(t, nil)
	pr := &persistRec{}
	r.persist = pr.set
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "save-1")
	r.Confirm("save-1")
	wait(t, r, Done)
	<-r.Done()
	if r.Leftover() != nil || pr.get() != nil {
		t.Fatalf("quedó reversa: %+v / %+v", r.Leftover(), pr.get())
	}
}

// saveHookExec avisa cuando el motor manda write memory.
type saveHookExec struct {
	*fakeExec
	onSave func()
}

func (s *saveHookExec) Save(ctx context.Context, dev string) (string, error) {
	if s.onSave != nil {
		s.onSave()
	}
	return s.fakeExec.Save(ctx, dev)
}

// B4: un Abort aceptado mientras corre write memory se respeta al terminar ese paso, como en los demás pasos.
func TestAbortDuranteWriteMemoryTerminaAborted(t *testing.T) {
	ex := &saveHookExec{fakeExec: &fakeExec{}}
	p := twoDevices()
	p.WriteMemory = true
	r, err := NewRun(Options{ID: "run1", Plan: p, Fn: Ports, Assisted: true, Exec: ex, Audit: (&auditRec{}).add})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	ex.onSave = func() { once.Do(func() { r.Abort() }) }
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "apply-2")
	r.Confirm("apply-2")
	pending(t, r, "save-1")
	r.Confirm("save-1")
	wait(t, r, Aborted)
	<-r.Done()
	if n := ex.count("save"); n != 1 {
		t.Fatalf("se guardó %d veces; tras el Abort no debe seguir con el equipo 2: %v", n, ex.Calls())
	}
}

// B2: la reversa de la reversa pendiente es lo que el equipo aceptó del apply, no el plan entero (objetos que nunca existieron).
func TestPendienteGuardaLoAplicadoParaRevertirLaReversa(t *testing.T) {
	dev := nfDev()
	dp, err := l3Plan(t, "netflow-export", nfVals(), dev)
	if err != nil {
		t.Fatal(err)
	}
	tpl := mustTemplate(t, "netflow-export")
	fx := &fakeExec{echo: true}
	fx.readFunc = func(_, cmd string) string { return dev.read([]string{cmd})[cmd] }
	pr := &persistRec{}
	r, err := NewRun(Options{ID: "run1", Plan: Plan{Function: tpl.Fn.Name, Devices: []DevicePlan{dp}}, Fn: tpl.Fn, Assisted: true,
		Exec: &strictExec{fakeExec: fx, dev: dev, reject: "collect counter bytes long"}, Audit: func(a, b, c string) {}, Persist: pr.set})
	if err != nil {
		t.Fatal(err)
	}
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	wait(t, r, Failed)
	cut := slices.Index(dp.Apply, "collect counter bytes long")
	if cut < 1 {
		t.Fatalf("la prueba supone un corte a mitad: %v", dp.Apply)
	}
	for _, l := range []*Leftover{r.Leftover(), pr.get()} {
		if l == nil || !slices.Equal(l.Devices[0].Apply, dp.Apply[:cut]) {
			t.Fatalf("Apply guardado = %+v, quería %v", l, dp.Apply[:cut])
		}
		plan, _, err := RollbackPlan(*l)
		if err != nil || !slices.Equal(plan.Devices[0].Rollback, dp.Apply[:cut]) {
			t.Fatalf("la reversa de la reversa = %v (%v), quería %v", plan.Devices[0].Rollback, err, dp.Apply[:cut])
		}
	}
}

// B3: si el núcleo cae a mitad de Configure, lo persistido ya lleva la línea base como estado (pre-check) y la auditoría ya dijo qué se
// iba a mandar, con el enmascarado de siempre.
func TestCaidaAMitadDeConfigureDejaEstadoYAuditoria(t *testing.T) {
	r, _, a := rotationRun(t, nil)
	pr := &persistRec{}
	r.persist = pr.set
	var midLeft *Leftover
	var midAudit string
	// onConfigure corre dentro de Configure: lo que se ve aquí es lo que habría quedado si el núcleo cae en este punto.
	fx := r.exec.(*verifyExec).fakeExec
	prev := fx.onConfigure
	fx.onConfigure = func(d string, l []string) { midLeft, midAudit = pr.get(), a.text(); prev(d, l) }
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "save-1")
	if midLeft == nil || len(midLeft.Devices[0].State) == 0 {
		t.Fatalf("a mitad de Configure no hay State persistido: %+v", midLeft)
	}
	if _, _, err := RollbackPlan(*midLeft); err != nil {
		t.Fatalf("la reversa pendiente a mitad de Configure no sirve: %v", err)
	}
	if !strings.Contains(midAudit, "assist.send") || strings.Contains(midAudit, newSec) {
		t.Fatalf("la auditoría debe tener assist.send enmascarado antes de Configure:\n%s", midAudit)
	}
	r.Confirm("save-1")
	wait(t, r, Done)
	<-r.Done()
}

// saveHook corre algo dentro de Save (donde un Abort llega «mientras corre write memory»).
type saveHook struct {
	*fakeExec
	on func(dev string)
}

func (s *saveHook) Save(ctx context.Context, dev string) (string, error) {
	s.on(dev)
	return s.fakeExec.Save(ctx, dev)
}

// Un Abort aceptado durante el write memory del último equipo no convierte en Aborted una ejecución que ya terminó; en el primero de dos, sí.
func TestAbortEnWriteMemoryDelUltimoEquipoTerminaDone(t *testing.T) {
	for _, c := range []struct {
		abortOn string
		want    State
	}{{"SW2", Done}, {"SW1", Aborted}} {
		p := twoDevices()
		p.WriteMemory = true
		var r *Run
		ex := &saveHook{fakeExec: &fakeExec{}}
		ex.on = func(dev string) {
			if dev == c.abortOn {
				r.Abort()
			}
		}
		a := &auditRec{}
		var err error
		r, err = NewRun(Options{ID: "run1", Plan: p, Fn: Ports, Assisted: true, Exec: ex, Audit: a.add})
		if err != nil {
			t.Fatal(err)
		}
		r.Start(context.Background())
		for _, id := range []string{"apply-1", "apply-2", "save-1"} {
			pending(t, r, id)
			r.Confirm(id)
		}
		if c.want == Done {
			pending(t, r, "save-2")
			r.Confirm("save-2")
		}
		wait(t, r, c.want)
		<-r.Done()
	}
}

// Con la bóveda caída tras write memory, el texto da dos salidas excluyentes (no «edítala a mano» a secas, que con la reversa pendiente deja equipo y bóveda desfasados).
func TestBovedaCaidaTrasWriteMemoryDaDosOpcionesExcluyentes(t *testing.T) {
	r, _, _ := rotationRunWith(t, nil, func(v *verifyExec) { v.savedErr = errors.New("bloqueada") })
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "save-1")
	r.Confirm("save-1")
	wait(t, r, Failed)
	es, en := r.FailReason(), r.Snapshot().ReasonEN
	for _, s := range []string{"(a)", "(b)", "descarta"} {
		if !strings.Contains(es, s) {
			t.Errorf("es sin %q: %s", s, es)
		}
	}
	for _, s := range []string{"(a)", "(b)", "discard"} {
		if !strings.Contains(en, s) {
			t.Errorf("en sin %q: %s", s, en)
		}
	}
	r.Abort()
	<-r.Done()
}

// El pre-check de una reversa pendiente con State provisional dice que el núcleo se cortó a mitad de aplicar, no «vuelve a planear».
func TestPreCheckConStateProvisionalDiceQueElNucleoSeCorto(t *testing.T) {
	r, _, _ := rotationRun(t, nil)
	pr := &persistRec{}
	r.persist = pr.set
	var mid *Leftover
	fx := r.exec.(*verifyExec).fakeExec
	prev := fx.onConfigure
	fx.onConfigure = func(d string, l []string) { mid = pr.get(); prev(d, l) }
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "save-1")
	r.Confirm("save-1")
	wait(t, r, Done)
	<-r.Done()
	if mid == nil || !mid.Devices[0].Provisional {
		t.Fatalf("a mitad de Configure el State debe marcarse provisional: %+v", mid)
	}
	for _, c := range []struct {
		l          Leftover
		es, en, no string
	}{
		{*mid, "a mitad de aplicar", "halfway through applying", "vuelve a planear"},
		{func() Leftover {
			l := *mid
			l.Devices = []LeftDevice{l.Devices[0]}
			l.Devices[0].Provisional = false
			return l
		}(), "vuelve a planear", "plan again", "a mitad de aplicar"},
	} {
		plan, fn, err := RollbackPlan(c.l)
		if err != nil {
			t.Fatal(err)
		}
		ex := &fakeExec{readFunc: func(_, _ string) string { return "otra cosa" }}
		rr, err := NewRun(Options{ID: "p1", Plan: plan, Fn: fn, Assisted: true, Exec: ex, Audit: func(a, b, c string) {}})
		if err != nil {
			t.Fatal(err)
		}
		rr.Start(context.Background())
		wait(t, rr, Failed) // el pre-check corre antes de pedir la confirmación
		if es, en := rr.FailReason(), rr.Snapshot().ReasonEN; !strings.Contains(es, c.es) || !strings.Contains(en, c.en) || strings.Contains(es, c.no) {
			t.Errorf("es=%q en=%q", es, en)
		}
		rr.Abort()
		<-rr.Done()
	}
}
