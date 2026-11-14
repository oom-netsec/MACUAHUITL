package assist

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/mask"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// DefaultDecisionTimeout es lo que el motor espera una decisión del ingeniero antes de abandonar la ejecución.
const DefaultDecisionTimeout = 30 * time.Minute

var (
	// ErrNotAssisted: regla 1; una ejecución solo existe si la petición la pidió de forma explícita.
	ErrNotAssisted = cerr("assist.not_assisted")
	ErrBadState    = cerr("assist.bad_state")
	ErrNoPending   = cerr("assist.no_pending")
	ErrWrongStep   = cerr("assist.wrong_step")
)

// Output es la salida de un comando de lectura.
type Output struct{ Command, Text string }

// Sent es una línea de configuración enviada y la respuesta del equipo.
type Sent struct {
	Line, Output string
	Failed       bool // la respuesta fue un error que detiene (% Invalid input, % Incomplete command...)
}

// Executor es lo único que el motor usa para tocar equipos; el servicio lo implementa con
// transport y platform. Debe mandar las líneas una por una y parar en el primer error.
type Executor interface {
	Read(ctx context.Context, device string, cmds []string) ([]Output, error)
	Configure(ctx context.Context, device string, lines []string) ([]Sent, error)
	Save(ctx context.Context, device string) (string, error) // write memory
	Close()
}

// Verifier lo implementa el ejecutor de una función que cambia credenciales (DevicePlan.VerifyLogin): Verify abre una sesión
// nueva con la credencial nueva (sin tocar la bóveda); Saved se llama cuando write memory salió bien y es el único momento en que la
// bóveda recibe la credencial nueva (la anterior se conserva aparte); Reverted se llama cuando la reversa se cumplió, para que la
// bóveda vuelva a como estaba. Ninguno recibe ni devuelve el secreto.
type Verifier interface {
	Verify(ctx context.Context, device string) (i18n.Text, error)
	Saved(ctx context.Context, device string) (i18n.Text, error)
	Reverted(ctx context.Context, device string) error
}

type State string

const (
	Planned        State = "planned"
	WaitingConfirm State = "waiting-confirm"
	Running        State = "running"
	Done           State = "done"
	Aborted        State = "aborted"
	Failed         State = "failed"
	RolledBack     State = "rolled-back"
	// Abandoned: nadie decidió a tiempo (o el núcleo se cerró). Los equipos cambiados siguen así; ver Changed.
	Abandoned State = "abandoned"
)

// Terminal dice si el estado ya no cambia.
func (s State) Terminal() bool {
	return s == Done || s == Aborted || s == RolledBack || s == Abandoned
}

type StepKind string

const (
	StepApply    StepKind = "apply"
	StepSave     StepKind = "save"
	StepRollback StepKind = "rollback"
	// StepClose cierra una ejecución sin write memory: el cambio queda solo en la configuración en
	// ejecución y el ingeniero decide dejarlo o revertirlo después de revisar el tráfico.
	StepClose StepKind = "close"
)

// Step es un paso que cambia la red y espera confirmación. Lines es lo exacto que se enviará.
type Step struct {
	ID     string
	Kind   StepKind
	Device string
	Lines  []string
}

type EventKind string

const (
	EvState   EventKind = "state"
	EvPending EventKind = "pending"
	EvOutput  EventKind = "output"
	EvFail    EventKind = "fail"
)

type Event struct {
	Seq    int
	Kind   EventKind
	State  State
	Step   *Step
	Device string
	Text   string
	// TextEN es el texto en inglés cuando lo hay (el motivo de un fallo y los avisos del propio motor); vacío = es salida del equipo, que no se traduce.
	TextEN string
	// Changed son los equipos que la ejecución cambió y siguen cambiados al emitirse el evento.
	Changed []string
}

type Options struct {
	ID       string
	Plan     Plan
	Fn       Function
	Assisted bool // regla 1: sin true no hay ejecución
	Exec     Executor
	Audit    func(action, target, detail string)
	// DecisionTimeout es cuánto espera el motor una decisión; al vencer la ejecución pasa a abandoned.
	// Cero = DefaultDecisionTimeout.
	DecisionTimeout time.Duration
}

type decision int

const (
	dConfirm decision = iota
	dAbort
	dRollback
	dAbandon // venció la espera o se canceló el contexto
)

type outcome int

const (
	oDone outcome = iota
	oAborted
	oFailed
	oRollback
	oAbandoned
)

// Run es una ejecución asistida: avanza sola en lo que solo lee y se detiene a esperar
// Confirm antes de cada paso que cambia la red (regla 4).
type Run struct {
	id       string
	plan     Plan
	exec     Executor
	audit    func(action, target, detail string)
	done     chan struct{}
	dec      chan decision
	mu       sync.Mutex
	state    State
	pending  *Step
	waiting  bool // el motor espera una decisión (Confirm, Abort o Rollback)
	canRoll  bool
	abort    bool  // Abort pedido mientras corría un paso
	changed  []int // equipos que siguen cambiados, en el orden en que se aplicaron
	reason   string
	reasonEN string // el mismo motivo en inglés
	inRoll   bool   // ya está revirtiendo
	log      []Event
	notify   chan struct{}
	timeout  time.Duration
	fn       Function
	secrets  []string // de todos los equipos: lo que scrub quita de todo lo que sale del motor
	// snap guarda, por equipo, la salida de los comandos de la línea base tras aplicar: si cambia antes de la reversa, alguien más tocó el puerto.
	snap map[int]map[string]string
	// recheck: equipos cuya reversa ya se mandó y no se pudo dar por buena; el reintento primero mira si ya están en su línea base.
	recheck map[int]bool
}

// NewRun valida el plan otra vez (reglas 2 y 3) y exige assisted (regla 1); no toca ningún equipo.
func NewRun(o Options) (*Run, error) {
	if !o.Assisted {
		return nil, ErrNotAssisted
	}
	if o.Exec == nil || o.Audit == nil || o.ID == "" {
		return nil, i18n.New("assist.run.missing_runner_parts", nil)
	}
	if err := Validate(o.Plan, o.Fn); err != nil {
		return nil, err
	}
	if o.DecisionTimeout <= 0 {
		o.DecisionTimeout = DefaultDecisionTimeout
	}
	var secrets []string
	for _, d := range o.Plan.Devices {
		secrets = append(secrets, d.Secrets...)
		if _, ok := o.Exec.(Verifier); d.VerifyLogin && !ok {
			return nil, cerr("assist.no_verifier")
		}
	}
	r := &Run{id: o.ID, plan: o.Plan, exec: o.Exec, state: Planned, timeout: o.DecisionTimeout, fn: o.Fn, secrets: secrets,
		snap: map[int]map[string]string{}, recheck: map[int]bool{}, done: make(chan struct{}), dec: make(chan decision, 1), notify: make(chan struct{})}
	// Único punto por el que sale la auditoría: ningún detalle lleva secretos.
	r.audit = func(action, target, detail string) { o.Audit(action, target, r.scrub(detail)) }
	return r, nil
}

// scrub quita de s los secretos del plan (y lo que IOS imprime tras secret/password si la función lo pide).
func (r *Run) scrub(s string) string { return Scrub(s, r.secrets, r.fn.Scrub) }

func (r *Run) scrubEN(s string) string { return scrubEN(s, r.secrets, r.fn.Scrub) }

func (r *Run) scrubLines(lines []string) []string { return scrubAll(lines, r.secrets, r.fn.Scrub) }

func (r *Run) ID() string            { return r.id }
func (r *Run) Done() <-chan struct{} { return r.done }

func (r *Run) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// Pending es el paso que espera confirmación, o nil.
func (r *Run) Pending() *Step {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		return nil
	}
	s := *r.pending
	return &s
}

// Changed son los equipos que la ejecución cambió y siguen cambiados (vacío si no hay o ya se revirtieron).
func (r *Run) Changed() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.changedLocked()
}

func (r *Run) changedLocked() []string {
	var out []string
	for _, i := range r.changed {
		out = append(out, r.plan.Devices[i].Device)
	}
	return out
}

// Snapshot es una foto coherente del estado de la ejecución (tomada con un solo candado).
type Snapshot struct {
	State       State
	Pending     *Step
	Reason      string
	ReasonEN    string // el motivo en inglés
	Changed     []string
	Devices     []string
	Waiting     bool // el motor espera una decisión
	CanRollback bool // Rollback es válido ahora
	Finished    bool // el motor terminó; ya no hay nada que decidir
	Events      int
}

func (r *Run) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	sn := Snapshot{State: r.state, Reason: r.reason, ReasonEN: r.reasonEN, Changed: r.changedLocked(), Waiting: r.waiting,
		CanRollback: r.waiting && r.canRoll, Events: len(r.log)}
	if r.pending != nil {
		p := *r.pending
		sn.Pending = &p
	}
	for _, d := range r.plan.Devices {
		sn.Devices = append(sn.Devices, d.Device)
	}
	select {
	case <-r.done:
		sn.Finished = true
	default:
	}
	return sn
}

// FailReason es el motivo de la parada (vacío si no falló).
func (r *Run) FailReason() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reason
}

// Events devuelve los eventos desde from y un canal que se cierra cuando haya más.
func (r *Run) Events(from int) ([]Event, <-chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if from > len(r.log) {
		from = len(r.log)
	}
	return append([]Event(nil), r.log[from:]...), r.notify
}

// emit anota un evento. Requiere r.mu.
func (r *Run) emit(e Event) {
	e.Seq = len(r.log)
	e.Text, e.TextEN = r.scrub(e.Text), r.scrubEN(e.TextEN)
	if e.Kind == EvOutput && !r.fn.Scrub { // la salida cruda de una lectura puede traer llaves y contraseñas de otras secciones del running
		e.Text, _ = mask.Apply("ios-xe", e.Text)
		if e.TextEN != "" {
			e.TextEN, _ = mask.Apply("ios-xe", e.TextEN)
		}
	}
	e.Changed = r.changedLocked()
	r.log = append(r.log, e)
	close(r.notify)
	r.notify = make(chan struct{})
}

func (r *Run) setState(s State) {
	r.mu.Lock()
	r.state = s
	r.emit(Event{Kind: EvState, State: s})
	r.mu.Unlock()
}

// outT emite un texto propio del motor (no salida del equipo) en los dos idiomas.
func (r *Run) outT(device string, t i18n.Text) {
	r.mu.Lock()
	r.emit(Event{Kind: EvOutput, Device: device, Text: t.In(i18n.Es), TextEN: t.In(i18n.En)})
	r.mu.Unlock()
}

func (r *Run) out(device, text string) {
	r.mu.Lock()
	r.emit(Event{Kind: EvOutput, Device: device, Text: text})
	r.mu.Unlock()
}

// say emite un texto del propio motor (no salida del equipo) con su versión en inglés: key del catálogo y los argumentos de cada idioma
// (difieren cuando un argumento es un texto en es; un error con código entra en inglés al texto en inglés).
func (r *Run) say(device, key string, es, en i18n.Args) {
	r.mu.Lock()
	r.emit(Event{Kind: EvOutput, Device: device, Text: i18n.Msg(i18n.Es, key, es), TextEN: i18n.Msg(i18n.En, key, en)})
	r.mu.Unlock()
}

// trim compacta y recorta una respuesta del equipo para la bitácora.
func trim(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

func (r *Run) log2(action, target, format string, a ...any) {
	r.audit(action, target, fmt.Sprintf(format, a...))
}

// Start arranca la ejecución: los pre-checks (solo lectura) corren solos y luego espera el primer Confirm.
func (r *Run) Start(ctx context.Context) {
	r.mu.Lock()
	if r.state != Planned {
		r.mu.Unlock()
		return
	}
	r.state = Running
	r.emit(Event{Kind: EvState, State: Running})
	r.mu.Unlock()
	go r.loop(ctx)
}

func (r *Run) finish(s State) {
	r.setState(s)
	r.log2("assist."+string(s), r.id, "state=%s", s)
}

func (r *Run) loop(ctx context.Context) {
	defer close(r.done)
	defer r.exec.Close()
	defer func() {
		r.mu.Lock()
		st, ch := r.state, strings.Join(r.changedLocked(), ",")
		r.mu.Unlock()
		r.log2("assist.end", r.id, "state=%s changed=%s", st, ch)
	}()
	r.log2("assist.start", r.id, "function=%s devices=%d write_memory=%t", r.plan.Function, len(r.plan.Devices), r.plan.WriteMemory)
	o := r.forward(ctx)
	if o == oFailed {
		r.mu.Lock()
		none := len(r.changed) == 0
		r.mu.Unlock()
		if none {
			return
		}
		// Regla 5: se detiene y propone la reversa; solo la ejecuta si se pide, con confirmación.
		switch r.await(ctx, nil, true) {
		case dRollback:
			o = oRollback
		case dAbandon:
			o = oAbandoned
		default:
			return // queda en failed
		}
	}
	switch o {
	case oDone:
		r.finish(Done)
	case oAborted:
		r.finish(Aborted)
	case oAbandoned:
		r.finish(Abandoned)
	case oRollback:
		r.rollback(ctx)
	}
}

// stop traduce una decisión distinta de confirmar al desenlace de la ejecución.
func stop(d decision) outcome {
	switch d {
	case dRollback:
		return oRollback
	case dAbandon:
		return oAbandoned
	}
	return oAborted
}

// await detiene el motor hasta una decisión. step nil = parada por fallo, sin paso que confirmar.
// Si nadie decide en r.timeout, o el contexto se cancela, devuelve dAbandon.
func (r *Run) await(ctx context.Context, step *Step, canRoll bool) decision {
	if step != nil {
		r.mu.Lock()
		r.pending, r.waiting = step, true
		r.canRoll = canRoll && len(r.changed) > 0
		r.state = WaitingConfirm
		r.emit(Event{Kind: EvPending, State: WaitingConfirm, Step: step, Device: step.Device})
		r.mu.Unlock()
	}
	// step nil: fail ya dejó el motor esperando, en la misma sección en que publicó el fallo.
	t := time.NewTimer(r.timeout)
	defer t.Stop()
	var why, whyEN string
	select {
	case d := <-r.dec:
		return d
	case <-ctx.Done():
		why, whyEN = "la ejecución se canceló (cierre del núcleo)", "the run was canceled (the core is closing)"
	case <-t.C:
		why, whyEN = fmt.Sprintf("nadie decidió en %s", r.timeout), fmt.Sprintf("nobody decided within %s", r.timeout)
	}
	r.mu.Lock()
	if !r.waiting { // una decisión llegó justo ahora
		r.mu.Unlock()
		return <-r.dec
	}
	r.pending, r.waiting = nil, false
	r.reason, r.reasonEN = why, whyEN
	r.mu.Unlock()
	return dAbandon
}

// Confirm autoriza el paso pendiente; id debe ser el de ese paso.
func (r *Run) Confirm(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.waiting || r.pending == nil {
		return ErrNoPending
	}
	if r.pending.ID != id {
		return newRefusal(ErrWrongStep, "assist.wrong_step_why", i18n.Tx("assist.wrong_step_why.expects", "pending", r.pending.ID, "id", id))
	}
	r.audit("assist.confirm", r.id, id)
	r.pending, r.waiting = nil, false
	r.state = Running
	r.emit(Event{Kind: EvState, State: Running})
	r.dec <- dConfirm
	return nil
}

// Abort no aplica nada más. Durante un paso en curso surte efecto al terminar ese paso.
func (r *Run) Abort() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.state == Planned:
		r.state = Aborted
		r.emit(Event{Kind: EvState, State: Aborted})
		close(r.done)
	case r.waiting:
		r.pending, r.waiting = nil, false
		r.dec <- dAbort
	case r.state == Running:
		r.abort = true
	default:
		return ErrBadState
	}
	r.audit("assist.abort", r.id, "requested by the engineer")
	return nil
}

// Rollback pide la reversa de los equipos ya cambiados, en orden inverso; cada uno pide confirmación.
func (r *Run) Rollback() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.waiting || !r.canRoll {
		return newRefusal(ErrBadState, "assist.bad_state_why", i18n.Tx("assist.bad_state_why.nothing_to_revert"))
	}
	r.pending, r.waiting = nil, false
	r.state = Running
	r.emit(Event{Kind: EvState, State: Running})
	r.audit("assist.rollback", r.id, "requested by the engineer")
	r.dec <- dRollback
	return nil
}

func (r *Run) takeAbort() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.abort
}

// failT detiene la ejecución (regla 5): el texto para la pantalla (es) y el de la auditoría, en inglés.
func (r *Run) failT(format, en string, a ...any) outcome {
	ea := make([]any, len(a)) // un error con código del catálogo entra en inglés al texto en inglés
	for i, x := range a {
		if e, ok := x.(error); ok {
			x = errIn(i18n.En, e)
		}
		ea[i] = x
	}
	return r.failMsg(fmt.Sprintf(format, a...), fmt.Sprintf(en, ea...))
}

// failMsg es failT con los dos textos ya armados.
func (r *Run) failMsg(es, en string) outcome {
	msg, msgEN := r.scrub(es), r.scrubEN(en)
	r.mu.Lock()
	r.state, r.reason, r.reasonEN = Failed, msg, msgEN
	o := oFailed
	switch {
	case r.abort: // un Abort aceptado mientras corría el paso: no hay nada que esperar
		o = oAborted
	case len(r.changed) > 0:
		// Quien vea el estado failed ya puede pedir la reversa (o reintentarla) o abortar: la espera se arma en esta misma sección.
		r.pending, r.waiting, r.canRoll = nil, true, true
	}
	r.emit(Event{Kind: EvFail, State: Failed, Text: msg, TextEN: msgEN})
	r.mu.Unlock()
	r.log2("assist.fail", r.id, "%s", en)
	return o
}

func (r *Run) read(ctx context.Context, i int, cmds []string) (map[string]string, error) {
	dev := r.plan.Devices[i].Device
	outs, err := r.exec.Read(ctx, dev, cmds)
	m := map[string]string{}
	for _, o := range outs {
		m[o.Command] = o.Text
		r.log2("assist.read", dev, "run=%s command=%s", r.id, o.Command)
		r.out(dev, "$ "+o.Command+"\n"+o.Text)
	}
	return m, err
}

// sent audita cada línea enviada con su respuesta (regla 6) y dice cuál falló.
func (r *Run) sent(dev string, sent []Sent) (failed, failedEN string) {
	for _, s := range sent {
		r.log2("assist.line", dev, "run=%s line=%s response=%s", r.id, s.Line, trim(s.Output))
		r.out(dev, "> "+s.Line+"\n"+s.Output)
		if s.Failed && failed == "" {
			failed = fmt.Sprintf("el equipo %s rechazó %q: %s", dev, s.Line, trim(s.Output))
			failedEN = fmt.Sprintf("device %s rejected %q: %s", dev, s.Line, trim(s.Output))
		}
	}
	return failed, failedEN
}

func (r *Run) forward(ctx context.Context) outcome {
	for i, dp := range r.plan.Devices {
		outs, err := r.read(ctx, i, dp.Pre)
		if err != nil {
			return r.failT("pre-check de %s: %v", "pre-check of %s: %v", dp.Device, err)
		}
		for cmd, was := range dp.Baseline {
			if !sameOut(cmd, outs[cmd], was) {
				return r.failT("%s cambió desde que se hizo el plan (%s); vuelve a planear", "%s changed since the plan was made (%s); plan again", dp.Device, cmd)
			}
		}
		if r.takeAbort() {
			return oAborted
		}
	}
	for i := range r.plan.Devices {
		if o, stop := r.applyOne(ctx, i); stop {
			return o
		}
	}
	if r.plan.WriteMemory { // regla 7: solo si el plan lo pide, al final y con confirmación
		for i, dp := range r.plan.Devices {
			step := Step{ID: fmt.Sprintf("save-%d", i+1), Kind: StepSave, Device: dp.Device, Lines: []string{"write memory"}}
			if d := r.await(ctx, &step, true); d != dConfirm {
				if d == dAbort && dp.VerifyLogin {
					// Sin write memory el equipo vuelve al hash anterior al reiniciar: no se da por terminada, se propone la reversa.
					return r.failT("write memory rechazado en %s: la credencial nueva solo está en la configuración en ejecución y se perdería al reiniciar; propón la reversa", "write memory refused on %s: the new credential is only in the running configuration and would be lost on reload; propose the rollback", dp.Device)
				}
				return stop(d)
			}
			text, err := r.exec.Save(ctx, dp.Device)
			r.log2("assist.save", dp.Device, "run=%s response=%s", r.id, trim(text))
			if err != nil {
				return r.failT("write memory en %s: %v", "write memory on %s: %v", dp.Device, err)
			}
			r.out(dp.Device, "> write memory\n"+text)
			if dp.VerifyLogin { // solo ahora la bóveda recibe la credencial nueva
				msg, err := r.exec.(Verifier).Saved(ctx, dp.Device)
				if err != nil {
					r.log2("assist.verify", dp.Device, "run=%s the vault was not updated after write memory", r.id)
					return r.failT("write memory salió bien en %s pero la bóveda no quedó con la credencial nueva: %v; edítala a mano", "write memory succeeded on %s but the vault does not hold the new credential: %v; edit it by hand", dp.Device, err)
				}
				r.outT(dp.Device, msg)
			}
		}
	} else {
		step := Step{ID: "close", Kind: StepClose}
		if d := r.await(ctx, &step, true); d != dConfirm {
			return stop(d)
		}
	}
	return oDone
}

// applyOne confirma, aplica y verifica un equipo. stop dice si la ejecución no continúa.
func (r *Run) applyOne(ctx context.Context, i int) (outcome, bool) {
	dp := r.plan.Devices[i]
	step := Step{ID: fmt.Sprintf("apply-%d", i+1), Kind: StepApply, Device: dp.Device, Lines: r.scrubLines(dp.Apply)}
	if d := r.await(ctx, &step, true); d != dConfirm {
		return stop(d), true
	}
	// Otra vez la línea base, ya con la confirmación dada: el equipo pudo cambiar mientras se decidía.
	if msg, en := r.drift(ctx, i, dp.Baseline, "desde que se hizo el plan", "since the plan was made"); msg != "" {
		return r.failMsg(msg, en), true
	}
	// Desde aquí el equipo puede haber cambiado, aunque la línea que falle sea la primera.
	r.mu.Lock()
	r.changed = append(r.changed, i)
	r.mu.Unlock()
	sent, err := r.exec.Configure(ctx, dp.Device, dp.Apply)
	if len(sent) == 0 { // ninguna línea llegó a mandarse (no se pudo conectar ni entrar a configuración): el equipo sigue igual
		r.unchange(i)
	}
	failed, failedEN := r.sent(dp.Device, sent)
	if (err != nil || failed != "") && len(sent) > 0 {
		r.resync(ctx, i) // lo que quedó a medias es la referencia de una reversa tardía
	}
	if err != nil {
		return r.failT("configuración de %s: %v", "configuration of %s: %v", dp.Device, err), true
	}
	if failed != "" {
		return r.failMsg(failed, failedEN), true
	}
	outs, err := r.read(ctx, i, dp.Post)
	r.remember(i, dp.Baseline, outs)
	if err != nil {
		return r.failT("post-check de %s: %v", "post-check of %s: %v", dp.Device, err), true
	}
	if fails := evalExpect(dp.Expect, outs); len(fails) > 0 {
		join := func(loc string) string {
			parts := make([]string, len(fails))
			for i, f := range fails {
				parts[i] = f.In(loc)
			}
			return strings.Join(parts, "; ")
		}
		return r.failMsg(fmt.Sprintf("el post-check de %s no cumple lo esperado: %s", dp.Device, join(i18n.Es)),
			fmt.Sprintf("the post-check of %s does not meet expectations: %s", dp.Device, join(i18n.En))), true
	}
	if dp.VerifyLogin { // sesión nueva con la credencial nueva: si no entra, la original sigue abierta para revertir
		msg, err := r.exec.(Verifier).Verify(ctx, dp.Device)
		if err != nil {
			r.log2("assist.verify", dp.Device, "run=%s result=failed", r.id)
			return r.failT("la credencial nueva no entró a %s con una sesión nueva: %v; la sesión original sigue abierta: propón la reversa", "the new credential did not log in to %s with a new session: %v; the original session is still open: propose the rollback", dp.Device, err), true
		}
		r.log2("assist.verify", dp.Device, "run=%s result=ok", r.id)
		r.outT(dp.Device, msg)
	}
	if r.takeAbort() {
		return oAborted, true
	}
	return 0, false
}

// remember guarda la salida de los comandos de la línea base tras aplicar, para detectar luego que alguien más tocó el equipo.
func (r *Run) remember(i int, base map[string]string, outs map[string]string) {
	m := map[string]string{}
	for cmd := range base {
		if t, ok := outs[cmd]; ok {
			m[cmd] = t
		}
	}
	r.mu.Lock()
	r.snap[i] = m
	r.mu.Unlock()
}

func (r *Run) unchange(i int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, c := range r.changed {
		if c == i {
			r.changed = append(r.changed[:k:k], r.changed[k+1:]...)
			return
		}
	}
}

func sortedCmds(m map[string]string) []string {
	cmds := make([]string, 0, len(m))
	for c := range m {
		cmds = append(cmds, c)
	}
	sort.Strings(cmds)
	return cmds
}

// resync relee los comandos de la línea base y los guarda como lo último que se vio del equipo
// (tras una escritura cortada a mitad); dice si ya coinciden con la línea base del plan.
func (r *Run) resync(ctx context.Context, i int) bool {
	dp := r.plan.Devices[i]
	if len(dp.Baseline) == 0 {
		return false
	}
	outs, err := r.read(ctx, i, sortedCmds(dp.Baseline))
	if err != nil { // sin lectura completa se conserva la referencia anterior (lo seguro es no pisar)
		return false
	}
	r.remember(i, dp.Baseline, outs)
	for c, want := range dp.Baseline {
		if !sameOut(c, outs[c], want) {
			return false
		}
	}
	return true
}

// drift relee los comandos de want y dice (no vacío) si alguno ya no da lo mismo.
func (r *Run) drift(ctx context.Context, i int, want map[string]string, since, sinceEN string) (es, en string) {
	if len(want) == 0 {
		return "", ""
	}
	cmds := sortedCmds(want)
	dev := r.plan.Devices[i].Device
	outs, err := r.read(ctx, i, cmds)
	if err != nil {
		return fmt.Sprintf("no se pudo verificar %s antes de continuar: %v", dev, err), fmt.Sprintf("could not verify %s before continuing: %v", dev, err)
	}
	for _, c := range cmds {
		if !sameOut(c, outs[c], want[c]) {
			return fmt.Sprintf("%s cambió %s (%s)", dev, since, c), fmt.Sprintf("%s changed %s (%s)", dev, sinceEN, c)
		}
	}
	return "", ""
}

// rollback aplica la reversa de los equipos cambiados, del último al primero, con confirmación.
func (r *Run) rollback(ctx context.Context) {
	r.mu.Lock()
	r.inRoll = true
	order := append([]int(nil), r.changed...)
	r.mu.Unlock()
	for k := len(order) - 1; k >= 0; k-- {
		if !r.rollbackOne(ctx, order[k]) {
			return
		}
	}
	r.finish(RolledBack)
}

// rollbackOne confirma y aplica la reversa de un equipo. Si falla se queda esperando una decisión:
// reintentar (Rollback) o abortar. false = la ejecución terminó aquí.
func (r *Run) rollbackOne(ctx context.Context, i int) bool {
	dp := r.plan.Devices[i]
	step := Step{ID: fmt.Sprintf("rollback-%d", i+1), Kind: StepRollback, Device: dp.Device, Lines: r.scrubLines(dp.Rollback)}
	for {
		if r.takeAbort() { // un Abort aceptado mientras corría la reversa anterior
			r.finishFor(dAbort)
			return false
		}
		if d := r.await(ctx, &step, false); d != dConfirm {
			r.finishFor(d)
			return false
		}
		// Quien corrigió a mano lo que dejó una reversa anterior ya lo tiene en su línea base: no hay nada que mandar.
		r.mu.Lock()
		again := r.recheck[i]
		r.mu.Unlock()
		if again {
			if _, diffs, err := r.checkBase(ctx, i, nil); err == nil && len(diffs) == 0 {
				r.say(dp.Device, "assist.run.matches_baseline", nil, nil)
				r.reverted(ctx, dp)
				r.unchange(i)
				return true
			}
		}
		r.mu.Lock()
		was := r.snap[i]
		r.mu.Unlock()
		if msg, en := r.drift(ctx, i, was, "desde nuestro cambio; la reversa pisaría un cambio ajeno", "since our change; the rollback would overwrite someone else's change"); msg != "" {
			r.failMsg(msg, en)
		} else if r.revert(ctx, i) {
			return true
		}
		if r.takeAbort() { // fail no armó la espera: el Abort ya estaba puesto
			r.finishFor(dAbort)
			return false
		}
		if d := r.await(ctx, nil, true); d != dRollback {
			r.finishFor(d)
			return false
		}
	}
}

func (r *Run) finishFor(d decision) {
	if d == dAbandon {
		r.finish(Abandoned)
	} else {
		r.finish(Aborted)
	}
}

// revert manda la reversa; false si falló (r.fail ya dejó el motor esperando).
func (r *Run) revert(ctx context.Context, i int) bool {
	dp := r.plan.Devices[i]
	sent, err := r.exec.Configure(ctx, dp.Device, dp.Rollback)
	failed, failedEN := r.sent(dp.Device, sent)
	if err != nil {
		failed, failedEN = fmt.Sprintf("reversa de %s: %v", dp.Device, err), fmt.Sprintf("rollback of %s: %v", dp.Device, i18n.English(err))
	}
	if failed != "" {
		// Si se mandó alguna línea, el equipo ya no está como lo dejó el apply: se relee para que un reintento
		// no lo tome por un cambio ajeno, y si ya coincide con la línea base la reversa sí se cumplió.
		if len(sent) > 0 && r.resync(ctx, i) {
			r.log2("assist.rollback", dp.Device, "run=%s the rollback failed (%s) but the device already matches the baseline", r.id, trim(failedEN))
			r.say(dp.Device, "assist.run.rollback_failed_matches", i18n.A("failed", trim(failed)), i18n.A("failed", trim(failedEN)))
			r.reverted(ctx, dp)
			r.unchange(i)
			return true
		}
		r.failMsg(failed, failedEN)
		return false
	}
	// Evidencia del estado devuelto, y el running-config de la línea base para ver que la reversa de verdad lo dejó igual
	// (p. ej. IOS agrega solo líneas al aplicar que la reversa no conoce).
	if outs, diffs, err := r.checkBase(ctx, i, dp.Post); err != nil {
		if len(runningCmds(dp)) > 0 {
			r.setRecheck(i)
			r.failT("no se pudo verificar la reversa de %s: %v; reintenta la reversa o revísalo a mano", "could not verify the rollback of %s: %v; retry the rollback or check it by hand", dp.Device, err)
			return false
		}
		r.say(dp.Device, "assist.run.post_check_after_rollback", i18n.A("error", err.Error()), i18n.A("error", i18n.English(err)))
	} else if len(diffs) > 0 {
		r.remember(i, dp.Baseline, outs) // un reintento parte de aquí, no lo toma por un cambio ajeno
		r.setRecheck(i)
		d := i18n.Join("; ", diffs...)
		r.failMsg(fmt.Sprintf("la reversa de %s no lo dejó como estaba (%s); reintenta la reversa o corrígelo a mano", dp.Device, d.In(i18n.Es)),
			fmt.Sprintf("the rollback of %s did not restore it (%s); retry the rollback or fix it by hand", dp.Device, d.In(i18n.En)))
		return false
	}
	r.reverted(ctx, dp)
	r.unchange(i)
	return true
}

func (r *Run) setRecheck(i int) {
	r.mu.Lock()
	r.recheck[i] = true
	r.mu.Unlock()
}

// snmpUserCmd muestra los usuarios SNMPv3, que IOS no escribe en el running-config: la línea base de snmpv3-usuario lo compara igual.
const snmpUserCmd = "show snmp user"

// runningCmds son los comandos de la línea base que muestran configuración (no estado operativo), ordenados.
func runningCmds(dp DevicePlan) []string {
	return slices.DeleteFunc(sortedCmds(dp.Baseline), func(c string) bool { return !strings.HasPrefix(c, "show running-config") && c != snmpUserCmd })
}

// isStatusCmd: `show interfaces X status`, el estado de un puerto. Sube y baja solo, así que no cuenta como «el equipo cambió»: la línea
// base lo guarda únicamente para ver, tras la reversa, que el puerto no quedó err-disabled sin estarlo antes (checkBase).
func isStatusCmd(c string) bool {
	return strings.HasPrefix(c, "show interfaces ") && strings.HasSuffix(c, " status")
}

// sameOut dice si dos lecturas de cmd son la misma para la comparación con la línea base.
func sameOut(cmd, a, b string) bool { return isStatusCmd(cmd) || normalize(a) == normalize(b) }

func statusCmds(dp DevicePlan) []string {
	return slices.DeleteFunc(sortedCmds(dp.Baseline), func(c string) bool { return !isStatusCmd(c) })
}

// checkBase lee cmds, el running-config de la línea base y el estado de sus puertos, y dice qué quedó distinto de ella (diffs vacío = igual).
func (r *Run) checkBase(ctx context.Context, i int, cmds []string) (map[string]string, []i18n.Text, error) {
	dp := r.plan.Devices[i]
	run := runningCmds(dp)
	cmds = slices.Clone(cmds)
	for _, c := range append(slices.Clone(run), statusCmds(dp)...) {
		if !slices.Contains(cmds, c) {
			cmds = append(cmds, c)
		}
	}
	outs, err := r.read(ctx, i, cmds)
	if err != nil {
		return nil, nil, err
	}
	var diffs []i18n.Text
	for _, c := range run {
		got, ok := outs[c]
		if !ok {
			return nil, nil, cerr("assist.err.output_not_received", "command", c)
		}
		if d := residueT(dp.Baseline[c], got); !d.Empty() {
			diffs = append(diffs, i18n.Tx("assist.residue.cmd", "command", c).With("residue", d))
		}
	}
	for _, c := range statusCmds(dp) {
		got, ok := outs[c]
		if !ok {
			return nil, nil, cerr("assist.err.output_not_received", "command", c)
		}
		now, _ := iosxe.ParseIfStatus(got)
		if len(now) == 0 {
			return nil, nil, cerr("assist.err.port_status_unreadable", "command", c)
		}
		was, _ := iosxe.ParseIfStatus(dp.Baseline[c])
		if now[0].Status == "err-disabled" && (len(was) == 0 || was[0].Status != "err-disabled") {
			diffs = append(diffs, i18n.Tx("assist.residue.err_disabled", "port", now[0].Port))
		}
	}
	return outs, diffs, nil
}

// residueT dice qué líneas sobran y cuáles faltan en got respecto de want (vacío si coinciden). Sin importar el orden; cada línea
// con sangría cuenta junto con su sección, para que el « shutdown» de una interfaz no tape el que falta en otra.
func residueT(want, got string) i18n.Text {
	// shortcut: las secciones anidadas (address-family) cuentan bajo el encabezado de primer nivel y el orden no cuenta, así que
	// una reversa que reordena las entradas de una ACL pasa por igual; habría que comparar por secuencia si llega a importar.
	count := func(s string) map[string]int {
		m, head := map[string]int{}, ""
		for _, raw := range strings.Split(s, "\n") {
			l := strings.TrimSpace(raw)
			switch {
			case skipLine(l):
			case raw[0] != ' ' && raw[0] != '\t':
				head = l
				m[l]++
			default:
				m[l+"\x00"+head]++
			}
		}
		return m
	}
	w, g := count(want), count(got)
	keys := slices.Sorted(maps.Keys(w))
	for k := range g {
		if _, ok := w[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var out []i18n.Text
	for _, k := range keys {
		if g[k] == w[k] {
			continue
		}
		what := "missing"
		if g[k] > w[k] {
			what = "extra"
		}
		line, head, ok := strings.Cut(k, "\x00")
		if ok {
			out = append(out, i18n.Tx("assist.residue."+what+"_in").With("line", shown(head, line)).With("head", shown("", head)))
		} else {
			out = append(out, i18n.Tx("assist.residue."+what).With("line", shown("", line)))
		}
	}
	if len(out) > 5 {
		out = append(out[:5], i18n.Tx("assist.residue.more", "n", len(out)-5))
	}
	return i18n.Join(", ", out...)
}

// residue es residueT en español (lo que ven las pruebas y los mensajes de siempre).
func residue(want, got string) string { return residueT(want, got).In(i18n.Es) }

// reverted avisa al ejecutor que la reversa de una rotación se cumplió. Si no puede dejar la bóveda como estaba, lo dice: el equipo ya
// volvió a la credencial anterior y eso es lo que importa decirle al ingeniero.
func (r *Run) reverted(ctx context.Context, dp DevicePlan) {
	if !dp.VerifyLogin {
		return
	}
	if err := r.exec.(Verifier).Reverted(ctx, dp.Device); err != nil {
		r.log2("assist.verify", dp.Device, "run=%s the vault did not return to the previous credential: %v", r.id, i18n.English(err))
		r.say(dp.Device, "assist.run.vault_not_restored", i18n.A("error", err.Error()), i18n.A("error", i18n.English(err)))
	}
}

var matchesRe = regexp.MustCompile(`\s*\(\d+ match(?:es)?\)\s*$`)

// normalize quita lo que cambia entre lecturas del mismo equipo sin que cambie su configuración.
func normalize(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); !skipLine(l) {
			keep = append(keep, matchesRe.ReplaceAllString(l, "")) // los contadores de show ip access-lists suben solos
		}
	}
	return strings.Join(keep, "\n")
}

// skipLine: lo que cambia solo entre dos lecturas del running-config (comentarios con hora, el reloj de NTP y el tamaño); l ya va sin espacios.
func skipLine(l string) bool {
	return l == "" || strings.HasPrefix(l, "!") || strings.HasPrefix(l, "Building configuration") || strings.HasPrefix(l, "Current configuration") ||
		strings.HasPrefix(l, "ntp clock-period") || strings.HasPrefix(l, "Using ") && strings.Contains(l, " out of ")
}

// shown enmascara una línea de configuración para un mensaje: las reglas de mask anclan al inicio de línea y a su sección.
func shown(head, line string) i18n.Text {
	if head == "" {
		m, _ := mask.Apply("ios-xe", line+"\n")
		return i18n.Lit(strings.TrimSpace(m), "")
	}
	m, _ := mask.Apply("ios-xe", head+"\n "+line+"\n")
	_, l, _ := strings.Cut(strings.TrimRight(m, "\n"), "\n")
	if l = strings.TrimSpace(l); l == "" {
		return i18n.Tx("assist.residue.hidden")
	}
	return i18n.Lit(l, "")
}
