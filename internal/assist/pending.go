package assist

import (
	"slices"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// PendingFunction es el nombre de la función de una reversa pendiente: su lista cerrada son exactamente las líneas guardadas.
const PendingFunction = "pending-rollback"

// LeftDevice es lo que hace falta para revertir un equipo que una ejecución dejó cambiado.
type LeftDevice struct {
	Device   string
	Apply    []string // lo que el equipo aceptó del apply (el plan entero si no se cortó)
	Rollback []string
	Pre      []string
	Post     []string
	Expect   []Expect
	Baseline map[string]string // el estado de antes de la ejecución
	Secrets  []string
	State    map[string]string // el estado en que la ejecución dejó el equipo (r.snap; mientras Configure corre, la línea base)
}

// Leftover es lo que una ejecución terminada dejó sin revertir.
type Leftover struct {
	Function string
	Scrub    bool
	// WriteMemory: la ejecución pedía write memory; si falló tras escribir, la startup-config puede conservar el cambio.
	WriteMemory bool
	Devices     []LeftDevice // en el orden en que se aplicaron
}

// Leftover devuelve los equipos que la ejecución dejó cambiados, o nil si no hay ninguno. Una rotación de credencial cuya bóveda ya
// recibió el secreto nuevo (write memory salió bien) no cuenta: revertirla dejaría la bóveda desfasada. Una rotación sin terminar
// (abortada, vencida, con el login nuevo fallido) sí: la bóveda aún guarda el secreto anterior, que es el que la reversa devuelve al equipo.
func (r *Run) Leftover() *Leftover {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := &Leftover{Function: r.plan.Function, Scrub: r.fn.Scrub, WriteMemory: r.plan.WriteMemory}
	for _, i := range r.changed {
		dp := r.plan.Devices[i]
		if dp.VerifyLogin && r.vaulted[i] {
			continue
		}
		// La reversa guardada es la que se mostraría en vivo: recortada a lo aplicado si el apply quedó a medias (con r.mu
		// tomado no se puede llamar a rollbackLines). Si el recorte queda vacío se guarda la completa: RollbackPlan exige líneas.
		rb := dp.Rollback
		if ok, cut := r.partial[i]; cut && r.fn.Undo != nil {
			if u := r.fn.Undo(dp.Rollback, ok); len(u) > 0 {
				rb = u
			}
		}
		// Apply guarda lo que el equipo aceptó, no el plan entero: es la «reversa de la reversa» y no debe crear objetos que nunca existieron.
		ap := dp.Apply
		if ok, cut := r.partial[i]; cut && len(ok) > 0 {
			ap = ok
		}
		state := r.snap[i]
		if state == nil { // Configure sigue o la relectura falló: la línea base es el único estado conocido
			state = r.prov[i]
		}
		out.Devices = append(out.Devices, LeftDevice{Device: dp.Device, Apply: slices.Clone(ap), Rollback: slices.Clone(rb),
			Pre: slices.Clone(dp.Pre), Post: slices.Clone(dp.Post), Expect: slices.Clone(dp.Expect), Baseline: cloneMap(dp.Baseline),
			Secrets: slices.Clone(dp.Secrets), State: cloneMap(state)})
	}
	if len(out.Devices) == 0 {
		return nil
	}
	return out
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// RollbackPlan arma el plan que revierte un Leftover. Por equipo, del último al primero que se aplicó:
//   - Pre y Baseline son el estado que dejó la ejecución: si el equipo ya no lo da, el motor se detiene sin cambiar nada (pre-check);
//   - Apply es la reversa original y Rollback el Apply original (revertir la reversa);
//   - Post y Expect verifican la vuelta al estado de antes (la Baseline original, columna same-state); no hay write memory.
//
// La función solo acepta exactamente las líneas guardadas.
func RollbackPlan(l Leftover) (Plan, Function, error) {
	fn := Function{Name: PendingFunction, Scrub: l.Scrub}
	plan := Plan{Function: PendingFunction}
	for k := len(l.Devices) - 1; k >= 0; k-- {
		d := l.Devices[k]
		if len(d.State) == 0 {
			return Plan{}, fn, cerr("assist.pending.no_state", "device", d.Device)
		}
		// Un State a medias (se cortó la lectura del post-check) dejaría sin pre-check a un equipo que otro pudo cambiar: se exige completo.
		for c := range d.Baseline {
			if _, ok := d.State[c]; !ok && !isStatusCmd(c) && slices.Contains(d.Post, c) {
				return Plan{}, fn, cerr("assist.pending.no_state", "device", d.Device)
			}
		}
		dp := DevicePlan{Device: d.Device, Pre: sortedCmds(d.State), Baseline: d.State, Apply: d.Rollback, Rollback: d.Apply, Secrets: d.Secrets}
		// La vuelta se verifica solo con configuración (running-config, show snmp user): la salida de comandos operativos cambia sin que nadie toque el equipo.
		// Una línea base vacía también cuenta: «no había nada» (p. ej. ninguna línea snmp-server) es un estado que se puede verificar.
		for _, c := range sortedCmds(d.Baseline) {
			if txt := d.Baseline[c]; isConfigCmd(c) {
				dp.Post = append(dp.Post, c)
				dp.Expect = append(dp.Expect, Expect{Command: c, Line: txt, Present: true, Column: "same-state"})
			}
		}
		if len(dp.Expect) == 0 {
			return Plan{}, fn, cerr("assist.pending.not_verifiable", "device", d.Device)
		}
		if l.WriteMemory {
			n := note("assist.pending.write_memory")
			dp.NoteItems, dp.Notes = []i18n.Text{n}, []string{n.In(i18n.Es)}
		}
		for _, line := range append(slices.Clone(d.Apply), d.Rollback...) {
			fn.Allowed = append(fn.Allowed, strings.Join(strings.Fields(strings.ToLower(line)), " "))
		}
		plan.Devices = append(plan.Devices, dp)
	}
	return plan, fn, nil
}

func isConfigCmd(c string) bool {
	return strings.HasPrefix(c, "show running-config") || c == snmpUserCmd
}

// sameState dice si got es el estado want de cmd; para el running-config usa la misma comparación que la reversa del motor
// (residueT, sin importar el orden) y devuelve qué difiere.
func sameState(cmd, want, got string) (bool, i18n.Text) {
	if strings.HasPrefix(cmd, "show running-config") || cmd == snmpUserCmd {
		d := residueT(want, got)
		return d.Empty(), d
	}
	return sameOut(cmd, got, want), i18n.Text{}
}

// ScrubLines da las líneas sin los secretos (y lo que IOS imprime tras secret/password si generic), listas para mostrarse.
func ScrubLines(lines, secrets []string, generic bool) []string {
	return scrubAll(lines, secrets, generic)
}
