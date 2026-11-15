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
	Apply    []string
	Rollback []string
	Pre      []string
	Post     []string
	Expect   []Expect
	Baseline map[string]string // el estado de antes de la ejecución
	Secrets  []string
	State    map[string]string // el estado en que la ejecución dejó el equipo (r.snap)
}

// Leftover es lo que una ejecución terminada dejó sin revertir.
type Leftover struct {
	Function string
	Scrub    bool
	Devices  []LeftDevice // en el orden en que se aplicaron
}

// Leftover devuelve los equipos que la ejecución dejó cambiados, o nil si no hay ninguno o la ejecución cambia credenciales (su reversa
// toca la bóveda y se hace a mano). Solo tiene sentido con la ejecución terminada.
func (r *Run) Leftover() *Leftover {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := &Leftover{Function: r.plan.Function, Scrub: r.fn.Scrub}
	for _, i := range r.changed {
		dp := r.plan.Devices[i]
		if dp.VerifyLogin {
			return nil
		}
		out.Devices = append(out.Devices, LeftDevice{Device: dp.Device, Apply: slices.Clone(dp.Apply), Rollback: slices.Clone(dp.Rollback),
			Pre: slices.Clone(dp.Pre), Post: slices.Clone(dp.Post), Expect: slices.Clone(dp.Expect), Baseline: cloneMap(dp.Baseline),
			Secrets: slices.Clone(dp.Secrets), State: cloneMap(r.snap[i])})
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
		dp := DevicePlan{Device: d.Device, Pre: sortedCmds(d.State), Baseline: d.State, Apply: d.Rollback, Rollback: d.Apply,
			Post: sortedCmds(d.Baseline), Secrets: d.Secrets}
		for _, c := range dp.Post {
			if txt := d.Baseline[c]; strings.TrimSpace(txt) != "" && !isStatusCmd(c) {
				dp.Expect = append(dp.Expect, Expect{Command: c, Line: txt, Present: true, Column: "same-state"})
			}
		}
		if len(dp.Expect) == 0 {
			return Plan{}, fn, cerr("assist.pending.not_verifiable", "device", d.Device)
		}
		for _, line := range append(slices.Clone(d.Apply), d.Rollback...) {
			fn.Allowed = append(fn.Allowed, strings.Join(strings.Fields(strings.ToLower(line)), " "))
		}
		plan.Devices = append(plan.Devices, dp)
	}
	return plan, fn, nil
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
