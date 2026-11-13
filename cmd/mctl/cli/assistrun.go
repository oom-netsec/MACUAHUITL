// Lo que comparten las áreas de mctl que cambian equipos con el modo asistido (ADR 0007): seguir una ejecución, preguntar en cada paso y mostrar el plan.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Interrupts da el canal de Ctrl-C y cómo dejar de escucharlo; las pruebas lo reemplazan.
var Interrupts = func() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	return ch, func() { signal.Stop(ch) }
}

// Exit termina el proceso (el segundo Ctrl-C); las pruebas lo reemplazan.
var Exit = os.Exit

// SplitHost separa HOST[:PUERTO]; sin puerto devuelve 0.
func SplitHost(s string) (string, uint32, error) {
	if i := strings.LastIndex(s, ":"); i > 0 && strings.Count(s, ":") == 1 {
		n, err := strconv.ParseUint(s[i+1:], 10, 16)
		if err != nil {
			return "", 0, Err("mctl.common_a.bad_port", "port", s[i+1:])
		}
		return s[:i], uint32(n), nil
	}
	return s, 0, nil
}

func StateLine(st *v1.AssistRunState) string {
	ch := "-"
	if len(st.Changed) > 0 {
		ch = strings.Join(st.Changed, ",")
	}
	live := ""
	if st.Active {
		live = T("mctl.run.live")
	}
	return T("mctl.run.state_line", "id", st.RunId, "state", fmt.Sprintf("%-15s", st.State), "live", live,
		"devices", strings.Join(st.Devices, ","), "changed", ch, "start", time.Unix(st.StartedUnix, 0).Format("2006-01-02 15:04:05"))
}

func PrintPlan(w io.Writer, p *v1.AssistPlan) {
	for _, d := range p.Devices {
		fmt.Fprintln(w, T("mctl.run.plan_for", "device", d.Device))
		for _, sec := range []struct {
			title string
			lines []string
		}{{T("mctl.run.pre"), d.Pre}, {T("mctl.run.apply"), d.Apply}, {T("mctl.run.rollback"), d.Rollback}, {T("mctl.run.post"), d.Post}} {
			fmt.Fprintf(w, "  %s:\n", sec.title)
			for _, l := range sec.lines {
				fmt.Fprintf(w, "    %s\n", l)
			}
		}
		if len(d.Notes) > 0 {
			fmt.Fprintln(w, T("mctl.run.notes"))
			for _, n := range d.Notes {
				fmt.Fprintf(w, "    %s\n", n)
			}
		}
		fmt.Fprintln(w, T("mctl.run.expect"))
		for _, e := range d.Expect {
			verb := T("mctl.run.must")
			if !e.Present {
				verb = T("mctl.run.must_not")
			}
			fmt.Fprintf(w, "    %s: %q (%s)\n", e.Command, e.Line, verb)
		}
	}
	if p.WriteMemory {
		fmt.Fprintln(w, T("mctl.run.write_mem"))
	}
}

// ask hace la pregunta y espera la respuesta; interrupted dice que llegó Ctrl-C antes de que hubiera una.
func ask(c *Env, q string, intr <-chan struct{}) (a string, interrupted bool) {
	fmt.Fprint(c.Out, q)
	line := make(chan string, 1)
	go func() {
		l, _ := c.In.ReadString('\n') // sin entrada = vacío = no
		line <- l
	}()
	select {
	case l := <-line:
		return strings.ToLower(strings.TrimSpace(l)), false
	case <-intr:
		return "", true
	}
}

func yes(a string) bool { return a == "s" || a == "si" || a == "sí" || a == "y" }

// Follow sigue la ejecución y pregunta en cada paso pendiente. Todo lo que no sea una afirmación
// explícita aborta: nunca se aplica nada por omisión. Ctrl-C también aborta (no deja la ejecución
// colgada) y el final avisa de los equipos que quedaron cambiados. from es el primer evento que se
// pide; first, si viene, es el estado de una ejecución retomada, cuya decisión pendiente se atiende antes.
func Follow(c *Env, cl v1.AssistServiceClient, runID string, from uint32, first *v1.AssistRunState) error {
	ctx := context.Background()
	sigs, stopSigs := Interrupts()
	defer stopSigs()
	intr, finished := make(chan struct{}), make(chan struct{})
	defer close(finished)
	abort := func() { cl.Abort(ctx, &v1.AbortRequest{RunId: runID}) } // error si ya terminó: no importa
	go func() {
		for n := 0; ; {
			select {
			case <-sigs:
				if n++; n > 1 { // el núcleo no contesta o no termina: no esperarlo
					fmt.Fprintln(c.Out, T("mctl.run.ctrlc2"))
					Exit(130)
					return
				}
				fmt.Fprintln(c.Out, T("mctl.run.ctrlc1"))
				go abort() // en otro hilo para seguir escuchando un segundo Ctrl-C
				close(intr)
			case <-finished:
				return
			}
		}
	}()
	changed := func(l []string) bool { return len(l) > 0 }
	final, failed := "", false
	var lastChanged []string
	onFail := func(reason string, ch []string) {
		failed = true
		fmt.Fprintln(c.Out, T("mctl.run.stopped", "reason", reason))
		if !changed(ch) { // sin equipos cambiados no hay reversa que proponer
			fmt.Fprintln(c.Out, T("mctl.run.none_changed"))
			return
		}
		fmt.Fprintln(c.Out, T("mctl.run.changed", "devices", strings.Join(ch, ", ")))
		// Con Ctrl-C (stopped) se vuelve a pedir el Abort: el primero pudo llegar cuando el motor aún corría un paso.
		if a, stopped := ask(c, T("mctl.run.ask_revert"), intr); !stopped && yes(a) {
			if _, err := cl.Rollback(ctx, &v1.RollbackRequest{RunId: runID}); err != nil {
				fmt.Fprintln(c.Out, T("mctl.run.cant_revert", "cause", err))
				abort() // sin decisión posible, no dejar la ejecución colgada
			}
		} else {
			abort()
		}
	}
	onPending := func(st *v1.AssistStep, ch []string) error {
		if st.Kind == "close" {
			fmt.Fprintln(c.Out, T("mctl.run.close", "id", st.Id))
		} else {
			what := map[string]string{"apply": T("mctl.run.kind_apply"), "save": T("mctl.run.kind_save"), "rollback": T("mctl.run.kind_rollback")}[st.Kind]
			fmt.Fprintln(c.Out, T("mctl.run.step", "what", what, "device", st.Device, "id", st.Id))
		}
		for _, l := range st.Lines {
			fmt.Fprintf(c.Out, "    %s\n", l)
		}
		if st.Kind == "close" {
			// Aquí «no» es ambiguo (¿no dejarlo o no revertir?): se pregunta qué hacer y se repite.
			for range 3 {
				a, stopped := ask(c, T("mctl.run.ask_close"), intr)
				switch {
				case stopped || a == "a":
					abort()
					return nil
				case yes(a):
					_, err := cl.Confirm(ctx, &v1.ConfirmRequest{RunId: runID, StepId: st.Id})
					return err
				case a == "r":
					_, err := cl.Rollback(ctx, &v1.RollbackRequest{RunId: runID})
					return err
				}
			}
			abort() // sin respuesta clara (o sin entrada): se detiene y el aviso dice qué quedó cambiado
			return nil
		}
		canRoll := st.Kind != "rollback" && changed(ch)
		q := T("mctl.run.ask_ok")
		if canRoll {
			q = T("mctl.run.ask_ok_roll")
		}
		a, stopped := ask(c, q, intr)
		var err error
		switch {
		case stopped:
			abort() // Ctrl-C ya pidió abortar; se repite por si el primer Abort llegó con el motor ocupado
			return nil
		case yes(a):
			_, err = cl.Confirm(ctx, &v1.ConfirmRequest{RunId: runID, StepId: st.Id})
		case a == "r" && canRoll:
			_, err = cl.Rollback(ctx, &v1.RollbackRequest{RunId: runID})
		default:
			_, err = cl.Abort(ctx, &v1.AbortRequest{RunId: runID})
		}
		return err
	}
	if first != nil {
		final, lastChanged = first.State, first.Changed
		switch {
		case first.Pending != nil:
			if err := onPending(first.Pending, first.Changed); err != nil {
				return err
			}
		case first.State == "failed" && first.Waiting:
			onFail(first.FailReason, first.Changed)
		}
	}
	stream, err := cl.WatchRun(ctx, &v1.WatchRunRequest{RunId: runID, FromSeq: from})
	if err != nil {
		return err
	}
	for {
		m, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		e := m.Event
		lastChanged = e.Changed
		switch e.Kind {
		case "state":
			final = e.State
			fmt.Fprintf(c.Out, "[%s]\n", e.State)
		case "output":
			fmt.Fprintf(c.Out, "%s: %s\n", e.Device, strings.TrimRight(e.Text, "\n"))
		case "fail":
			onFail(e.Text, e.Changed)
		case "pending":
			if err := onPending(e.Step, e.Changed); err != nil {
				return err
			}
		}
	}
	if changed(lastChanged) && final != "done" && final != "rolled-back" {
		code := "mctl.run.warn_one"
		if len(lastChanged) > 1 {
			code = "mctl.run.warn_many"
		}
		fmt.Fprintln(c.Out, T(code, "devices", strings.Join(lastChanged, ", ")))
	}
	switch {
	case final == "done":
		fmt.Fprintln(c.Out, T("mctl.run.done"))
		return nil
	case final == "rolled-back": // a propósito ≠ 0: el cambio pedido no quedó aplicado (ADR 0007)
		return Err("mctl.run.err_rolled")
	case final == "abandoned":
		return Err("mctl.run.err_abandoned")
	case failed || final == "failed":
		return Err("mctl.run.err_failed")
	}
	return Err("mctl.run.err_final", "state", final)
}
