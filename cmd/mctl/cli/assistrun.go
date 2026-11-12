// Lo que comparten las áreas de mctl que cambian equipos con el modo asistido (ADR 0007): seguir una ejecución, preguntar en cada paso y mostrar el plan.
package cli

import (
	"context"
	"errors"
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
			return "", 0, fmt.Errorf("puerto inválido %q", s[i+1:])
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
		live = " (viva)"
	}
	return fmt.Sprintf("%s  %-15s%s  equipos=%s  cambiados=%s  inicio=%s", st.RunId, st.State, live,
		strings.Join(st.Devices, ","), ch, time.Unix(st.StartedUnix, 0).Format("2006-01-02 15:04:05"))
}

func PrintPlan(w io.Writer, p *v1.AssistPlan) {
	for _, d := range p.Devices {
		fmt.Fprintf(w, "Plan para %s\n", d.Device)
		for _, sec := range []struct {
			title string
			lines []string
		}{{"Pre-check (lectura)", d.Pre}, {"Aplicar", d.Apply}, {"REVERSA (restaura lo capturado)", d.Rollback}, {"Post-check (lectura)", d.Post}} {
			fmt.Fprintf(w, "  %s:\n", sec.title)
			for _, l := range sec.lines {
				fmt.Fprintf(w, "    %s\n", l)
			}
		}
		if len(d.Notes) > 0 {
			fmt.Fprintln(w, "  Avisos:")
			for _, n := range d.Notes {
				fmt.Fprintf(w, "    %s\n", n)
			}
		}
		fmt.Fprintln(w, "  Se espera ver:")
		for _, e := range d.Expect {
			verb := "debe aparecer"
			if !e.Present {
				verb = "NO debe aparecer"
			}
			fmt.Fprintf(w, "    %s: %q (%s)\n", e.Command, e.Line, verb)
		}
	}
	if p.WriteMemory {
		fmt.Fprintln(w, "  Al final, con confirmación: write memory")
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
					fmt.Fprintln(c.Out, "\nSegundo Ctrl-C: se sale sin esperar al núcleo.")
					Exit(130)
					return
				}
				fmt.Fprintln(c.Out, "\nCtrl-C: se aborta la ejecución; no se aplicará nada más.")
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
		fmt.Fprintf(c.Out, "\nSE DETUVO: %s\n", reason)
		if !changed(ch) { // sin equipos cambiados no hay reversa que proponer
			fmt.Fprintln(c.Out, "Ningún equipo quedó cambiado.")
			return
		}
		fmt.Fprintf(c.Out, "Ya cambiados: %s.\n", strings.Join(ch, ", "))
		// Con Ctrl-C (stopped) se vuelve a pedir el Abort: el primero pudo llegar cuando el motor aún corría un paso.
		if a, stopped := ask(c, "¿Proponer la reversa de los equipos ya cambiados? [s/N] ", intr); !stopped && yes(a) {
			if _, err := cl.Rollback(ctx, &v1.RollbackRequest{RunId: runID}); err != nil {
				fmt.Fprintln(c.Out, "no se puede revertir:", err)
				abort() // sin decisión posible, no dejar la ejecución colgada
			}
		} else {
			abort()
		}
	}
	onPending := func(st *v1.AssistStep, ch []string) error {
		if st.Kind == "close" {
			fmt.Fprintf(c.Out, "\nTerminar sin guardar [%s]: el cambio queda solo en la configuración en ejecución (sin write memory). Revisa el tráfico antes de decidir.\n", st.Id)
		} else {
			what := map[string]string{"apply": "Aplicar", "save": "Guardar en NVRAM", "rollback": "Aplicar la REVERSA"}[st.Kind]
			fmt.Fprintf(c.Out, "\n%s en %s [%s]: se enviarán estas líneas\n", what, st.Device, st.Id)
		}
		for _, l := range st.Lines {
			fmt.Fprintf(c.Out, "    %s\n", l)
		}
		if st.Kind == "close" {
			// Aquí «no» es ambiguo (¿no dejarlo o no revertir?): se pregunta qué hacer y se repite.
			for range 3 {
				a, stopped := ask(c, "¿Dejas el cambio solo en ejecución? [s = dejarlo, r = revertir todo, a = abortar] ", intr)
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
		q := "¿Confirmas? [s/N] "
		if canRoll {
			q = "¿Confirmas? [s/N, r = revertir lo ya cambiado] "
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
		who := "el equipo " + strings.Join(lastChanged, ", ") + " quedó cambiado"
		if len(lastChanged) > 1 {
			who = "los equipos " + strings.Join(lastChanged, ", ") + " quedaron cambiados"
		}
		fmt.Fprintf(c.Out, "\nATENCIÓN: %s. Revisa su configuración o aplica la reversa del plan a mano.\n", who)
	}
	switch {
	case final == "done":
		fmt.Fprintln(c.Out, "\nListo: el cambio se aplicó y pasó el post-check.")
		return nil
	case final == "rolled-back": // a propósito ≠ 0: el cambio pedido no quedó aplicado (ADR 0007)
		return errors.New("el cambio se revirtió")
	case final == "abandoned":
		return errors.New("la ejecución se abandonó sin decisión")
	case failed || final == "failed":
		return errors.New("la ejecución se detuvo por un error")
	}
	return fmt.Errorf("la ejecución terminó en %s sin completarse", final)
}
