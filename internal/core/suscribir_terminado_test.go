package core

import (
	"context"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/engine"
	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
)

func (h *harness) jobClosed(job string) bool {
	h.core.mu.Lock()
	defer h.core.mu.Unlock()
	return h.core.jobs[job].closed
}

// closedJob arma, cancela y espera a que el trabajo cierre de verdad (manifest y zip hechos).
func (h *harness) closedJob(t *testing.T, cred string) string {
	t.Helper()
	job, _ := h.arm(t, cred)
	if _, err := h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: job}); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(30 * time.Second); !h.jobClosed(job); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("el trabajo no cerró")
		}
	}
	return job
}

// Suscribirse a un trabajo ya cerrado manda su estado final y un closed con hora, y cierra el stream.
func TestSubscribeATrabajoCerradoMandaFinalYClosedYCierra(t *testing.T) { suscribirCerrado(t, 1) }

// Con el mismo id repetido en la petición, el cierre por «todos cerrados» funciona igual.
func TestSubscribeConIdRepetidoDeTrabajoCerradoCierra(t *testing.T) { suscribirCerrado(t, 2) }

func suscribirCerrado(t *testing.T, veces int) {
	t.Helper()
	h := newHarness(t, nil)
	job := h.closedJob(t, h.ready(t))
	c, stop := context.WithTimeout(ctx(t), 5*time.Second)
	defer stop()
	s, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: slices.Repeat([]string{job}, veces)})
	if err != nil {
		t.Fatal(err)
	}
	var states []string
	for {
		e, err := s.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("el stream debía terminar: %v (eventos %v)", err, states)
		}
		if e.JobId != job || e.At == nil || e.At.AsTime().IsZero() {
			t.Fatalf("evento sin trabajo u hora: %v", e)
		}
		states = append(states, e.GetJobStateChanged().GetState())
	}
	if !slices.Equal(states, []string{"cancelled", "closed"}) {
		t.Fatalf("eventos = %v", states)
	}
}

// Un Subscribe que llega mientras finish corre (estado final puesto, closed aún no) no se cierra: con el closed del bus
// recibe antes el estado final que se perdió.
func TestSubscribeDuranteFinishRecibeClosed(t *testing.T) {
	h := newHarness(t, nil)
	job, _ := h.created(t, h.ready(t), nil)
	h.core.mu.Lock()
	h.core.jobs[job].state = "completed" // finish en curso: estado puesto, manifest y zip pendientes
	h.core.mu.Unlock()
	c, stop := context.WithTimeout(ctx(t), 10*time.Second)
	defer stop()
	s, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: []string{job}})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 4)
	go func() {
		for {
			e, err := s.Recv()
			if err != nil {
				got <- "fin:" + err.Error()
				return
			}
			got <- e.GetJobStateChanged().GetState()
		}
	}()
	select {
	case m := <-got:
		t.Fatalf("antes del closed llegó %q (cerró el stream o mandó un final)", m)
	case <-time.After(500 * time.Millisecond):
	}
	h.core.mu.Lock()
	h.core.jobs[job].closed = true
	h.core.mu.Unlock()
	h.core.bus.Publish(engine.Event{JobID: job, Kind: engine.JobState, State: "closed"})
	for _, want := range []string{"completed", "closed"} {
		if m := <-got; m != want {
			t.Fatalf("llegó %q, quería %q", m, want)
		}
	}
}

// Cancelar un trabajo creado (que nunca pasa por finish) publica cancelled y closed, y un Subscribe tardío lo ve cerrado.
func TestCancelJobCreadoPublicaCancelledYClosed(t *testing.T) {
	h := newHarness(t, nil)
	job, _ := h.created(t, h.ready(t), nil)
	c, stop := context.WithTimeout(ctx(t), 10*time.Second)
	defer stop()
	s, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: []string{job}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: job}); err != nil {
		t.Fatal(err)
	}
	var states []string
	for len(states) < 2 || states[len(states)-1] != "closed" {
		e, err := s.Recv()
		if err != nil {
			t.Fatalf("%v (eventos %v)", err, states)
		}
		if js := e.GetJobStateChanged(); js != nil {
			states = append(states, js.State)
		}
	}
	if !slices.Equal(states, []string{"cancelled", "closed"}) {
		t.Fatalf("eventos = %v", states)
	}
	s2, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: []string{job}})
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := s2.Recv(); err != nil {
			if err != io.EOF {
				t.Fatal(err)
			}
			break
		}
	}
}

// Con un trabajo real: tras el estado final llegan las fases de empaquetado y el closed, en ese orden.
func TestTrabajoRealEmiteEmpaquetadoAntesDeClosed(t *testing.T) {
	h := newHarness(t, nil)
	job, _ := h.arm(t, h.ready(t))
	c, stop := context.WithTimeout(ctx(t), 30*time.Second)
	defer stop()
	s, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: []string{job}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: job}); err != nil {
		t.Fatal(err)
	}
	var seq []string
	for {
		e, err := s.Recv()
		if err != nil {
			t.Fatalf("%v (eventos %v)", err, seq)
		}
		if js := e.GetJobStateChanged(); js != nil {
			seq = append(seq, js.State)
			if js.State == "closed" {
				break
			}
		}
		if p := e.GetPhaseAdded(); p != nil {
			seq = append(seq, p.Kind.String())
		}
	}
	iPack, iClosed := slices.Index(seq, "JOB_PHASE_KIND_PACKAGED"), slices.Index(seq, "closed")
	if iPack < 0 || iPack > iClosed || slices.Index(seq, "JOB_PHASE_KIND_CANCELLED") > iClosed {
		t.Fatalf("orden = %v", seq)
	}
}

// recvStates lee el stream hasta EOF y devuelve "<id>:<estado>" de cada jobStateChanged.
func recvStates(t *testing.T, s v1.EventService_SubscribeClient) []string {
	t.Helper()
	var out []string
	for {
		e, err := s.Recv()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("el stream debía terminar: %v (eventos %v)", err, out)
		}
		if js := e.GetJobStateChanged(); js != nil {
			out = append(out, e.JobId+":"+js.State)
		}
	}
}

// Un trabajo cancelado mientras se arma (cancelReq puesto por CancelJob) nunca pasa por finish: ArmJob lo cierra con
// cancelled y closed por las dos ramas (armado fallido, o cancelReq visto antes de armar en el planificador).
func TestCancelDuranteElArmadoPublicaCancelledYClosed(t *testing.T) {
	for nombre, excluirTodo := range map[string]bool{"armado fallido": true, "antes de armar": false} {
		t.Run(nombre, func(t *testing.T) {
			h := newHarness(t, nil)
			job, fp := h.created(t, h.ready(t), nil)
			c, stop := context.WithTimeout(ctx(t), 20*time.Second)
			defer stop()
			vivo, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: []string{job}}) // ya suscrito antes de armar
			if err != nil {
				t.Fatal(err)
			}
			h.core.mu.Lock()
			h.core.jobs[job].cancelReq = true // lo que deja un CancelJob llegado durante el armado
			h.core.mu.Unlock()
			req := &v1.ArmJobRequest{JobId: job, AcceptedHostKeyFingerprints: []string{fp}}
			if excluirTodo {
				req.ExcludedDeviceIds = []string{h.target.Address}
			}
			if _, err := h.patrol.ArmJob(ctx(t), req); err == nil {
				t.Fatal("ArmJob debía fallar")
			}
			want := []string{job + ":cancelled", job + ":closed"}
			if got := recvStates(t, vivo); !slices.Equal(got, want) {
				t.Fatalf("el watch ya suscrito vio %v", got)
			}
			tardio, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: []string{job}})
			if err != nil {
				t.Fatal(err)
			}
			if got := recvStates(t, tardio); !slices.Equal(got, want) {
				t.Fatalf("el Subscribe tardío vio %v", got)
			}
		})
	}
}

// Con varios ids: el sintético de un trabajo ya cerrado no se repite por el bus, y el stream termina en vivo
// cuando cierran todos.
func TestSubscribeVariosIdsNoRepiteYTerminaEnVivo(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	cerrado := h.closedJob(t, cred)
	vivo, _ := h.created(t, cred, nil)
	c, stop := context.WithTimeout(ctx(t), 20*time.Second)
	defer stop()
	s, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: []string{cerrado, vivo}})
	if err != nil {
		t.Fatal(err)
	}
	for h.core.bus.Subscribers() < 1 { // el servidor ya está suscrito al bus
		time.Sleep(5 * time.Millisecond)
	}
	h.core.bus.Publish(engine.Event{JobID: cerrado, Kind: engine.JobState, State: "closed"}) // el reenvío del bus que ya salió sintético
	if _, err := h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: vivo}); err != nil {
		t.Fatal(err)
	}
	got := recvStates(t, s)
	want := []string{cerrado + ":cancelled", cerrado + ":closed", vivo + ":cancelled", vivo + ":closed"}
	if !slices.Equal(got, want) {
		t.Fatalf("eventos = %v, quería %v", got, want)
	}
}

// Un id que no existe no cuelga el stream: NotFound con su código del catálogo, en es y en.
func TestSubscribeAIdInexistenteEsNotFound(t *testing.T) {
	h := newHarness(t, nil)
	for loc, want := range map[string]string{"es": "no existe", "en": "does not exist"} {
		s, err := h.events.Subscribe(con(t, loc), &v1.SubscribeRequest{JobIds: []string{"nope"}})
		if err == nil {
			_, err = s.Recv()
		}
		st := status.Convert(err)
		reason, _ := reasonOf(err)
		if st.Code() != codes.NotFound || reason != "patrol.err.job_missing" || !strings.Contains(st.Message(), want) {
			t.Errorf("%s: %v (%q)", loc, err, reason)
		}
	}
}

// Un Subscribe que llega con el trabajo ya terminado pero aún sin "closed" (finish haciendo el manifest y el zip, o
// closeCancelled entre sus dos eventos) se perdió el estado final por el bus: lo recibe antes del "closed" en vivo.
func TestSubscribeEnMedioDelCierreRecibeElEstadoFinal(t *testing.T) {
	h := newHarness(t, nil)
	job, _ := h.created(t, h.ready(t), nil)
	h.core.mu.Lock()
	h.core.jobs[job].state = "cancelled" // finish ya lo marcó; "cancelled" salió por el bus antes de suscribirse
	h.core.mu.Unlock()
	c, stop := context.WithTimeout(ctx(t), 20*time.Second)
	defer stop()
	s, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: []string{job}})
	if err != nil {
		t.Fatal(err)
	}
	for h.core.bus.Subscribers() < 1 {
		time.Sleep(5 * time.Millisecond)
	}
	h.core.mu.Lock()
	h.core.jobs[job].closed = true
	h.core.mu.Unlock()
	h.core.bus.Publish(engine.Event{JobID: job, Kind: engine.JobState, State: "closed"})
	want := []string{job + ":cancelled", job + ":closed"}
	if got := recvStates(t, s); !slices.Equal(got, want) {
		t.Fatalf("eventos = %v, quería %v", got, want)
	}
}

// Un armado deshecho (el planificador lo rechaza, o una cancelación vista justo antes) no deja al trabajo apuntando a
// la carpeta de salida, al writer ni al release ya deshechos, y la carpeta vacía se borra.
func TestArmadoDeshechoNoDejaCarpetaNiWriter(t *testing.T) {
	for nombre, cancelar := range map[string]bool{"rechazado": false, "cancelado antes de armar": true} {
		t.Run(nombre, func(t *testing.T) {
			h := newHarness(t, nil)
			job, fp := h.created(t, h.ready(t), nil)
			h.core.mu.Lock()
			j := h.core.jobs[job]
			j.spec.Schedule.Cron = "no es cron" // sched.Arm lo rechaza después de crear el writer
			j.cancelReq = cancelar
			out := j.spec.OutputDir
			h.core.mu.Unlock()
			if _, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: job, AcceptedHostKeyFingerprints: []string{fp}}); err == nil {
				t.Fatal("ArmJob debía fallar")
			}
			h.core.mu.Lock()
			dir, w, rel, until, creds := j.OutputDir, j.writer, j.release, j.Until, j.creds
			h.core.mu.Unlock()
			if dir != "" || w != nil || rel != nil || !until.IsZero() || creds != nil {
				t.Fatalf("OutputDir=%q writer=%v release=%v Until=%v creds=%v", dir, w != nil, rel != nil, until, creds)
			}
			if m, _ := filepath.Glob(filepath.Join(out, "*")); len(m) != 0 {
				t.Fatalf("quedó la carpeta del armado deshecho: %v", m)
			}
		})
	}
}

// Un armado que el planificador rechaza (Schedule.Until ya vencido: engine.err.job_ended) deja el trabajo como
// estaba: los equipos excluidos siguen en el spec y no quedan ventana, credenciales ni verificaciones del intento.
func TestArmadoRechazadoDejaElTrabajoIgual(t *testing.T) {
	h := newHarness(t, nil)
	job, fp := h.created(t, h.ready(t), nil)
	h.core.mu.Lock()
	j := h.core.jobs[job]
	j.spec.Targets = append(j.spec.Targets, patrol.Target{Address: "192.0.2.10", DeviceID: "excluido"})
	j.spec.Schedule.IntervalSeconds, j.spec.Schedule.Rounds = 60, 0
	j.spec.Schedule.Until = time.Now().Add(-time.Hour)
	antes := j.spec
	previos := []patrol.HostKeyChange{{}} // lo que ya tenía el trabajo: el intento fallido no lo cambia
	j.changes = previos
	h.core.mu.Unlock()
	_, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: job, AcceptedHostKeyFingerprints: []string{fp}, ExcludedDeviceIds: []string{"excluido"}})
	if reason, _ := reasonOf(err); reason != "engine.err.job_ended" {
		t.Fatalf("err = %v (%q); quería engine.err.job_ended", err, reason)
	}
	h.core.mu.Lock()
	defer h.core.mu.Unlock()
	if j.state != "created" || !slices.Equal(j.spec.Targets, antes.Targets) || !j.Until.IsZero() || j.creds != nil || j.verified != nil || len(j.changes) != 1 {
		t.Fatalf("el trabajo cambió: state=%q targets=%v until=%v creds=%v verified=%v", j.state, j.spec.Targets, j.Until, j.creds, j.verified)
	}
}
