package core

import (
	"net/netip"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// lentoHarness apunta el harness a un equipo cuyo comando tarda (líneas cada 250 ms). El reloj del núcleo es
// manual: cada prueba lo adelanta por eventos para acercar el fin de la ventana sin esperar ni depender de la carga.
func lentoHarness(t *testing.T, lines int) (*harness, string) {
	t.Helper()
	h := newHarnessReloj(t, func(o *Options) { o.IdleLock = 100 * time.Hour })
	cred := h.ready(t)
	addr, _ := simulator.Start(t, simulator.Config{Hostname: "SW-LAB-03", Username: "admin", Password: "MARKER-PW", Enable: "MARKER-EN",
		Transcripts: transcripts(), StreamCommand: "show memory summary", StreamLines: lines, SlowDelay: 250 * time.Millisecond})
	ap := netip.MustParseAddrPort(addr)
	h.target = &v1.Target{Address: ap.Addr().String(), Port: uint32(ap.Port()), DeviceId: "sw3"}
	return h, cred
}

// enRonda vuelve cuando el equipo de la ronda en curso ya está ejecutando el comando.
func enRonda(h *harness, t *testing.T, job string) {
	t.Helper()
	h.esperaEvento(t, job, func(e *v1.SubscribeResponse) bool {
		return e.GetCommandProgress() != nil // el comando ya salió al equipo
	})
}

// finales devuelve el último evento de equipo (estado y motivo) hasta el cierre del trabajo.
func finales(t *testing.T, h *harness, job string) (v1.DeviceState, string) {
	t.Helper()
	var st v1.DeviceState
	var reason string
	for _, e := range h.waitJob(t, job, "closed") {
		if d := e.GetDeviceStateChanged(); d != nil && (d.State == v1.DeviceState_DEVICE_STATE_COMPLETED || d.State == v1.DeviceState_DEVICE_STATE_FAILED) {
			st, reason = d.State, d.Reason
		}
	}
	return st, reason
}

// Schedule.Until solo impide empezar rondas nuevas: una ronda que arrancó antes y cuyo comando sigue después de
// Until termina bien; el equipo solo se corta con el fin de la ventana de la bóveda.
func TestWindowSchedUntilNoCortaRondaEnCurso(t *testing.T) {
	h, cred := lentoHarness(t, 16)
	spec := h.spec(cred)
	spec.CustomCommands = "show memory summary\n"
	spec.Schedule = &v1.Schedule{Rounds: 1, Until: timestamppb.New(h.reloj.Now().Add(3 * time.Second))}
	job, _ := h.armSpec(t, spec)
	enRonda(h, t, job)
	h.reloj.Avanza(10 * time.Second) // Until ya pasó con el comando a medias
	st, reason := finales(t, h, job)
	if st != v1.DeviceState_DEVICE_STATE_COMPLETED {
		t.Fatalf("la ronda en curso debía terminar pasado Schedule.Until: estado %v motivo %q", st, reason)
	}
}

// El fin de la ventana sí corta al equipo a medias, con patrol.err.window_ended.
func TestWindowFinCortaRondaEnCurso(t *testing.T) {
	h, cred := lentoHarness(t, 20) // el comando dura ~5 s de reloj real; corta el temporizador de windowCtx (1 s tras empezar la ronda 2)
	spec := h.spec(cred)
	spec.CustomCommands = "show memory summary\n"
	spec.Schedule = &v1.Schedule{IntervalSeconds: 5, Rounds: 2}
	job, _ := h.armSpec(t, spec)
	// Con la ronda 1 terminada (esperaEvento ya adelantó 1 s) el reloj salta a 1 s del fin de la ventana: la ronda 2,
	// la última, arranca; con su equipo ya ejecutando se pasa del fin y debe cortarlo.
	h.esperaEvento(t, job, func(e *v1.SubscribeResponse) bool {
		p := e.GetPhaseAdded()
		return p != nil && p.Kind == v1.JobPhaseKind_JOB_PHASE_KIND_ROUND_FINISHED
	})
	h.reloj.Avanza(time.Hour - 2*time.Second)
	enRonda(h, t, job)
	h.reloj.Avanza(2 * time.Second)
	st, reason := finales(t, h, job)
	if st != v1.DeviceState_DEVICE_STATE_FAILED || reason != "patrol.err.window_ended" {
		t.Fatalf("el fin de la ventana debía cortar la ronda 2: estado %v motivo %q", st, reason)
	}
}
