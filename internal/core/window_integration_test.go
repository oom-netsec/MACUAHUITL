package core

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// lentoHarness apunta el harness a un equipo cuyo comando tarda (líneas cada 250 ms). clock suma shift al
// reloj del núcleo (para acercar el fin de la ventana sin esperar horas).
func lentoHarness(t *testing.T, shift *atomic.Int64, lines int) (*harness, string) {
	t.Helper()
	h := newHarness(t, func(o *Options) {
		o.IdleLock = 100 * time.Hour
		o.Now = func() time.Time { return time.Now().Add(time.Duration(shift.Load())) }
	})
	cred := h.ready(t)
	addr, _ := simulator.Start(t, simulator.Config{Hostname: "SW-LAB-03", Username: "admin", Password: "MARKER-PW", Enable: "MARKER-EN",
		Transcripts: transcripts(), StreamCommand: "show memory summary", StreamLines: lines, SlowDelay: 250 * time.Millisecond})
	ap := netip.MustParseAddrPort(addr)
	h.target = &v1.Target{Address: ap.Addr().String(), Port: uint32(ap.Port()), DeviceId: "sw3"}
	return h, cred
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
	var shift atomic.Int64
	h, cred := lentoHarness(t, &shift, 16)
	spec := h.spec(cred)
	spec.CustomCommands = "show memory summary\n"
	spec.Schedule = &v1.Schedule{Rounds: 1, Until: timestamppb.New(time.Now().Add(3 * time.Second))} // la ronda arranca a los ~50 ms y el comando dura ~4 s
	job, _ := h.armSpec(t, spec)
	st, reason := finales(t, h, job)
	if st != v1.DeviceState_DEVICE_STATE_COMPLETED {
		t.Fatalf("la ronda en curso debía terminar pasado Schedule.Until: estado %v motivo %q", st, reason)
	}
}

// El fin de la ventana sí corta al equipo a medias, con patrol.err.window_ended.
func TestWindowFinCortaRondaEnCurso(t *testing.T) {
	var shift atomic.Int64
	h, cred := lentoHarness(t, &shift, 12)
	spec := h.spec(cred)
	spec.CustomCommands = "show memory summary\n"
	spec.Schedule = &v1.Schedule{IntervalSeconds: 5, Rounds: 2}
	job, _ := h.armSpec(t, spec)
	// La ronda 1 (a t=0) termina bien; antes de la 2 (a t=5 s) se adelanta el reloj para que a la ronda 2 le quede
	// ~1 s de ventana, menos de los ~3 s del comando.
	for {
		e, err := h.subs[job].Recv()
		if err != nil {
			t.Fatal(err)
		}
		if d := e.GetDeviceStateChanged(); d != nil && d.State == v1.DeviceState_DEVICE_STATE_COMPLETED {
			break
		}
	}
	shift.Store(int64(time.Hour - 6*time.Second))
	st, reason := finales(t, h, job)
	if st != v1.DeviceState_DEVICE_STATE_FAILED || reason != "patrol.err.window_ended" {
		t.Fatalf("el fin de la ventana debía cortar la ronda 2: estado %v motivo %q", st, reason)
	}
}
