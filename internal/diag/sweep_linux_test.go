//go:build !windows

package diag

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// sweepPing hace de ping de iputils: a partir de 1000 bytes con DF dice «message too long»; antes, una respuesta.
// Guarda el argv de cada corrida en log.
func sweepPing(t *testing.T, log string, hang bool) func(string) (string, error) {
	h := ""
	if hang {
		h = "1"
	}
	return fakeScript(t, `echo "$*" >> `+log+`
trap 'exit 0' INT
size=56
while [ $# -gt 0 ]; do [ "$1" = "-s" ] && size=$2; shift; done
echo "start $size"
if [ "$size" -ge 2000 ]; then
  echo "1 packets transmitted, 0 received, 100% packet loss, time 0ms"
  exit 1
fi
if [ "$size" -ge 1000 ]; then
  echo "ping: local error: message too long, mtu=1500"
  echo "1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms"
  exit 1
fi
echo "$((size+8)) bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=2.00 ms"
if [ "$size" -eq 500 ] && [ -n "`+h+`" ]; then while :; do sleep 0.05; done; fi
echo "1 packets transmitted, 1 received, 0% packet loss, time 0ms"
`)
}

func sweepReq() Request {
	return req(Ping, "192.0.2.1", map[string]string{"sweep_start": "0", "sweep_end": "1000", "sweep_step": "500", "df": "true"}, "")
}

func TestBarridoOkOkFrag(t *testing.T) {
	log := filepath.Join(t.TempDir(), "argv")
	var mu sync.Mutex
	var pts []SweepPoint
	r := Runner{LookPath: sweepPing(t, log, false), OnSweep: func(p SweepPoint) { mu.Lock(); pts = append(pts, p); mu.Unlock() }}
	res, err := r.Run(context.Background(), sweepReq(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d", res.ExitCode)
	}
	want := []SweepPoint{{0, 1, 1, "ok"}, {500, 1, 1, "ok"}, {1000, 1, 0, "frag"}}
	if !reflect.DeepEqual(pts, want) {
		t.Errorf("puntos %+v, quería %+v", pts, want)
	}
	if s := res.Ping; s == nil || s.Sent != 3 || s.Received != 2 || s.MinMs != 2 || s.MaxMs != 2 || s.AvgMs != 2 {
		t.Errorf("resumen %+v", s)
	}
	// El tamaño va antes del host, con -M do en todas las corridas.
	b, _ := os.ReadFile(log)
	got := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i, size := range []string{"0", "500", "1000"} {
		if wantLine := "-n -c 1 -M do -s " + size + " 192.0.2.1"; got[i] != wantLine {
			t.Errorf("argv %d: %q, quería %q", i, got[i], wantLine)
		}
	}
}

func TestBarridoLoss(t *testing.T) {
	var pts []SweepPoint
	r := Runner{LookPath: sweepPing(t, filepath.Join(t.TempDir(), "argv"), false), OnSweep: func(p SweepPoint) { pts = append(pts, p) }}
	q := req(Ping, "192.0.2.1", map[string]string{"sweep_start": "1000", "sweep_end": "2000", "sweep_step": "1000"}, "")
	res, err := r.Run(context.Background(), q, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 1 { // ninguno respondió en todo el barrido
		t.Errorf("exit = %d", res.ExitCode)
	}
	if want := []SweepPoint{{1000, 1, 0, "frag"}, {2000, 1, 0, "loss"}}; !reflect.DeepEqual(pts, want) {
		t.Errorf("puntos %+v, quería %+v", pts, want)
	}
}

func TestBarridoStopRunAMitad(t *testing.T) {
	log := filepath.Join(t.TempDir(), "argv")
	stop := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	var pts []SweepPoint
	r := Runner{Stop: stop, LookPath: sweepPing(t, log, true), OnSweep: func(p SweepPoint) { mu.Lock(); pts = append(pts, p); mu.Unlock() }}
	res, err := r.Run(context.Background(), sweepReq(), func(l string) {
		if l == "508 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=2.00 ms" {
			once.Do(func() { close(stop) })
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []SweepPoint{{0, 1, 1, "ok"}}; !reflect.DeepEqual(pts, want) {
		t.Errorf("puntos %+v, quería %+v", pts, want)
	}
	// B2: el ping interrumpido (500) ni su punto ni su cuenta entran al resumen.
	if s := res.Ping; s == nil || s.Sent != 1 || s.Received != 1 {
		t.Errorf("resumen %+v", s)
	}
	if b, _ := os.ReadFile(log); strings.Count(string(b), "\n") != 2 {
		t.Errorf("no debió correr el tamaño 1000: %q", b)
	}
}

// Sin ninguna respuesta en todo el barrido el código de salida es 1.
func TestBarridoSinRespuestasSale1(t *testing.T) {
	r := Runner{LookPath: sweepPing(t, filepath.Join(t.TempDir(), "argv"), false)}
	q := req(Ping, "192.0.2.1", map[string]string{"sweep_start": "2000", "sweep_end": "2000", "sweep_step": "1"}, "")
	res, err := r.Run(context.Background(), q, func(string) {})
	if err != nil || res.ExitCode != 1 {
		t.Errorf("exit=%d err=%v", res.ExitCode, err)
	}
}

// ok exige que vuelvan todas: con count 2 y 1 de 2 respuestas es loss.
func TestBarridoParcialEsLoss(t *testing.T) {
	p := fakeScript(t, `echo "64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=2.00 ms"
echo "2 packets transmitted, 1 received, 50% packet loss, time 1ms"
`)
	var pts []SweepPoint
	r := Runner{LookPath: p, OnSweep: func(p SweepPoint) { pts = append(pts, p) }}
	q := req(Ping, "192.0.2.1", map[string]string{"sweep_start": "0", "sweep_end": "0", "sweep_step": "1", "count": "2"}, "")
	if _, err := r.Run(context.Background(), q, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if want := []SweepPoint{{0, 2, 1, "loss"}}; !reflect.DeepEqual(pts, want) {
		t.Errorf("puntos %+v, quería %+v", pts, want)
	}
}

// Con Stop ya cerrado no corre ningún tamaño.
func TestBarridoStopAntesDeEmpezar(t *testing.T) {
	log := filepath.Join(t.TempDir(), "argv")
	stop := make(chan struct{})
	close(stop)
	r := Runner{Stop: stop, LookPath: sweepPing(t, log, false)}
	res, err := r.Run(context.Background(), sweepReq(), func(string) {})
	if _, e := os.Stat(log); err != nil || e == nil || res.Ping == nil || res.Ping.Sent != 0 {
		t.Errorf("err=%v stat=%v %+v", err, e, res.Ping)
	}
}

// M1: duration vale para el barrido entero, no por tamaño (3 tamaños con duration=1 no tardan 3 s).
func TestBarridoDuracionEsDelBarrido(t *testing.T) {
	r := Runner{LookPath: fakeScript(t, "trap 'exit 0' INT\nwhile :; do sleep 0.05; done\n")}
	q := req(Ping, "192.0.2.1", map[string]string{"sweep_start": "0", "sweep_end": "1000", "sweep_step": "500", "duration": "1"}, "")
	t0 := time.Now()
	if _, err := r.Run(context.Background(), q, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d > 2*time.Second {
		t.Errorf("tardó %v", d)
	}
}

// M1: el tope de envíos cuenta el total del barrido.
func TestBarridoTopeDeEnviosEsDelTotal(t *testing.T) {
	old := pingMaxSent
	pingMaxSent = 3
	t.Cleanup(func() { pingMaxSent = old })
	log := filepath.Join(t.TempDir(), "argv")
	r := Runner{LookPath: fakeScript(t, `echo "$*" >> `+log+`
echo "64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=2.00 ms"
echo "64 bytes from 192.0.2.1: icmp_seq=2 ttl=64 time=2.00 ms"
`)}
	q := req(Ping, "192.0.2.1", map[string]string{"sweep_start": "0", "sweep_end": "1000", "sweep_step": "500", "count": "2"}, "")
	if _, err := r.Run(context.Background(), q, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(log); strings.Count(string(b), "\n") != 2 {
		t.Errorf("debió parar en el segundo tamaño: %q", b)
	}
}

// B4: cancelar por ctx sale con 143 como siempre; si un tamaño no arranca, el .txt con lo anterior se conserva.
func TestBarridoCancelacionYArranqueFallido(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := Runner{LookPath: sweepPing(t, filepath.Join(t.TempDir(), "argv"), true)}
	res, err := r.Run(ctx, sweepReq(), func(l string) {
		if strings.HasPrefix(l, "508 bytes") {
			cancel()
		}
	})
	if err != nil || res.ExitCode != 143 {
		t.Errorf("exit=%d err=%v", res.ExitCode, err)
	}

	dir := t.TempDir()
	r = Runner{LookPath: fakeScript(t, "rm -f \"$0\"\necho \"64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=2.00 ms\"\n")}
	q := req(Ping, "192.0.2.1", map[string]string{"sweep_start": "0", "sweep_end": "500", "sweep_step": "500"}, dir)
	res, err = r.Run(context.Background(), q, func(string) {})
	if err == nil {
		t.Fatal("el segundo tamaño no puede arrancar")
	}
	if b, e := os.ReadFile(res.OutputPath); e != nil || !strings.Contains(string(b), "bytes from") {
		t.Errorf("se perdió la salida anterior: %v %q", e, b)
	}
}
