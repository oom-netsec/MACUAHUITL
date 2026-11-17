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
if [ "$size" -eq 500 ] && [ -n "`+h+`" ]; then while :; do sleep 0.05; done; fi
echo "$((size+8)) bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=2.00 ms"
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
	if _, err := r.Run(context.Background(), q, func(string) {}); err != nil {
		t.Fatal(err)
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
		if l == "start 500" {
			once.Do(func() { close(stop) })
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []SweepPoint{{0, 1, 1, "ok"}}; !reflect.DeepEqual(pts, want) {
		t.Errorf("puntos %+v, quería %+v", pts, want)
	}
	if s := res.Ping; s == nil || s.Sent != 1 || s.Received != 1 {
		t.Errorf("resumen %+v", s)
	}
	if b, _ := os.ReadFile(log); strings.Count(string(b), "\n") != 2 {
		t.Errorf("no debió correr el tamaño 1000: %q", b)
	}
}

func TestSweepArgv(t *testing.T) {
	for _, c := range []struct {
		win  bool
		in   []string
		want []string
	}{
		{false, []string{"-n", "-c", "1", "192.0.2.1"}, []string{"-n", "-c", "1", "-s", "9", "192.0.2.1"}},
		{true, []string{"-n", "1", "-w", "4000", "192.0.2.1"}, []string{"-n", "1", "-w", "4000", "-l", "9", "192.0.2.1"}},
	} {
		got, err := sweepArgv(c.in, 9, c.win)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v %v", got, err)
		}
	}
	if _, err := sweepArgv([]string{"-n", "-x"}, 9, false); err == nil { // vuelve a pasar por checkFlagLike
		t.Error("un valor con forma de bandera debe rechazarse")
	}
}
