//go:build !windows

package diag

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeScript escribe un script que hace de ping y devuelve el LookPath que lo resuelve.
func fakeScript(t *testing.T, body string) func(string) (string, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ping")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return func(string) (string, error) { return p, nil }
}

const linuxLoop = `trap 'exit 0' INT
i=1
while :; do echo "64 bytes from 192.0.2.1: icmp_seq=$i ttl=64 time=2.00 ms"; i=$((i+1)); sleep 0.05; done
`

func contRun(t *testing.T, body string, r Runner) (Result, time.Duration) {
	t.Helper()
	r.LookPath = fakeScript(t, body)
	t0 := time.Now()
	res, err := r.Run(context.Background(), req(Ping, "192.0.2.1", map[string]string{"count": "100"}, ""), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	return res, time.Since(t0)
}

// M4: el tope de duración detiene con SIGINT (salida 0 del trap), no con el respaldo SIGTERM (143).
func TestPingTopeDeDuracion(t *testing.T) {
	old := pingMaxRun
	pingMaxRun = 300 * time.Millisecond
	t.Cleanup(func() { pingMaxRun = old })
	res, d := contRun(t, linuxLoop, Runner{})
	if res.ExitCode != 0 || d > 5*time.Second || res.Ping == nil || res.Ping.Sent < 2 {
		t.Errorf("exit=%d dur=%v %+v", res.ExitCode, d, res.Ping)
	}
}

// M4: el tope de envíos detiene al llegar a N envíos.
func TestPingTopeDeEnvios(t *testing.T) {
	old := pingMaxSent
	pingMaxSent = 5
	t.Cleanup(func() { pingMaxSent = old })
	res, _ := contRun(t, linuxLoop, Runner{})
	// El script puede imprimir una o dos líneas más antes de recibir SIGINT.
	if res.ExitCode != 0 || res.Ping == nil || res.Ping.Sent < 5 || res.Ping.Sent > 8 {
		t.Errorf("exit=%d %+v", res.ExitCode, res.Ping)
	}
}

const winLoop = `i=0
while :; do echo "Reply from 192.0.2.1: bytes=32 time=1ms TTL=64"; sleep 0.05; done
`

// M5: en Windows el Job Object termina con 143; tras una parada pedida eso es éxito (0 si hubo respuestas, 1 si no).
func TestPingStopWindowsSale0o1(t *testing.T) {
	old := goos
	goos = "windows"
	t.Cleanup(func() { goos = old })
	for _, c := range []struct {
		body string
		want int
	}{{winLoop, 0}, {"sleep 60\n", 1}} {
		stop := make(chan struct{})
		time.AfterFunc(400*time.Millisecond, func() { close(stop) })
		res, _ := contRun(t, c.body, Runner{Stop: stop})
		if res.ExitCode != c.want {
			t.Errorf("exit=%d, quería %d (%+v)", res.ExitCode, c.want, res.Ping)
		}
	}
}
