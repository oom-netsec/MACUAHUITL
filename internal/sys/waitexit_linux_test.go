package sys

import (
	"os/exec"
	"testing"
	"time"
)

// startSleep lanza un sleep y devuelve su PID y kill (lo mata y espera al reapado). Un solo Wait, en una goroutine: lo
// que WaitExit observa es el proceso ya reapado.
func startSleep(t *testing.T, secs string) (pid int, kill func()) {
	t.Helper()
	cmd := exec.Command("sleep", secs)
	if err := cmd.Start(); err != nil {
		t.Skip("sin sleep:", err)
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	kill = func() { cmd.Process.Kill(); <-done }
	t.Cleanup(kill)
	return cmd.Process.Pid, kill
}

func TestWaitExitTermina(t *testing.T) {
	pid, kill := startSleep(t, "30")
	go func() { time.Sleep(100 * time.Millisecond); kill() }()
	t0 := time.Now()
	if err := WaitExit(pid, 5*time.Second); err != nil {
		t.Fatalf("WaitExit = %v", err)
	}
	if time.Since(t0) < 80*time.Millisecond {
		t.Fatal("volvió antes de que el proceso terminara")
	}
}

func TestWaitExitVencePlazo(t *testing.T) {
	pid, _ := startSleep(t, "30")
	t0 := time.Now()
	err := WaitExit(pid, 200*time.Millisecond)
	if err == nil {
		t.Fatal("WaitExit debía vencer el plazo")
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("tardó %v", d)
	}
}

func TestWaitExitYaTerminado(t *testing.T) {
	pid, kill := startSleep(t, "30")
	kill()
	if err := WaitExit(pid, time.Second); err != nil {
		t.Fatalf("proceso ya terminado: %v", err)
	}
}

func TestWaitExitSondeo(t *testing.T) {
	pid, kill := startSleep(t, "30")
	go func() { time.Sleep(100 * time.Millisecond); kill() }()
	t0 := time.Now()
	if err := waitExitPoll(pid, 5*time.Second); err != nil {
		t.Fatalf("sondeo = %v", err)
	}
	if time.Since(t0) < 80*time.Millisecond {
		t.Fatal("el sondeo volvió antes de que el proceso terminara")
	}
	if err := waitExitPoll(pid, time.Second); err != nil {
		t.Fatalf("sondeo ya terminado = %v", err)
	}
}

func TestWaitExitSondeoVencePlazo(t *testing.T) {
	pid, _ := startSleep(t, "30")
	if err := waitExitPoll(pid, 100*time.Millisecond); err != ErrWaitTimeout {
		t.Fatalf("sondeo = %v, quería ErrWaitTimeout", err)
	}
}
