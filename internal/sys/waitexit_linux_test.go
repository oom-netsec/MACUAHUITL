package sys

import (
	"os/exec"
	"testing"
	"time"
)

// WaitExit espera a un proceso que no es hijo nuestro: el hijo se reapa en otra goroutine para que no quede zombi.
func startSleep(t *testing.T, secs string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", secs)
	if err := cmd.Start(); err != nil {
		t.Skip("sin sleep:", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd
}

func TestWaitExitTermina(t *testing.T) {
	cmd := startSleep(t, "30")
	go func() { time.Sleep(100 * time.Millisecond); cmd.Process.Kill(); cmd.Wait() }()
	t0 := time.Now()
	if err := WaitExit(cmd.Process.Pid, 5*time.Second); err != nil {
		t.Fatalf("WaitExit = %v", err)
	}
	if time.Since(t0) < 80*time.Millisecond {
		t.Fatal("volvió antes de que el proceso terminara")
	}
}

func TestWaitExitVencePlazo(t *testing.T) {
	cmd := startSleep(t, "30")
	t0 := time.Now()
	err := WaitExit(cmd.Process.Pid, 200*time.Millisecond)
	if err == nil {
		t.Fatal("WaitExit debía vencer el plazo")
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("tardó %v", d)
	}
}

func TestWaitExitYaTerminado(t *testing.T) {
	cmd := startSleep(t, "30")
	cmd.Process.Kill()
	cmd.Wait()
	if err := WaitExit(cmd.Process.Pid, time.Second); err != nil {
		t.Fatalf("proceso ya terminado: %v", err)
	}
}

func TestWaitExitSondeo(t *testing.T) {
	cmd := startSleep(t, "30")
	go func() { time.Sleep(100 * time.Millisecond); cmd.Process.Kill(); cmd.Wait() }()
	t0 := time.Now()
	if err := waitExitPoll(cmd.Process.Pid, 5*time.Second); err != nil {
		t.Fatalf("sondeo = %v", err)
	}
	if time.Since(t0) < 80*time.Millisecond {
		t.Fatal("el sondeo volvió antes de que el proceso terminara")
	}
	if err := waitExitPoll(cmd.Process.Pid, time.Second); err != nil {
		t.Fatalf("sondeo ya terminado = %v", err)
	}
}

func TestWaitExitSondeoVencePlazo(t *testing.T) {
	cmd := startSleep(t, "30")
	if err := waitExitPoll(cmd.Process.Pid, 100*time.Millisecond); err != ErrWaitTimeout {
		t.Fatalf("sondeo = %v, quería ErrWaitTimeout", err)
	}
}
