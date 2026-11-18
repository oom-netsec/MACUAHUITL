package diag

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestHelperProcess es el hijo (y el nieto) de TestConfineMataElArbol: se relanzan a sí mismos como procesos.
func TestHelperProcess(t *testing.T) {
	switch os.Getenv("DIAG_HELPER") {
	case "child":
		g := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		g.Env = append(os.Environ(), "DIAG_HELPER=grand")
		if err := g.Start(); err != nil {
			os.Exit(3)
		}
		os.WriteFile(os.Getenv("DIAG_PID"), []byte(strconv.Itoa(g.Process.Pid)), 0o600)
		time.Sleep(time.Minute)
	case "grand":
		time.Sleep(time.Minute)
	}
}

func TestConfineMataElArbol(t *testing.T) {
	confineProbe(t, func(cancel func(), _ func()) { cancel() })
}

// Cerrar el job (done) sin cancelar también mata al nieto: KILL_ON_JOB_CLOSE.
func TestConfineCerrarElJobMataElArbol(t *testing.T) {
	confineProbe(t, func(_ func(), done func()) { done() })
}

func confineProbe(t *testing.T, kill func(cancel func(), done func())) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), "DIAG_HELPER=child", "DIAG_PID="+pidFile)
	started, done, err := confine(cmd)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	closeJob := func() { once.Do(done) }
	defer closeJob()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := started(); err != nil {
		t.Fatal(err)
	}
	var pid uint32
	for i := 0; i < 100 && pid == 0; i++ {
		time.Sleep(100 * time.Millisecond)
		if b, err := os.ReadFile(pidFile); err == nil {
			n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
			pid = uint32(n)
		}
	}
	if pid == 0 {
		t.Fatal("el hijo no lanzó al nieto")
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	kill(cancel, closeJob)
	cmd.Process.Kill() // el hijo directo no es lo que se prueba; el nieto sí
	cmd.Wait()
	if ev, _ := windows.WaitForSingleObject(h, 5000); ev != windows.WAIT_OBJECT_0 {
		t.Fatal("el nieto sigue vivo tras cancelar")
	}
}

// Cancel después de done (la goroutine de diag puede llegar tarde) no debe tocar el job: su handle ya está cerrado y el
// número puede ser de otro objeto.
func TestCancelTrasDoneNoTerminaElJob(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	_, done, err := confine(cmd)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	old := terminateJob
	terminateJob = func(h windows.Handle, code uint32) error { calls++; return old(h, code) }
	defer func() { terminateJob = old }()
	if err := cmd.Start(); err != nil { // Cancel también hace Kill: hace falta un proceso (queda suspendido)
		t.Fatal(err)
	}
	defer cmd.Wait()
	cmd.Cancel() // con el job abierto sí lo termina, una vez
	if calls != 1 {
		t.Fatalf("Cancel antes de done: %d llamadas, quiero 1", calls)
	}
	done()
	done() // idempotente: no cierra dos veces
	cmd.Cancel()
	if calls != 1 {
		t.Fatalf("Cancel tras done terminó un job cerrado (%d llamadas)", calls)
	}
}
