package diag

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	pidFile := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), "DIAG_HELPER=child", "DIAG_PID="+pidFile)
	started, done, err := confine(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
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
	cancel()
	cmd.Wait()
	if ev, _ := windows.WaitForSingleObject(h, 5000); ev != windows.WAIT_OBJECT_0 {
		t.Fatal("el nieto sigue vivo tras cancelar")
	}
}
