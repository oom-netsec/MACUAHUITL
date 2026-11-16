package ipc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
)

// TestHelperServidor es el proceso servidor de TestServerPID: escucha en el socket de MCTL_IPC_SOCK hasta que se cierra su stdin.
func TestHelperServidor(t *testing.T) {
	p := os.Getenv("MCTL_IPC_SOCK")
	if p == "" {
		t.Skip("solo como proceso auxiliar")
	}
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	fmt.Println("listo")
	io.Copy(io.Discard, os.Stdin)
}

func TestServerPID(t *testing.T) {
	p := sockPath(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperServidor$")
	cmd.Env = append(os.Environ(), "MCTL_IPC_SOCK="+p)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); cmd.Wait() })
	if line, _ := bufio.NewReader(out).ReadString('\n'); line != "listo\n" {
		t.Fatalf("el servidor auxiliar no arrancó: %q", line)
	}
	pid, err := ServerPID(p)
	if err != nil || pid != cmd.Process.Pid || pid == os.Getpid() {
		t.Fatalf("ServerPID = %d, %v; quería %d", pid, err, cmd.Process.Pid)
	}
	// Un socket que atiende otro usuario no es nuestro núcleo: core stop no debe esperar a ese PID.
	if pid, err := serverPID(p, os.Getuid()+1); err == nil {
		t.Fatalf("serverPID con otro UID = %d, sin error", pid)
	}
}

func TestServerPIDNoCorre(t *testing.T) {
	p := sockPath(t)
	if _, err := ServerPID(p); !errors.Is(err, ErrNotRunning) { // sin socket
		t.Fatalf("sin socket: %v", err)
	}
	// socket huérfano: el archivo existe pero nadie escucha (núcleo muerto)
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	l.(*peerListener).Listener.(interface{ SetUnlinkOnClose(bool) }).SetUnlinkOnClose(false)
	l.Close()
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	if _, err := ServerPID(p); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("socket huérfano: %v", err)
	}
}
