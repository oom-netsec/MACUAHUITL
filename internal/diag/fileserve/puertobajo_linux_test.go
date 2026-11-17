package fileserve

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// puerto69 intenta servir TFTP en 127.0.0.1:69 y devuelve el resultado: nil si escuchó, el error si no.
func puerto69(t *testing.T) error {
	t.Helper()
	f, _ := image(t, "a.bin", 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- Serve(ctx, Config{Addr: "127.0.0.1:69", Proto: "tftp", Files: []string{f}, OnListening: func(string) { close(ready) }})
	}()
	select {
	case <-ready:
		cancel()
		<-done
		return nil
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("ni escucha ni falla")
		return nil
	}
}

// Con el sysctl del kernel en ≤ 69 (decisión del usuario), la app escucha de verdad en el 69 sin privilegios propios.
func TestEscuchaEn69SiElSysctlLoPermite(t *testing.T) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start")
	if err != nil {
		t.Skip("sin /proc/sys/net/ipv4/ip_unprivileged_port_start: ", err)
	}
	if n, _ := strconv.Atoi(strings.TrimSpace(string(b))); n > 69 {
		t.Skipf("net.ipv4.ip_unprivileged_port_start=%d (> 69): el kernel no deja abrir el 69 sin privilegios", n)
	}
	if err := puerto69(t); err != nil {
		t.Fatal(err)
	}
}

// Subproceso de la prueba con namespaces: el resultado de abrir el 69 se imprime en la salida.
func TestAyudanteBind69(t *testing.T) {
	fase := os.Getenv("MACUA_BIND_FASE")
	if fase == "" {
		t.Skip("solo como subproceso")
	}
	err := puerto69(t)
	var c i18n.Coded
	switch {
	case fase == "ok" && err == nil:
	case fase == "denied" && errors.As(err, &c) && c.Reason() == "fileserve.err.port_denied" && c.Metadata()["min_port"] == "69" &&
		c.Metadata()["cmd"] == "echo 'net.ipv4.ip_unprivileged_port_start=69' | sudo tee /etc/sysctl.d/60-macuahuitl.conf && sudo sysctl --system":
	default:
		t.Fatalf("fase %s: %v", fase, err)
	}
}

// Con unshare -rn (user y net namespace sin privilegios reales) y sin CAP_NET_BIND_SERVICE: con el sysctl en 1024 el
// bind da EACCES y el error trae la orden; al bajar el sysctl a 69 (lo que hace esa orden), escucha. Se omite si el
// sistema no deja crear los namespaces.
func TestBind69ConSysctlEnNamespace(t *testing.T) {
	if os.Getenv("MACUA_BIND_FASE") != "" {
		t.Skip("ya es el subproceso")
	}
	for _, bin := range []string{"unshare", "setpriv", "ip", "sh"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip("falta ", bin)
		}
	}
	probe := "ip link set lo up && echo 1024 > /proc/sys/net/ipv4/ip_unprivileged_port_start"
	if out, err := exec.Command("unshare", "-rn", "sh", "-c", probe).CombinedOutput(); err != nil {
		t.Skipf("unshare -rn (lo up + sysctl) no disponible sin privilegios: %v %s", err, out)
	}
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	const sysctl = "/proc/sys/net/ipv4/ip_unprivileged_port_start"
	script := `ip link set lo up && echo 1024 > ` + sysctl + ` &&
MACUA_BIND_FASE=denied "$0" -test.run='^TestAyudanteBind69$' -test.v &&
echo 69 > ` + sysctl + ` &&
MACUA_BIND_FASE=ok "$0" -test.run='^TestAyudanteBind69$' -test.v`
	cmd := exec.Command("unshare", "-rn", "setpriv", "--bounding-set=-net_bind_service", "--inh-caps=-net_bind_service", "sh", "-c", script, self)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.Count(string(out), "--- PASS: TestAyudanteBind69") != 2 {
		t.Fatalf("%v\n%s", err, out)
	}
}
