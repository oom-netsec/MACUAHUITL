package listen

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func bindErr(t *testing.T, goos string, errno error, port int) i18n.Coded {
	t.Helper()
	err := bindFor(goos, "listen", &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", errno)}, port)
	var c i18n.Coded
	if !errors.As(err, &c) {
		t.Fatalf("sin código: %v", err)
	}
	return c
}

func TestBindDeniedLinuxUsaElPuertoConMinimo21(t *testing.T) {
	for _, tc := range []struct {
		port int
		min  string
	}{{69, "69"}, {22, "22"}, {5, "21"}, {21, "21"}, {80, "80"}} {
		c := bindErr(t, "linux", syscall.EACCES, tc.port)
		m := c.Metadata()
		want := "echo 'net.ipv4.ip_unprivileged_port_start=" + tc.min + "' | sudo tee /etc/sysctl.d/60-macuahuitl.conf && sudo sysctl --system"
		if c.Reason() != "fileserve.err.port_denied" || m["min_port"] != tc.min || m["cmd"] != want || m["port"] != strconv.Itoa(tc.port) {
			t.Errorf("%d: %s %v", tc.port, c.Reason(), m)
		}
		for _, loc := range []string{i18n.Es, i18n.En} {
			s := c.Localize(loc)
			if !strings.Contains(s, want) || !strings.Contains(s, "sudo rm /etc/sysctl.d/60-macuahuitl.conf") || strings.Contains(s, "setcap") {
				t.Errorf("%s: %q", loc, s)
			}
		}
	}
}

func TestBindDeniedPuertoAltoOSinLinuxNoDaSysctl(t *testing.T) {
	for _, tc := range []struct {
		goos  string
		errno error
		port  int
	}{
		{"windows", syscall.Errno(10013), 69}, {"darwin", syscall.EACCES, 69}, {"linux", syscall.EACCES, 8080}, {"linux", syscall.EPERM, 8080},
	} {
		want := "fileserve.err.port_denied_win"
		if tc.goos == "linux" {
			want = "fileserve.err.port_denied_linux"
		}
		c := bindErr(t, tc.goos, tc.errno, tc.port)
		if c.Reason() != want || c.Metadata()["cmd"] != "" || c.Metadata()["port"] != strconv.Itoa(tc.port) {
			t.Errorf("%v: %s %v", tc, c.Reason(), c.Metadata())
		}
		if s := c.Localize(i18n.Es); strings.Contains(s, "sysctl") || (tc.goos == "linux" && strings.Contains(s, "firewall")) {
			t.Errorf("%v: %q", tc, s)
		}
	}
}

func TestBindEnUso(t *testing.T) {
	for _, tc := range []struct {
		goos  string
		errno error
	}{{"linux", syscall.EADDRINUSE}, {"windows", syscall.Errno(10048)}} {
		c := bindErr(t, tc.goos, tc.errno, 22)
		s := c.Localize(i18n.Es)
		if c.Reason() != "fileserve.err.port_in_use" || c.Metadata()["port"] != "22" || strings.Contains(s, "sysctl") {
			t.Errorf("%v: %s %v %q", tc, c.Reason(), c.Metadata(), s)
		}
	}
}

func TestBindOtroErrorSeConserva(t *testing.T) {
	orig := errors.New("boom")
	err := bindFor("linux", "listen", orig, 69)
	if !errors.Is(err, orig) || err.Error() != fmt.Sprintf("listen: %v", orig) {
		t.Errorf("%v", err)
	}
}

// Golden: el texto exacto de los errores de bind en español y en inglés.
func TestBindTextosGolden(t *testing.T) {
	const cmd = "echo 'net.ipv4.ip_unprivileged_port_start=69' | sudo tee /etc/sysctl.d/60-macuahuitl.conf && sudo sysctl --system"
	denied := bindErr(t, "linux", syscall.EACCES, 69)
	inUse := bindErr(t, "linux", syscall.EADDRINUSE, 22)
	for _, tc := range []struct {
		name string
		c    i18n.Coded
		loc  string
		want string
	}{
		{"denied es", denied, i18n.Es, "no se pudo abrir el puerto 69: el kernel no deja a un proceso sin privilegios abrir puertos bajos. Corre UNA vez esta orden y vuelve a intentar: " + cmd + "\nAdvertencia: el cambio es persistente y, desde el 69 hasta el 1023, cualquier proceso sin privilegios, de cualquier usuario, podrá abrir esos puertos. Para deshacerlo: sudo rm /etc/sysctl.d/60-macuahuitl.conf && sudo sysctl -w net.ipv4.ip_unprivileged_port_start=1024\nAlternativa: usa un puerto de 1024 o más."},
		{"denied en", denied, i18n.En, "could not open port 69: the kernel does not let an unprivileged process open low ports. Run this command ONCE and try again: " + cmd + "\nWarning: the change is persistent and, from port 69 up to 1023, any unprivileged process of any user will be able to open those ports. To undo it: sudo rm /etc/sysctl.d/60-macuahuitl.conf && sudo sysctl -w net.ipv4.ip_unprivileged_port_start=1024\nAlternative: use a port of 1024 or higher."},
		{"in_use es", inUse, i18n.Es, "el puerto 22 ya lo usa otro servicio; elige otro puerto o detén ese servicio"},
		{"in_use en", inUse, i18n.En, "port 22 is already used by another service; choose another port or stop that service"},
	} {
		if got := tc.c.Localize(tc.loc); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

// 43d-3 (4.8): el sysctl solo lleva dígitos que salen de un entero; el prefijo y el error hostiles no llegan a cmd.
func TestBindSysctlSoloDigitos(t *testing.T) {
	cmdRe := regexp.MustCompile(`^echo 'net\.ipv4\.ip_unprivileged_port_start=\d+' \| sudo tee /etc/sysctl\.d/60-macuahuitl\.conf && sudo sysctl --system$`)
	for _, port := range []int{-1, 1, 20, 21, 22, 69, 1023, 1024} {
		err := bindFor("linux", "li'sten;$(x)\u202e\n", &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EACCES)}, port)
		var c i18n.Coded
		if !errors.As(err, &c) {
			t.Fatalf("%d: sin código: %v", port, err)
		}
		cmd := c.Metadata()["cmd"]
		if port >= 1024 {
			if cmd != "" {
				t.Errorf("%d: cmd sin sysctl esperado: %q", port, cmd)
			}
			continue
		}
		if !cmdRe.MatchString(cmd) {
			t.Errorf("%d: cmd no es solo dígitos: %q", port, cmd)
		}
	}
}
