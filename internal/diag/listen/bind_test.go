package listen

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func bindErr(t *testing.T, goos string, errno error, ports ...int) i18n.Coded {
	t.Helper()
	err := bindFor(goos, "listen", &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", errno)}, ports)
	var c i18n.Coded
	if !errors.As(err, &c) {
		t.Fatalf("sin código: %v", err)
	}
	return c
}

func TestBindDeniedLinuxUsaElPuertoMasBajoConMinimo21(t *testing.T) {
	for _, tc := range []struct {
		ports []int
		min   string
	}{
		{[]int{69}, "69"}, {[]int{80, 69}, "69"}, {[]int{69, 80}, "69"}, {[]int{22}, "22"}, {[]int{5, 80}, "21"}, {[]int{21, 80}, "21"},
	} {
		c := bindErr(t, "linux", syscall.EACCES, tc.ports...)
		m := c.Metadata()
		want := "echo 'net.ipv4.ip_unprivileged_port_start=" + tc.min + "' | sudo tee /etc/sysctl.d/60-macuahuitl.conf && sudo sysctl --system"
		if c.Reason() != "fileserve.err.port_denied" || m["min_port"] != tc.min || m["cmd"] != want || m["port"] != strconv.Itoa(tc.ports[0]) {
			t.Errorf("%v: %s %v", tc.ports, c.Reason(), m)
		}
		for _, loc := range []string{i18n.Es, i18n.En} {
			s := c.Localize(loc)
			if !strings.Contains(s, want) || strings.Contains(s, "setcap\n") || strings.Contains(s, "nft") == false {
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
		c := bindErr(t, tc.goos, tc.errno, tc.port)
		if c.Reason() != "fileserve.err.port_denied_win" || c.Metadata()["cmd"] != "" || c.Metadata()["port"] != strconv.Itoa(tc.port) {
			t.Errorf("%v: %s %v", tc, c.Reason(), c.Metadata())
		}
		if s := c.Localize(i18n.Es); strings.Contains(s, "sysctl") {
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
		if c.Reason() != "fileserve.err.port_in_use" || c.Metadata()["port"] != "22" || strings.Contains(s, "sysctl") || !strings.Contains(s, "sshd") {
			t.Errorf("%v: %s %v %q", tc, c.Reason(), c.Metadata(), s)
		}
	}
}

func TestBindOtroErrorSeConserva(t *testing.T) {
	orig := errors.New("boom")
	err := bindFor("linux", "listen", orig, []int{69})
	if !errors.Is(err, orig) || err.Error() != fmt.Sprintf("listen: %v", orig) {
		t.Errorf("%v", err)
	}
}
