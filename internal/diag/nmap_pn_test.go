package diag

import (
	"errors"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func nmapArgv(t *testing.T, opts map[string]string) (string, error) {
	t.Helper()
	localTest(t)
	_, argv, err := build(req(Nmap, "192.0.2.1", opts, ""), false)
	return strings.Join(argv, " "), err
}

func TestNmapSkipDiscoveryArgv(t *testing.T) {
	got, err := nmapArgv(t, map[string]string{"skip_discovery": "true"})
	if err != nil || got != "-sT -Pn -n -oG - 192.0.2.1" {
		t.Errorf("got %q, %v", got, err)
	}
	if base, _ := nmapArgv(t, nil); strings.Contains(base, "-Pn") || base != "-sT -n -oG - 192.0.2.1" {
		t.Errorf("sin la opción cambió el argv: %q", base)
	}
	if off, err := nmapArgv(t, map[string]string{"skip_discovery": "false"}); err != nil || strings.Contains(off, "-Pn") {
		t.Errorf("false: %q, %v", off, err)
	}
}

// Con -sn la opción se rechaza (es lo mínimo: no se descarta en silencio).
func TestNmapSkipDiscoveryConPingRechaza(t *testing.T) {
	_, err := nmapArgv(t, map[string]string{"scan": "ping", "skip_discovery": "true"})
	if !errCode(err, "diag.err.skip_with_ping") {
		t.Errorf("err = %v", err)
	}
}

func TestNmapSkipDiscoveryNoBooleano(t *testing.T) {
	for _, v := range []string{"yes", "-oN x", "", "2", "True"} {
		if got, err := nmapArgv(t, map[string]string{"skip_discovery": v}); !errCode(err, "diag.err.bool") {
			t.Errorf("valor %q: %q, %v", v, got, err)
		}
	}
}

func TestNmapZeroUp(t *testing.T) {
	for line, want := range map[string]bool{
		"# Nmap done at Tue Nov 17 10:00:00 2026 -- 1 IP address (0 hosts up) scanned in 0.50 seconds":  true,
		"# Nmap done at Tue Nov 17 10:00:00 2026 -- 1 IP address (1 host up) scanned in 0.50 seconds":   false,
		"# Nmap done at Tue Nov 17 10:00:00 2026 -- 1 IP address (10 hosts up) scanned in 0.50 seconds": false,
		"Nmap done: 1 IP address (0 hosts up) scanned in 0.50 seconds":                                  false,
		"Host: 127.0.0.1 ()\tStatus: Up": false,
	} {
		if NmapZeroUp(line) != want {
			t.Errorf("%q: quería %v", line, want)
		}
	}
}

func errCode(err error, code string) bool {
	var e *i18n.Error
	return errors.As(err, &e) && e.Code == code
}

// El primer error de opciones no lo tapa el rechazo de skip_discovery con scan=ping.
func TestNmapSkipDiscoveryNoTapaPrimerError(t *testing.T) {
	_, err := nmapArgv(t, map[string]string{"scan": "ping", "skip_discovery": "true", "timing": "9"})
	if !errCode(err, "diag.err.number") {
		t.Errorf("err = %v", err)
	}
}
