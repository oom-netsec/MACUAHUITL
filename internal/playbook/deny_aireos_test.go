package playbook

import (
	"errors"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Cisco AireOS 8.x (Command Reference 8.10, sin validar en laboratorio): lista blanca de lectura.
func TestCheckDeniedAireOSRechaza(t *testing.T) {
	for _, cmd := range []string{
		// no son lectura
		"config paging disable", "config wlan disable 1", "config", "save config", "reset system", "transfer download start", "debug client aa:bb:cc:dd:ee:ff",
		"clear stats ap", "test pmk-cache delete all", "logout", "restart", "cd /", "linktest aa:bb:cc:dd:ee:ff", "eping 10.0.0.1", "mping 10.0.0.1",
		"CONFIG paging disable", "sh sysinfo", "sho sysinfo", "s sysinfo", "",
		// show run-config pregunta y/N (y sus abreviaturas)
		"show run-config", "show run-config commands", "show run-config no-ap", "show run-conf", "show ru", "show run", "show run-c commands",
		// y/n sueltos al final: contestarían una pregunta de confirmación
		"show sysinfo y", "show sysinfo n", "show sysinfo Y", "show wlan summary N",
		// pipe y redirección (reglas comunes y propias: AireOS no tiene pipe)
		"show sysinfo | include x", "show sysinfo |", "show sysinfo > x", "show sysinfo ; reload",
		// ping solo IP, count y size acotados
		"ping", "ping host.example.com", "ping 10.0.0.1 count 11", "ping 10.0.0.1 count 0", "ping 10.0.0.1 size 1501", "ping 10.0.0.1 count 2 count 3",
		"ping 10.0.0.1 repeat 2", "ping 255.255.255.255", "ping 0.0.0.0", "ping 224.0.0.1", "ping 10.0.0.1 extra", "ping 10.0.0.1 count", "ping y", "ping 10.0.0.1 y",
		// show con rutas remotas o signo de ayuda
		"show sysinfo tftp://h/x", "show tech-support ftp:x", "show sysinfo ?",
		// comillas fuera del grep
		"show \"sysinfo\"", "show sysinfo \"x\"",
		// grep: solo include|exclude "patrón" "show …"
		"grep", "grep include", "grep include \"x\"", "grep include x \"show sysinfo\"", "grep include \"x\" show sysinfo", "grep \"x\" \"show sysinfo\"",
		"grep begin \"x\" \"show sysinfo\"", "grep include \"x\" \"show sysinfo\" extra", "grep include \"x\" \"show sysinfo\" y",
		"grep include \"x\" \"config paging disable\"", "grep include \"x\" \"config wlan disable 1\"", "grep include \"x\" \"debug all\"", "grep include \"x\" \"save config\"",
		"grep include \"x\" \"show run-config\"", "grep include \"x\" \"show sysinfo y\"", "grep include \"x\" \"ping 10.0.0.1\"", "grep include \"x\" \"grep include \\\"y\\\" \\\"show sysinfo\\\"\"",
		"grep include \"x\" \"show sysinfo\" \"show wlan summary\"", "grep include \"x\" \"show \"sysinfo\"\"", "grep include \"x\" \"\"", "grep include \"x\" \"show\" y",
		"grep include \"a\"b\" \"show sysinfo\"", "grep include \"x\" \"show sysinfo | include y\"", "grep include \"x\" \"show sysinfo tftp://h/x\"",
		"grep include \"x\" \" config paging disable\"", "grep include \"x\" \"sh sysinfo\"", "grep include \"x|y\" \"show sysinfo\"",
	} {
		if err := CheckDenied("wlc-aireos", cmd); !errors.Is(err, ErrDenied) {
			t.Errorf("%q: se aceptó (err=%v)", cmd, err)
		}
	}
}

func TestCheckDeniedAireOSAcepta(t *testing.T) {
	for _, cmd := range []string{
		"show sysinfo", "SHOW SYSINFO", "show wlan summary", "show ap summary", "show client summary", "show client detail aa:bb:cc:dd:ee:ff", "show wlan 1",
		"show radius summary", "show mobility summary", "show interface summary", "show 802.11a", "show advanced 802.11a summary", "show tech-support", "show logging",
		"show ap config general {ap}", "show client detail {mac}", "show wlan {wlan}", "show run-config-not-this", "show cdp neighbors",
		"ping 10.0.0.1", "ping 10.0.0.1 count 5 size 100", "ping 10.0.0.1 size 1500 count 10", "ping {ip}", "ping 2001:db8::1", "PING 10.0.0.1",
		"grep include \"error\" \"show logging\"", "grep exclude \"up\" \"show interface summary\"", "grep include \"AP-1\" \"show ap summary\"",
		"grep include \"{ap}\" \"show ap summary\"", "grep include \"^a.*b$\" \"show client summary\"", "GREP INCLUDE \"x\" \"show sysinfo\"",
	} {
		if err := CheckDenied("wlc-aireos", cmd); err != nil {
			t.Errorf("%q: rechazado: %v", cmd, err)
		}
	}
}

// Las reglas de AireOS no cambian a las demás plataformas.
func TestCheckDeniedAireOSNoCambiaOtras(t *testing.T) {
	for _, p := range []string{"ios", "ios-xe", "asa", "ftd", "nx-os"} {
		if err := CheckDenied(p, "grep include \"x\" \"show version\""); err == nil {
			t.Errorf("%s: grep no es suyo", p)
		}
	}
	if err := CheckDenied("ios-xe", "show version | section a"); err != nil {
		t.Error(err)
	}
}

func TestMotivosAireOS(t *testing.T) {
	for cmd, want := range map[string]string{
		"config paging disable": "playbook.why.not_read", "show sysinfo | include x": "playbook.why.pipe_aireos",
		"show run-config": "playbook.why.confirm_aireos", "show sysinfo y": "playbook.why.confirm_aireos",
		"ping 10.0.0.1 count 99": "playbook.why.probe_aireos", "grep include \"x\" \"config x\"": "playbook.why.grep_aireos",
		"show sysinfo tftp://h/x": "playbook.why.remote",
	} {
		d, ok := CheckDenied("wlc-aireos", cmd).(deniedErr)
		if !ok {
			t.Errorf("%q: no se rechazó", cmd)
			continue
		}
		if c, ok := d.e.Cause.(*i18n.Error); !ok || c.Code != want {
			t.Errorf("%q: motivo %v, se esperaba %s", cmd, d.e.Cause, want)
		}
	}
}
