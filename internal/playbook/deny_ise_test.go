package playbook

import (
	"errors"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Cisco ISE 3.x, CLI ADE-OS (CLI Reference 3.1-3.4, sin validar en laboratorio): lista blanca de lectura.
func TestCheckDeniedISERechaza(t *testing.T) {
	for _, cmd := range []string{
		// application, reload, copias, parches y todo lo que cambia estado
		"application stop ise", "application start ise", "application reset-config ise", "application configure ise",
		"application install x.tar.gz repo", "application upgrade x repo", "application remove ise", "application status ise",
		"reload", "halt", "copy running-config disk:/x", "backup x repository r", "restore x repository r", "patch install x.tar.gz repo",
		"patch remove ise 1", "configure terminal", "conf t", "debug all", "undebug all", "clock set 10:00:00", "crypto key generate rsa",
		"password", "ssh host", "telnet host", "ftp host", "sftp host", "scp x y", "clear logging", "delete disk:/x", "mkdir x", "rmdir x",
		"write memory", "tech dumptcp 1", "tech top", "tech", "license esn", "dir disk:/", "dir ftp://h/x", "dir", "more disk:/x", "ping6 ::1",
		"SHOW version tail", "sh version", "s version", "", "exit", "end", "nslookup", "nslookup a b", "traceroute", "traceroute a b",
		// tail, file, rutas y show top
		"show logging system tail", "show logging application ise-psc.log tail", "show logging system TAIL", "show tail", "show logging tai",
		"show tech-support file disk:/x", "show tech-support fi x", "show file x", "show running-config file x", "show repository r ftp://h/x",
		"show top", "show to", "show TOP", "show version disk:/x", "show version localdisk:x", "show version tftp://h/x", "show version https://h/x",
		// abreviaturas de una letra de tail y file; show t solo es ambiguo
		"show logging system t", "show logging application ise-psc.log t", "show tech-support f x", "show logging system ta", "show f x", "show t",
		// show repository con argumento lista el repositorio remoto
		"show repository myrepo", "show repo myrepo", "show rep x",
		// destinos numéricos abreviados u hexadecimales
		"ping 224.1", "ping 4294967295", "ping 0xffffffff", "ping 127.1", "ping 0177.0.0.1", "ping 0xff.1.1.1", "ping a:b", "traceroute 224.1", "nslookup 0xffffffff", "nslookup 4294967295",
		// ?, ;, >, `
		"show version ?", "show version ; reload", "show version > x", "show `x`",
		// pipe: un operador de la lista, sin sumideros ni segundas tuberías
		"show version |", "show version | redirect disk:/x", "show version | tee x", "show version | append x", "show version | sed x", "show version | include",
		"show version | include a | redirect x", "show version | include a|b", "show version | count x", "show version | last x", "show version | last 1 2",
		"show version | last -1", "show version | grep x", "show version | i x", "show version | inc x", "show version | include disk:/x",
		"show version | include ftp://h/x", "show version | begin tftp:x", "show version | section x", "| include x", "show version | last 1.5",
		// terminal solo length 0
		"terminal length 24", "terminal length", "terminal width 80", "terminal monitor", "terminal length 0 x", "terminal", "terminal length 0 | include x", "term length 0",
		// ping / traceroute / nslookup acotados
		"ping", "ping 0.0.0.0", "ping 255.255.255.255", "ping 224.0.0.1", "ping ff02::1", "ping ::", "ping 169.254.1.1", "ping fe80::1", "ping ::ffff:255.255.255.255",
		"ping 10.0.0.1 pingcount 11", "ping 10.0.0.1 pingcount 0", "ping 10.0.0.1 count 11", "ping 10.0.0.1 packetsize 1501", "ping 10.0.0.1 pingcount 2 pingcount 3",
		"ping 10.0.0.1 extra", "ping 10.0.0.1 pingcount", "ping 10.0.0.1 df 1", "ping -f 10.0.0.1", "ping $(x)", "ping 10.0.0.1 | redirect x",
		"traceroute 0.0.0.0", "traceroute 224.0.0.1", "traceroute 255.255.255.255", "traceroute 10.0.0.1 -m 99", "nslookup 224.0.0.1", "nslookup ::", "nslookup a/b",
		"nslookup 10.0.0.1 server x", "nslookup -type=any x",
	} {
		if err := CheckDenied("ise", cmd); !errors.Is(err, ErrDenied) {
			t.Errorf("%q: se aceptó (err=%v)", cmd, err)
		}
	}
}

func TestCheckDeniedISEAcepta(t *testing.T) {
	for _, cmd := range []string{
		"show version", "SHOW VERSION", "show application status ise", "show application version ise", "show cpu", "show cpu usage", "show memory", "show disks",
		"show uptime", "show timezone", "show ntp", "show interface", "show interface GigabitEthernet 0", "show ip route", "show running-config", "show repository",
		"show inventory", "show udi", "show logging system", "show logging application", "show logging application ise-psc.log", "show tech-support", "show ntp | include synchronised",
		"show logging system | last 100", "show logging application ise-psc.log | last 200", "show logging system | include error", "show logging system | exclude info",
		"show logging system | begin Nov", "show logging system | count", "show logging system | end x", "show version | include ISE", "show version | include Version : 3", "show repository",
		"show logging system | include Error code=5", "show logging application | exclude disk0 files", "show patch", "show udi", "show tech-support | last 50",
		"show ip name-server", "show ports", "show users", "show running-config | include hostname",
		"ping 10.0.0.1", "ping host-1.example.com", "ping ise-node1", "PING 10.0.0.1", "ping 2001:db8::1", "ping 10.0.0.1 pingcount 5", "ping 10.0.0.1 count 5",
		"ping 10.0.0.1 packetsize 100 pingcount 10", "ping {ip}", "ping 10.0.0.1 | include loss", "traceroute 10.0.0.1", "traceroute {ip}", "traceroute host.example.com",
		"nslookup host.example.com", "nslookup 10.0.0.1", "nslookup {nombre}", "terminal length 0", "TERMINAL LENGTH 0",
	} {
		if err := CheckDenied("ise", cmd); err != nil {
			t.Errorf("%q: rechazado: %v", cmd, err)
		}
	}
}

// Las reglas de ISE no cambian a las demás plataformas.
func TestCheckDeniedISENoCambiaOtras(t *testing.T) {
	for _, p := range []string{"ios", "ios-xe", "asa", "ftd", "wlc-aireos"} {
		if err := CheckDenied(p, "application status ise"); err == nil {
			t.Errorf("%s: application no es suyo", p)
		}
		if err := CheckDenied(p, "nslookup host.example.com"); err == nil {
			t.Errorf("%s: nslookup no es suyo", p)
		}
	}
	if err := CheckDenied("ios-xe", "show version | section a"); err != nil {
		t.Error(err)
	}
	if err := CheckDenied("ios-xe", "terminal length 0"); err != nil {
		t.Error(err)
	}
}

func TestMotivosISE(t *testing.T) {
	for cmd, want := range map[string]string{
		"application stop ise": "playbook.why.not_read", "show logging system tail": "playbook.why.show_ise", "show top": "playbook.why.show_ise",
		"show tech-support file disk:/x": "playbook.why.show_ise", "show version | redirect x": "playbook.why.pipe_ise", "show version | include a | include b": "playbook.why.pipe_ise",
		"terminal length 24": "playbook.why.terminal_ise", "ping 224.0.0.1": "playbook.why.probe_ise", "ping 10.0.0.1 pingcount 99": "playbook.why.probe_ise",
		"nslookup a b": "playbook.why.probe_ise", "show version tftp://h/x": "playbook.why.remote", "show version disk:/x": "playbook.why.local_path",
		"show version ?": "playbook.why.show_ise",
	} {
		d, ok := CheckDenied("ise", cmd).(deniedErr)
		if !ok {
			t.Errorf("%q: no se rechazó", cmd)
			continue
		}
		if c, ok := d.e.Cause.(*i18n.Error); !ok || c.Code != want {
			t.Errorf("%q: motivo %v, se esperaba %s", cmd, d.e.Cause, want)
		}
	}
}

// Los playbooks de ISE solo corren en ISE y ningún otro usa los suyos.
func TestCompatibleISE(t *testing.T) {
	if !Compatible("ise", "ise") {
		t.Error("ise consigo misma")
	}
	for _, p := range []string{"ios", "ios-xe", "wlc-9800", "asa", "ftd", "nx-os", "wlc-aireos", "cat9k", "sda"} {
		if Compatible("ise", p) || Compatible(p, "ise") {
			t.Errorf("%s no es compatible con ise", p)
		}
	}
}

// Los destinos numéricos abreviados u hexadecimales también se rechazan en asa y ftd; los nombres y las IP completas pasan.
func TestDestinosNumericosAbreviados(t *testing.T) {
	for _, p := range []string{"asa", "ftd", "ise"} {
		for _, cmd := range []string{"ping 224.1", "ping 4294967295", "ping 0xffffffff", "ping 127.1", "ping 0177.0.0.1"} {
			if err := CheckDenied(p, cmd); err == nil {
				t.Errorf("%s %q: se aceptó", p, cmd)
			}
		}
		for _, cmd := range []string{"ping 10.0.0.1", "ping host.example.com", "ping 2001:db8::1", "ping 1.2.3.4.nip.io"} {
			if err := CheckDenied(p, cmd); err != nil {
				t.Errorf("%s %q: %v", p, cmd, err)
			}
		}
	}
}

// Un FQDN con punto final es un nombre válido (asa, ftd e ise).
func TestDestinoFQDNConPuntoFinal(t *testing.T) {
	for p, cmd := range map[string]string{"asa": "ping inside host.example.com.", "ftd": "ping host.example.com.", "ise": "ping host.example.com."} {
		if err := CheckDenied(p, cmd); err != nil {
			t.Errorf("%s %q: %v", p, cmd, err)
		}
	}
	for _, cmd := range []string{"ping host.example.com..", "ping .", "ping 224.1.", "ping 0xff."} {
		if err := CheckDenied("ise", cmd); err == nil {
			t.Errorf("%q: se aceptó", cmd)
		}
	}
}
