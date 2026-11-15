package playbook

import (
	"errors"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Cisco ASA (comandos de la Command Reference 9.x, sin validar en laboratorio): lista blanca de lectura.
func TestCheckDeniedASARechaza(t *testing.T) {
	for _, cmd := range []string{
		// no son lectura
		"more system:running-config", "mo system:running-config", "copy running-config disk0:x", "write memory", "wr mem", "reload",
		"configure terminal", "conf t", "clear xlate", "clear conn", "debug icmp trace", "undebug all", "no debug all", "capture x interface inside",
		"changeto context admin", "failover active", "failover reload-standby", "cluster exec show version", "test aaa-server authentication srv host 10.0.0.1 username u password p",
		"vpn-sessiondb logoff all", "shun 10.0.0.1", "delete disk0:x", "erase disk0:", "format disk0:", "verify disk0:x", "ssh 10.0.0.1", "telnet 10.0.0.1",
		"login", "enable", "crypto key generate rsa", "call-home send alert-group all", "perfmon interval 5", "exit", "who",
		// abreviaturas: el primer comando va completo (show acepta sh y sho)
		"s version", "pi 10.0.0.1", "pin 10.0.0.1", "tr 10.0.0.1", "trace 10.0.0.1", "packet-t input inside tcp 1.1.1.1 1 2.2.2.2 80", "p input inside tcp 1.1.1.1 1 2.2.2.2 80",
		"di", "ter pager 0", "term pager 0",
		// terminal: solo pager y width
		"terminal monitor", "terminal length 0", "terminal", "terminal pager", "terminal pager x", "terminal width", "terminal pager 0 0", "terminal pa 0",
		// show: file y rutas remotas
		"show tech-support file disk0:x", "show tech-support f disk0:x", "show tech-support fil x", "sh tech-support file x",
		"show running-config tftp://h/x", "dir ftp://h/x", "show file ftp:x", "dir tftp:",
		// pipes
		"show version |", "show version | redirect disk0:x", "show version | tee x", "show version | append x", "show version | foo", "show version | section x", "show version | sec x",
		"show version | include", "show version | grep -v", "show version | include redirect x", "show version | include red x", "show version | include t x",
		"show version | include a | redirect x", "show version | grep -v append x", "show version | s a", "| include a", "show version | count", "show version | j",
		// ping
		"ping", "ping tcp", "ping 255.255.255.255", "ping 0.0.0.0", "ping ::", "ping 224.0.0.1", "ping fe80::1", "ping inside 255.255.255.255",
		"ping 10.0.0.1 repeat 11", "ping 10.0.0.1 repeat 0", "ping 10.0.0.1 timeout 11", "ping 10.0.0.1 size 27", "ping 10.0.0.1 size 1501", "ping 10.0.0.1 repeat 2 repeat 3",
		"ping 10.0.0.1 data 0x1", "ping 10.0.0.1 validate", "ping 10.0.0.1 repeat", "ping 10.0.0.1 count 3", "ping interface inside 10.0.0.1", "ping i 10.0.0.1", "ping t 10.0.0.1",
		"ping a b c", "ping inside", "ping ipv6 1.1.1.1", "ping ipv6 inside 1.1.1.1", "ping ::ffff:255.255.255.255", "ping ::ffff:224.0.0.1", "ping ::ffff:0.0.0.0", "traceroute ipv6", "traceroute ipv6 1.1.1.1", "traceroute ::ffff:255.255.255.255", "ping 10.0.0.1/24", "ping inside 10.0.0.1 extra",
		"ping tcp 10.0.0.1", "ping tcp inside 10.0.0.1", "ping tcp 10.0.0.1 99999", "ping tcp 10.0.0.1 80 count 11", "ping tcp 10.0.0.1 80 repeat 2", "ping tcp 10.0.0.1 80 size 50",
		"ping tcp inside 10.0.0.1 80 count 2 count 3", "ping tcp inside 255.255.255.255 80", "ping tcp inside 10.0.0.1 80 timeout 11",
		// traceroute
		"traceroute", "traceroute 255.255.255.255", "traceroute 0.0.0.0", "traceroute 10.0.0.1 repeat 2", "traceroute 10.0.0.1 timeout 11", "traceroute 10.0.0.1 probe 6",
		"traceroute 10.0.0.1 probe 0", "traceroute 10.0.0.1 source", "traceroute 10.0.0.1 numeric numeric", "traceroute 10.0.0.1 port 80", "traceroute 10.0.0.1 ttl 1 5",
		"traceroute 10.0.0.1 source !!", "traceroute 224.0.0.1",
		// packet-tracer
		"packet-tracer", "packet-tracer input", "packet-tracer input inside", "packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2",
		"packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2 80 detailed xml", "packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2 80 xml detailed",
		"packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2 80 detailed disk0:x", "packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2 80 xml tftp://h/x",
		"packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2 80 detailed | redirect disk0:x", "packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2 80 transmit",
		"packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2 80 persist", "packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2 80 vlan-id 5", "packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2 80 inline-tag 5",
		"packet-tracer input inside rawip 1.1.1.1 47 2.2.2.2", "packet-tracer input inside rawip 1.1.1.1 47 2.2.2.2 80", "packet-tracer input inside tcp host1 1000 2.2.2.2 80", "packet-tracer input inside tcp 1.1.1.1 99999 2.2.2.2 80",
		"packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2 80 d", "packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2 http;x", "packet-tracer in inside tcp 1.1.1.1 1000 2.2.2.2 80",
		"packet-tracer input inside icmp 1.1.1.1 8 0", "packet-tracer input inside icmp 1.1.1.1 256 0 2.2.2.2", "packet-tracer input inside icmp 1.1.1.1 8 300 2.2.2.2",
		"packet-tracer input inside icmp 1.1.1.1 8 0 2.2.2.2 xml xml", "packet-tracer input inside icmp 1.1.1.1 8 0 2.2.2.2 detailed disk0:x", "packet-tracer input inside icmp 1.1.1.1 8 0 host",
		"packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2 80 detailed xml disk0:x",
		// comunes
		"show version ; reload", "show version > disk0:x", "show version | include `x`", "show \x01version",
	} {
		if err := CheckDenied("asa", cmd); !errors.Is(err, ErrDenied) {
			t.Errorf("%q: se aceptó (err=%v)", cmd, err)
		}
	}
}

func TestCheckDeniedASAAcepta(t *testing.T) {
	for _, cmd := range []string{
		"show version", "sh version", "sho version", "SHOW VERSION", "show running-config", "show tech-support", "show tech-support detail", "show failover", "show conn count",
		"show interface ip brief | include up", "show running-config | grep -v ^!", "show xlate | include 10.0.0.1|10.0.0.2", "show access-list | begin inside",
		"show conn | exclude 10.0.0.1", "show run | i interface", "show run | in x | b", "show version | grep -v ^$", "show running-config | include ^ping$", "show filesystem",
		"show asp drop", "show crypto ikev2 sa", "show vpn-sessiondb anyconnect", "show context", "dir", "dir disk0:", "dir /recursive disk0:", "",
		"terminal pager 0", "terminal width 511", "terminal width 80",
		"ping 10.0.0.1", "ping inside 10.0.0.1", "ping switch1.example.com", "ping inside switch1", "ping inside host.example.com", "ping 10.0.0.1 repeat 5 timeout 2 size 100", "ping inside 10.0.0.1 repeat 10 timeout 10 size 1500", "ping 2001:db8::1",
		"ping inside 10.0.0.1 size 28", "ping tcp 10.0.0.1 80", "ping tcp inside 10.0.0.1 443 count 3 timeout 5", "ping tcp inside 10.0.0.1 https", "ping tcp 10.0.0.1 65535", "ping {ip}", "ping {interface} {ip} repeat 3",
		"ping 10.0.0.1 | include !", "traceroute 10.0.0.1", "traceroute switch1.example.com numeric", "traceroute 10.0.0.1 source inside timeout 3 probe 2 use-icmp numeric", "traceroute 10.0.0.1 source 10.0.0.2", "traceroute {ip}",
		"packet-tracer input inside tcp 10.0.0.1 1025 192.0.2.5 80", "packet-tracer input inside tcp 10.0.0.1 1025 192.0.2.5 https detailed", "packet-tracer input inside udp 10.0.0.1 1025 192.0.2.5 53 xml",
		"packet-tracer input inside icmp 10.0.0.1 8 0 192.0.2.5", "packet-tracer input outside icmp 10.0.0.1 8 0 192.0.2.5 detailed", "packet-tracer input {interface} tcp {ip} 1025 192.0.2.5 80",
		"packet-tracer input inside tcp 2001:db8::1 1025 2001:db8::2 80", "packet-tracer input inside tcp 10.0.0.1 1025 192.0.2.5 80 | include Action",
	} {
		if err := CheckDenied("asa", cmd); err != nil {
			t.Errorf("%q: rechazado: %v", cmd, err)
		}
	}
}

// Las reglas de ASA no se aplican a otras plataformas ni al revés.
func TestCheckDeniedASANoCambiaOtras(t *testing.T) {
	if err := CheckDenied("ios-xe", "pi 10.0.0.1"); err != nil {
		t.Error(err)
	}
	if err := CheckDenied("ios-xe", "show version | section a"); err != nil {
		t.Error(err)
	}
	if err := CheckDenied("asa", "show version | section a"); err == nil {
		t.Error("section no es de ASA")
	}
}

func TestMotivosASA(t *testing.T) {
	for cmd, want := range map[string]string{
		"more system:running-config": "playbook.why.not_read", "show tech-support file x": "playbook.why.show_file_asa",
		"show version | redirect x": "playbook.why.pipe_filter_asa", "show version | include redirect x": "playbook.why.pipe_sink",
		"ping 10.0.0.1 repeat 99": "playbook.why.probe_asa", "packet-tracer input a tcp 1.1.1.1 1 2.2.2.2 3 transmit": "playbook.why.tracer_asa",
		"terminal length 0": "playbook.why.terminal_asa", "dir ftp://h/x": "playbook.why.remote",
	} {
		d, ok := CheckDenied("asa", cmd).(deniedErr)
		if !ok {
			t.Errorf("%q: no se rechazó", cmd)
			continue
		}
		if c, ok := d.e.Cause.(*i18n.Error); !ok || c.Code != want {
			t.Errorf("%q: motivo %v, se esperaba %s", cmd, d.e.Cause, want)
		}
	}
}

// Destinos de escritura de la otra familia: «file» en ASA, «to-file» (y prefijos) en IOS/IOS-XE.
func TestWritesOnOtherFamily(t *testing.T) {
	for cmd, want := range map[string]bool{
		"show logging process ios to-file bootflash:x": true, "show x to-f flash:x": true, "show x t y": true,
		"show tech-support file disk0:x": true, "show tech-support fil x": true, "show tech-support f x": true,
		"show ip interface brief | section x": false, "show conn count": false, "show running-config | include file": false,
		"show tech-support | include to-file": false, "show file systems": false, "show file information x": false, "show file descriptors": false, "show fil systems": false, "show x file y": true, "show version": false, "": false,
	} {
		if got := WritesOnOtherFamily(cmd); got != want {
			t.Errorf("%q: %v, se esperaba %v", cmd, got, want)
		}
	}
}

// Un segundo «|» tras el filtro no puede abrir un sumidero (redirect, append, tee) ni la parte del pipe nombrar una ruta
// del equipo o remota: algunas versiones de ASA aceptan esos sumideros en show. Una palabra «redirect» dentro de la
// regex, sin «|» delante, sigue valiendo.
func TestASASegundoPipeNoAbreSumidero(t *testing.T) {
	for _, c := range []string{
		"show run | i x | redirect disk0:/a",
		"show run | i x | append flash:/a",
		"sh run | g -v x | tee disk0:a",
		"show run | i x | r disk0:/a",
		"show run | i x|redirect disk0:/a",
		"show run | i x disk0:/a",
		"show run | i system:running-config",
		"show run | i x | tee a.txt",
		"show run | i x | app a.txt",
		"show run | i x tftp://10.0.0.1/a",
	} {
		if CheckDenied("asa", c) == nil {
			t.Errorf("debió rechazarse: %q", c)
		}
	}
	for _, c := range []string{"show run | i redirect", "show run | i up|down", "show conn | i 10.0.0.1"} {
		if err := CheckDenied("asa", c); err != nil {
			t.Errorf("debió permitirse %q: %v", c, err)
		}
	}
}

// Una ruta del equipo en el pipe tiene su propio motivo: no es una ruta remota.
func TestASARutaDelEquipoTieneMotivoPropio(t *testing.T) {
	motivo := func(plat, cmd string) string {
		d, ok := CheckDenied(plat, cmd).(deniedErr)
		if !ok {
			return ""
		}
		c, _ := d.e.Cause.(*i18n.Error)
		if c == nil {
			return ""
		}
		return c.Code
	}
	for _, plat := range []string{"asa", "ftd"} {
		cmd := "show running-config | include x disk0:/a"
		if r := motivo(plat, cmd); r != "playbook.why.local_path" {
			t.Errorf("%s: motivo %q", plat, r)
		}
		err := CheckDenied(plat, cmd)
		if es, en := i18n.In("es", err), i18n.In("en", err); !strings.Contains(es, "ruta del equipo") || !strings.Contains(en, "device path") {
			t.Errorf("%s:\n es=%s\n en=%s", plat, es, en)
		}
	}
	if r := motivo("asa", "show running-config | include x tftp://10.0.0.1/a"); r != "playbook.why.remote" {
		t.Errorf("tftp: motivo %q", r)
	}
}

// Tras el segundo «|» de un ASA o FTD tampoco van los comandos de shell de NX-OS (sscp, email, vsh, bash, python).
func TestFamiliaASARechazaShellEnPipesPosteriores(t *testing.T) {
	for _, p := range []string{"asa", "ftd"} {
		for _, cmd := range []string{
			"show version | include x | sscp conn1 out.txt", "show version | include x | email a@b.c", "show version | include x | vsh",
			"show version | include x | bash", "show version | include x | python",
		} {
			if err := CheckDenied(p, cmd); !errors.Is(err, ErrDenied) {
				t.Errorf("%s %q: se aceptó (err=%v)", p, cmd, err)
			}
		}
		for _, cmd := range []string{"show run | include x", "show conn count", "show run | in x | b", "show xlate | include 10.0.0.1|10.0.0.2"} {
			if err := CheckDenied(p, cmd); err != nil {
				t.Errorf("%s %q: se rechazó (%v)", p, cmd, err)
			}
		}
	}
}
