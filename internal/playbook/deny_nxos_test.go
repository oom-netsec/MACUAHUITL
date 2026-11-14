package playbook

import (
	"errors"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"testing"
)

// NX-OS: lista blanca de primer comando, sin redirecciones ni sumideros de pipe, ping/traceroute acotados.
func TestCheckDeniedNXOSRechaza(t *testing.T) {
	for _, cmd := range []string{
		"run bash ls", "bash", "guestshell", "python", "python3", "source x", "tclsh", "copy running-config bootflash:x",
		"write memory", "reload", "install all nxos x", "feature bgp", "configure terminal", "conf t", "terminal monitor",
		"clear counters", "debug ip packet", "event manager run x", "terminal session-timeout 0", "terminal", "terminal length",
		"show running-config > bootflash:f", "show version >> f", "show version >bootflash:f", "show tech-support >x",
		"show version | redirect bootflash:x", "show version | tee x", "show version | append x", "show version | email x",
		"show version | bash", "show version | python x", "show version | vsh", "show version | less", "show version | diff",
		"show version | i foo", "show version | inc foo", "show version | foo", "show version |",
		"show version | json | redirect bootflash:x", "show version | json | red x", "show version | json | e x", "show version | json | ba",
		"show version | include a|email", "show version | include a|b",
		// encadenado con «;» (NX-OS ejecuta cada parte)
		"show version ; reload", "show version;reload", "terminal length 0;reload", "show version | include x ; reload",
		// cada «|» es un pipe nuevo: lista blanca en todos los segmentos
		"show version | sed 'w /bootflash/x'", "show version | sed e", "show version | json | python3", "show version | json | run bash",
		"show version | json | source y", "show version | json | tclsh", "show version | json | diff-clean", "show version | include a | awk x",
		"show version | json | xargs x", "show version | include \"a|b\" | sed e", "show version | include \"a|b", "show version | include \"a\\\"|reload\"", "show version | include \"a\"\"|reload\"",
		// to-file, rutas remotas y destinos de escritura de show tech-support
		"show tech-support all binary bootflash:x", "show tech-support binary bootflash:x", "show tech-support all bin x", "show tech-support all tar",
		"show tech-support compressed", "show tech-support all gzip", "show running-config to-file bootflash:x", "show version to-",
		"show tech-support ftp://h/x",
		// destinos que son palabras clave (abren sub-diálogos)
		"ping vrf", "ping multicast", "ping mpls", "ping m", "ping v", "traceroute vrf", "ping ip", "ping ipv6", "ping nve", "traceroute6 vrf default",
		"dir ftp://h/x", "show file scp://u@h/x", "dir tftp:", "show file sftp:x", "show file http://h/x",
		"ping", "ping6", "ping 255.255.255.255", "ping 0.0.0.0", "ping 224.0.0.1", "ping fe80::1", "ping ::",
		"ping 10.0.0.1 count 11", "ping 10.0.0.1 count 0", "ping 10.0.0.1 packet-size 1501", "ping 10.0.0.1 timeout 11",
		"ping 10.0.0.1 count 2 count 3", "ping 10.0.0.1 df-bit", "ping 10.0.0.1 source", "ping 10.0.0.1 data 0x1",
		"traceroute", "traceroute 10.0.0.1 count 2", "traceroute6 ff02::1", "traceroute 10.0.0.1 vrf",
		"ping 10.0.0.1 vrf a;b", "ping {ip} count 11", "ping {ip} data 1", "ping {mal", "ping {ip}x", "ping 10.0.0.1 vrf management\x01",
	} {
		if err := CheckDenied("nx-os", cmd); !errors.Is(err, ErrDenied) {
			t.Errorf("%q: se aceptó (err=%v)", cmd, err)
		}
	}
}

func TestCheckDeniedNXOSAcepta(t *testing.T) {
	for _, cmd := range []string{
		"show version", "sh ver", "show tech-support details", "show running-config | include ^interface", "show interface status",
		"show logging last 100 | grep -i error", "show ip route vrf all | json | no-more", "show vpc | head lines 5",
		"show interface counters errors | exclude ' 0 '", "show ip route | include 10.0.0.0/8", "show mac address-table | count",
		"show version | json-pretty", "show version | xml | end", "show vlan | section 10", "show vpc | begin Peer", "show vpc | sort | uniq", "show vpc | wc",
		"show running-config | egrep ^int | last 5", "show version | egrep \"up|down\"", "show version | include \"a|b\" | count",
		"show tech-support all", "show tech-support details", "show tech-support ethpm", "ping switch1", "ping 10.0.0.1 count 5 | include x",
		"dir bootflash:", "dir", "terminal length 0", "terminal width 511", "ter wid 0", "",
		"ping 10.0.0.1", "ping 10.0.0.1 vrf management count 5 packet-size 1400 timeout 2 source 10.0.0.2",
		"ping 10.0.0.1 source-interface loopback0", "ping6 2001:db8::1 vrf default count 3", "traceroute 10.0.0.1 vrf management source 10.0.0.2",
		"traceroute6 2001:db8::1 source-interface loopback0", "ping {ip} count 5", "traceroute {ip}", "traceroute switch1",
	} {
		if err := CheckDenied("nx-os", cmd); err != nil {
			t.Errorf("%q: rechazado: %v", cmd, err)
		}
	}
}

// `;` encadena comandos en NX-OS: se rechaza en todas las plataformas por si el host está mal marcado.
func TestCheckDeniedRechazaPuntoYComaEnTodas(t *testing.T) {
	for _, pl := range []string{"nx-os", "ios", "ios-xe", "wlc-9800", ""} {
		for _, cmd := range []string{"show version ; reload", "show version;reload", "terminal length 0;reload"} {
			if err := CheckDenied(pl, cmd); !errors.Is(err, ErrDenied) {
				t.Errorf("%s %q: se aceptó", pl, cmd)
			}
		}
	}
}

// Plataforma mal marcada: una regla de IOS aplicada a un Nexus no deja pasar los comandos de shell tras un pipe.
func TestCheckDeniedIOSRechazaShellDeNXOSTrasPipe(t *testing.T) {
	for _, tok := range []string{"sed", "awk", "python", "python3", "bash", "run", "source", "tclsh", "vsh", "email", "diff", "less", "xargs"} {
		if err := CheckDenied("ios-xe", "show version | include a | "+tok+" x"); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: se aceptó", tok)
		}
	}
	if err := CheckDenied("ios-xe", "show version | include a | include b"); err != nil {
		t.Error(err)
	}
}

// Los motivos de nx-os no describen reglas de IOS.
func TestMotivosNXOSPropios(t *testing.T) {
	for cmd, want := range map[string]string{
		"show version | sed e": "playbook.why.pipe_filter_nxos", "ping 10.0.0.1 repeat 3": "playbook.why.probe_nxos",
		"show version ; reload": "playbook.why.chain", "show tech-support binary x": "playbook.why.write_nxos",
	} {
		d, ok := CheckDenied("nx-os", cmd).(deniedErr)
		if !ok {
			t.Errorf("%q: no se rechazó", cmd)
			continue
		}
		if c, ok := d.e.Cause.(*i18n.Error); !ok || c.Code != want {
			t.Errorf("%q: motivo %v, se esperaba %s", cmd, d.e.Cause, want)
		}
	}
}

// Las demás plataformas conservan sus reglas: «feature» sigue siendo no-lectura y el ping de IOS no cambia.
func TestCheckDeniedNXOSNoCambiaIOS(t *testing.T) {
	if err := CheckDenied("ios-xe", "ping 10.0.0.1 repeat 5"); err != nil {
		t.Error(err)
	}
	if err := CheckDenied("ios-xe", "ping 10.0.0.1 count 5"); err == nil {
		t.Error("count no es de IOS")
	}
}
