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
		// comilla a media palabra y argumentos de los pipes permitidos
		"show version | include a\" | sed 'w /bootflash/x' | include \"b", "show version | include a\"b", "show version | include a\"b c\"", "show version | include \"a\"b", "show version | include \"a",
		"show version | sort -o bootflash:x", "show version | uniq a bootflash:x", "show version | head -c 10", "show version | json native",
		"show version | count x", "show version | wc lines", "show version | no-more x", "show version | xml x", "show version | end x", "show version | sort -n",
		"show version | head lines", "show version | head lines x", "show version | head 5 6", "show version | last x", "show version | last lines 5", "show version | head -5",
		"show version | include -f bootflash:x", "show version | include a b", "show version | include", "show version | grep -c -f x", "show version | include next x z",
		"show version | include bootflash:x", "show version | include volatile:x", "show version | include logflash:x", "show version | include usb1:x", "show version | include /bootflash/x",
		"show version | include \"bootflash:x\"", "show version | egrep ignore-case bootflash:x", "show version | include -i /etc/passwd",
		// variables y sustituciones
		"show version | include $(reload)", "show version | include `reload`", "show version | include $x", "show version | egrep \"up$\"", "show $x",
		// to-file, rutas remotas y destinos de escritura de show tech-support
		"show tech-support all binary bootflash:x", "show tech-support binary bootflash:x", "show tech-support all bin x", "show tec binary bootflash:x", "sh tec tar bootflash:x", "show tech all compressed", "show tech-s gzip", "show tech-support all tar",
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
		"show interface counters errors | exclude \" 0 \"", "show ip route | include 10.0.0.0/8", "show mac address-table | count",
		"show version | json-pretty", "show version | xml | end", "show vlan | section 10", "show vpc | begin Peer", "show vpc | sort | uniq", "show vpc | wc",
		"show running-config | egrep ^int | last 5", "show version | egrep \"up|down\"", "show version | include \"a|b\" | count",
		"show version | include ignore-case up", "show version | include invert-match line-number word-exp up", "show version | include -i -v -c -n -w -x up",
		"show version | include next 2 up", "show version | egrep prev 3 \"a|b\"", "show version | head lines 5", "show version | head 5", "show version | last 5",
		"show version | json | no-more", "show version | sort | uniq | wc", "show version | include 2001:db8::1", "show version | include fe80::1", "show version | section \"ethernet1/1 \"",
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

// `>`, comillas invertidas y `$(` se rechazan en todas las plataformas; en nx-os, cualquier `$`.
func TestCheckDeniedRedireccionYSustitucionEnTodas(t *testing.T) {
	for _, pl := range []string{"nx-os", "ios", "ios-xe", "wlc-9800"} {
		for _, cmd := range []string{"show version > bootflash:x", "show version >> x", "show version | include a > x", "show version | include `x`", "show version | include $(x)", "show $(x)"} {
			if err := CheckDenied(pl, cmd); !errors.Is(err, ErrDenied) {
				t.Errorf("%s %q: se aceptó", pl, cmd)
			}
		}
	}
	if err := CheckDenied("ios-xe", "show running-config | include ^interface.*$"); err != nil {
		t.Error("el ancla $ de una regex en IOS debe pasar:", err)
	}
	if err := CheckDenied("nx-os", "show running-config | include up$"); err == nil {
		t.Error("nx-os rechaza cualquier $")
	}
}

// Plataforma mal marcada: una regla de IOS aplicada a un Nexus no deja pasar los comandos de shell tras un pipe.
func TestCheckDeniedIOSRechazaShellDeNXOSTrasPipe(t *testing.T) {
	for _, tok := range []string{"sed", "awk", "python", "python3", "bash", "run", "source", "tclsh", "vsh", "email", "diff", "less", "xargs"} {
		if err := CheckDenied("ios-xe", "show version | include a | "+tok+" x"); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: se aceptó", tok)
		}
	}
	for _, tok := range []string{"em", "ema", "vs", "pe", "perl", "ss", "sscp", "se", "cu", "cut", "tr", "pyt", "ba", "ru", "sou", "tcl", "di", "le", "xar"} {
		if err := CheckDenied("ios-xe", "show version | include a | "+tok+" x"); !errors.Is(err, ErrDenied) {
			t.Errorf("abreviatura %s: se aceptó", tok)
		}
	}
	for _, ok := range []string{"show version | include a | include b", "show version | include \"a|down\" | exclude x", "show version | include a | trunk"} {
		if err := CheckDenied("ios-xe", ok); err != nil {
			t.Errorf("%q: %v", ok, err)
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

// En los filtros de NX-OS, un argumento con guion fuera de la lista cerrada (`--file=bootflash:x`, `-f`) no se cuenta
// como patrón: se rechaza. `line-exp` es una opción válida de egrep.
func TestCheckDeniedNXOSOpcionesDeFiltro(t *testing.T) {
	for _, c := range []string{
		"show version | grep --file=bootflash:x",
		"show version | grep -f x",
		`show version | egrep -e "a"`,
	} {
		if err := CheckDenied("nx-os", c); err == nil {
			t.Errorf("aceptado: %q", c)
		}
	}
	if err := CheckDenied("nx-os", `show interface | egrep line-exp "Eth1/1"`); err != nil {
		t.Errorf("line-exp rechazado: %v", err)
	}
}
