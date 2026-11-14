package playbook

import (
	"errors"
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
		"dir ftp://h/x", "show file scp://u@h/x", "dir tftp:", "show file sftp:x", "show file http://h/x",
		"ping", "ping6", "ping 255.255.255.255", "ping 0.0.0.0", "ping 224.0.0.1", "ping fe80::1", "ping ::",
		"ping 10.0.0.1 count 11", "ping 10.0.0.1 count 0", "ping 10.0.0.1 packet-size 1501", "ping 10.0.0.1 timeout 11",
		"ping 10.0.0.1 count 2 count 3", "ping 10.0.0.1 df-bit", "ping 10.0.0.1 source", "ping 10.0.0.1 data 0x1",
		"traceroute", "traceroute 10.0.0.1 count 2", "traceroute6 ff02::1", "traceroute 10.0.0.1 vrf",
		"ping 10.0.0.1 vrf a;b", "ping 10.0.0.1 vrf management\x01",
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
		"show running-config | egrep ^int | last 5",
		"dir bootflash:", "dir", "terminal length 0", "terminal width 511", "ter wid 0", "",
		"ping 10.0.0.1", "ping 10.0.0.1 vrf management count 5 packet-size 1400 timeout 2 source 10.0.0.2",
		"ping 10.0.0.1 source-interface loopback0", "ping6 2001:db8::1 vrf default count 3", "traceroute 10.0.0.1 vrf management source 10.0.0.2",
		"traceroute6 2001:db8::1 source-interface loopback0", "traceroute switch1",
	} {
		if err := CheckDenied("nx-os", cmd); err != nil {
			t.Errorf("%q: rechazado: %v", cmd, err)
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
