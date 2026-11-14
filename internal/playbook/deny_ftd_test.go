package playbook

import (
	"errors"
	"testing"
)

// Cisco Secure Firewall Threat Defense (Command Reference de FTD 7.x, sin validar en laboratorio).
func TestCheckDeniedFTDRechaza(t *testing.T) {
	for _, cmd := range []string{
		"expert", "system support diagnostic-cli", "system generate-troubleshoot all", "system", "system reboot", "configure network ipv4 manual 1.1.1.1 255.255.255.0 1.1.1.2",
		"configure password", "capture x interface inside", "capture-traffic", "capture-traffic -n", "clear conn", "clear xlate", "copy /noconfirm x y", "file", "delete x",
		"debug icmp trace", "undebug all", "reboot", "shutdown", "restart", "upgrade", "cpu profile", "dir", "more x", "terminal pager 0", "test aaa", "failover active",
		"cluster exec show version", "cluster", "vpn-sessiondb logoff all", "exit", "logout", "enable", "write memory", "reload",
		// sin abreviaturas
		"sh version", "sho version", "s version", "pi 10.0.0.1", "tr 10.0.0.1", "packet-t input inside tcp 1.1.1.1 1 2.2.2.2 80", "SHOW version x ;",
		// show: file, rutas remotas
		"show tech-support file disk0:x", "show tech-support f x", "show running-config tftp://h/x",
		// pipes
		"show version | redirect x", "show version | include redirect x", "show version | section x", "show version |", "| include a",
		// ping y traceroute: solo la forma de datos; «system» sale por la gestión
		"ping system 10.0.0.1", "traceroute system 10.0.0.1", "ping tcp system 10.0.0.1 443", "traceroute 10.0.0.1 source system", "ping 10.0.0.1 system", "ping inside system", "ping system", "ping 10.0.0.1 repeat 11", "ping 255.255.255.255", "traceroute 10.0.0.1 probe 6",
		"packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2 80 transmit", "packet-tracer input inside tcp 1.1.1.1 1000 2.2.2.2",
		"show version > x", "show version | include `x`",
	} {
		if err := CheckDenied("ftd", cmd); !errors.Is(err, ErrDenied) {
			t.Errorf("%q: se aceptó (err=%v)", cmd, err)
		}
	}
}

func TestCheckDeniedFTDAcepta(t *testing.T) {
	for _, cmd := range []string{
		"show version", "SHOW VERSION", "show managers", "show network", "show snort3 status", "show access-control-config", "show asp drop", "show conn detail", "show running-config",
		"show tech-support", "show running-config | include ^ping$", "show xlate | include 10.0.0.1|10.0.0.2", "show route | begin 10.", "show version | grep -v ^$", "",
		"ping 10.0.0.1", "ping inside 10.0.0.1 repeat 5 timeout 2 size 100", "ping tcp inside 10.0.0.1 443 count 3", "ping {ip}", "traceroute 10.0.0.1", "traceroute {ip} numeric",
		"packet-tracer input inside tcp 10.0.0.1 1025 192.0.2.5 80", "packet-tracer input {interface} icmp {src} 8 0 {dst} detailed",
	} {
		if err := CheckDenied("ftd", cmd); err != nil {
			t.Errorf("%q: rechazado: %v", cmd, err)
		}
	}
}
