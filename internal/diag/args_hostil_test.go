package diag

import (
	"strings"
	"testing"
)

// 43d-3 (5.7): valores hostiles de destino, interfaz y filtro. Cada uno se rechaza o viaja como UN argumento que no
// empieza con «-» ni (en Windows) con «/»; nunca como argumento inyectado. Unicode de formato escapado.
func TestArgsHostilesDestino(t *testing.T) {
	hostiles := []string{
		"-oN", "-oN/tmp/x", "-iL", "-iL/etc/passwd", "--script", "--script=x", "--iflist", "-", "--",
		"a -oN x", "a\n-oN x", "a\r-oN", "a\x00-oN", "a\u0085b", "a b", "a‮b", "a b", " a", "a ", "a\tb",
		"a;b", "a&b", "a|b", "a`b", "a$(b)", "a'b", `a"b`, "a=b", "a@b", "/x", "/?", "\\\\srv\\x", "a/24x", "10.0.0.1 -oN", "10.0.0.0/24 -oN",
		"@file", "host\n", "\nhost", "\x00",
	}
	for _, win := range []bool{false, true} {
		for _, tool := range []Tool{Ping, Traceroute, Nmap} {
			for _, h := range hostiles {
				_, argv, err := build(req(tool, h, nil, ""), win)
				if err == nil {
					t.Errorf("%s win=%v %q: aceptado: %q", tool, win, h, argv)
				}
			}
		}
	}
}

func TestArgsHostilesInterfazYFiltro(t *testing.T) {
	for _, win := range []bool{false, true} {
		for _, iface := range []string{"-oN", "-w", "--iflist", "-i", "/x", "eth0;reboot", "eth0 -w /x", "eth0\n-w", "eth0\x00", "eth0\u0085", "eth0 ", "eth0‮", "", " ", "$(x)", "eth0`x`", "\\Device\\NPF_{x}", "\\Device\\NPF_{00000000-0000-0000-0000-000000000000}\n"} {
			if _, argv, err := build(req(Pcap, "", map[string]string{"interface": iface}, "/tmp/o"), win); err == nil && !(win && strings.HasPrefix(iface, "\\Device\\NPF_{0")) {
				t.Errorf("win=%v iface %q aceptada: %q", win, iface, argv)
			}
		}
	}
	// El filtro BPF viaja como UN argumento tras -f aunque lleve saltos, comillas o «-w».
	for _, f := range []string{"-w /tmp/x", "host 1.1.1.1\n-w /tmp/x", `host "a"`, "a'b", "$(x)", "tcp port 22", "tcp‮port 22", "a\x00b"} {
		_, argv, err := build(req(Pcap, "", map[string]string{"interface": "eth0", "filter": f}, "/tmp/o"), false)
		if err != nil {
			continue // rechazar también es correcto
		}
		n := 0
		for i, a := range argv {
			if a == "-f" && i == len(argv)-2 && argv[i+1] == f {
				n++
			}
		}
		if n != 1 {
			t.Errorf("filtro %q no viaja como un solo argumento: %q", f, argv)
		}
		if strings.Contains(f, "\x00") {
			t.Errorf("NUL en el filtro llegó al argv: %q", argv)
		}
	}
}

// Las opciones de texto libre (ports, bind) tampoco admiten flags ni saltos.
func TestArgsHostilesOpcionesNmapIperf(t *testing.T) {
	localTest(t)
	for _, p := range []string{"-oN x", "80\n-oN", "80,", "80 -oN", "--script", "80\x00", "80;81", "-p", "", "80 "} {
		if _, _, err := build(req(Nmap, "10.0.0.1", map[string]string{"ports": p}, ""), false); err == nil {
			t.Errorf("ports %q aceptado", p)
		}
	}
	for _, b := range []string{"-B", "192.0.2.9\n", "192.0.2.9 -p 1", "192.0.2.9\x00", "192.0.2.9%eth0", "--daemon"} {
		if _, _, err := build(req(Iperf3, "", map[string]string{"mode": "server", "bind": b}, ""), false); err == nil {
			t.Errorf("bind %q aceptado", b)
		}
	}
	// checkFlagLike por sí solo: una bandera que llegara al argv se detiene; en Windows también «/x».
	if checkFlagLike("nmap", []string{"-oN"}, false) == nil || checkFlagLike("ping", []string{"/x"}, true) == nil || checkFlagLike("ping", []string{"/x"}, false) != nil {
		t.Error("checkFlagLike")
	}
}
