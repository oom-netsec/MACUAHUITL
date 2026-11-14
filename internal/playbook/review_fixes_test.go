package playbook

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

func TestDenyReviewBypasses(t *testing.T) {
	for _, c := range []string{
		"tclsh", "guestshell run bash", "event manager run pol", "archive download-sw tftp://x", "archive config",
		"software install file x", "upgrade rom-monitor", "crypto key generate rsa", "crypto key zeroize", "crypto pki enroll TP",
		"clock set 10:00:00 1 Jan 2026", "monitor capture CAP start", "hw-module switch 1 reset", "redundancy force-switchover",
		"rename flash:a flash:b", "mkdir flash:x", "squeeze flash:", "setup", "boot", "send *", "do show run", "terminal shell",
		"show run | redirect flash:x", "show run | tee flash:x", "show run | append flash:x", "show tech | redirect tftp://1.2.3.4/x",
		"show run | include x | redirect flash:y", "show clock\rconf t", "show clock\nconf t", "show\x00clock", "s run",
	} {
		if err := CheckDenied("ios-xe", c); !errors.Is(err, ErrDenied) {
			t.Errorf("%q not denied", c)
		}
	}
	for _, c := range []string{"show running-config", "sh run", "show logging | include CPU|HOG|MEM", "show run | section interface",
		"show int | exclude down", "show version | begin Switch", "show run | count interface", "dir flash:", "more flash:x.txt",
		"terminal length 0", "terminal width 0", "ping 10.0.0.1", "traceroute 10.0.0.1", "verify flash:x.bin"} {
		if err := CheckDenied("ios-xe", c); err != nil {
			t.Errorf("%q denied: %v", c, err)
		}
	}
}

func TestEphemeralRejectsCR(t *testing.T) {
	if _, err := Ephemeral("ios-xe", "show clock\rconf t\n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestEphemeralAcceptsCRLF(t *testing.T) {
	p, err := Ephemeral("ios-xe", "show clock\r\nshow version\r\n")
	if err != nil || len(p.Commands) != 2 || p.Commands[0].Text != "show clock" {
		t.Fatalf("%+v %v", p.Commands, err)
	}
}

// IOS con exec-character-bits 7 quita el bit alto: Í (C3 8D) llega como C+CR y Ê (C3 8A) como LF.
func TestDenyNoASCII(t *testing.T) {
	for _, c := range []string{
		"show xÍconf tÍusername evil privilege 15 secret xÍend", "show xÊconf t", "show\tclock", "show clock 😀", "show \u0085clock",
	} {
		if err := CheckDenied("ios-xe", c); !errors.Is(err, ErrDenied) {
			t.Errorf("%q not denied", c)
		}
	}
}

func TestDenySinksTrasElPrimerPipe(t *testing.T) {
	for _, c := range []string{"sh run | i x | r flash:x", "sh run | i x | t flash:x", "sh run | i x | a flash:x", "sh run | i x | re flash:x"} {
		if err := CheckDenied("ios-xe", c); !errors.Is(err, ErrDenied) {
			t.Errorf("%q not denied", c)
		}
	}
	if err := CheckDenied("ios-xe", "sh run | i x"); err != nil {
		t.Errorf("denied: %v", err)
	}
}

func TestTimeoutMayorAlTopeSeRechazaConElArchivo(t *testing.T) {
	yml := func(to string) fstest.MapFS {
		return fstest.MapFS{"mio.yaml": {Data: []byte("id: x\nplatform: ios-xe\nname: X\ncommands:\n  - cmd: show version\n    timeout: " + to + "\n")}}
	}
	if _, err := Load(yml("30m")); err != nil {
		t.Fatalf("30m debe aceptarse: %v", err)
	}
	_, err := Load(yml("31m"))
	if err == nil || !strings.Contains(err.Error(), "mio.yaml") {
		t.Fatalf("err = %v, quiero error que nombre mio.yaml", err)
	}
}

// ping y traceroute: solo destino más opciones de una lista cerrada con topes; un .mpack de terceros no
// puede lanzar `ping X repeat 2147483647 size 18024 timeout 0` en toda la flota.
func TestDenyProbeOptions(t *testing.T) {
	bad := []string{
		"ping", "ping 10.0.0.1 repeat 2147483647 size 18024 timeout 0", "ping 10.0.0.1 repeat 11", "ping 10.0.0.1 repeat 0",
		"ping 10.0.0.1 size 1501", "ping 10.0.0.1 timeout 0", "ping 10.0.0.1 timeout 11", "ping 10.0.0.1 repeat",
		"ping 10.0.0.1 repeat x", "ping 10.0.0.1 data 0xabcd", "ping 10.0.0.1 df-bit extra", "ping 10.0.0.1 source",
		"ping 10.0.0.1 source gi0/1;x", "ping vrf", "ping 10.0.0.1 10.0.0.2", "ping 10.0.0.1 repeat 5 repeat 5",
		"ping 10.0.0.1 repeat -5", "ping 10.0.0.1 repeat 05x", "ping 10.0.0.1 repeat 99999999999999999999",
		"traceroute 10.0.0.1 ttl 1 300", "traceroute 10.0.0.1 ttl 0 5", "traceroute 10.0.0.1 ttl 9 3", "traceroute 10.0.0.1 probe 11",
		"traceroute 10.0.0.1 timeout 0", "traceroute 10.0.0.1 size 100", "pi 10.0.0.1 repeat 99999", "traceroute", "ping a$b",
	}
	for _, c := range bad {
		if err := CheckDenied("ios-xe", c); !errors.Is(err, ErrDenied) {
			t.Errorf("%q not denied", c)
		}
	}
	good := []string{
		"ping 10.0.0.1", "ping ip 10.0.0.1", "ping ipv6 2001:db8::1", "ping host-1.example.com", "ping 10.0.0.1 repeat 10",
		"ping 10.0.0.1 repeat 2 size 1500 timeout 2", "ping vrf MGMT 10.0.0.1", "ping vrf mgmt ip 10.0.0.1 source gigabitethernet0/1 repeat 3",
		"ping 10.0.0.1 source 10.0.0.9", "pi 10.0.0.1 rep 3", "traceroute 10.0.0.1", "traceroute vrf mgmt 10.0.0.1 ttl 1 30 timeout 3 probe 2",
		"traceroute 10.0.0.1 source loopback0", "ping 10.0.0.1 | include !",
	}
	for _, c := range good {
		if err := CheckDenied("ios-xe", c); err != nil {
			t.Errorf("%q denied: %v", c, err)
		}
	}
}

// to-file es el único destino de escritura que empieza por «to-» en show; «to-» ya es abreviatura suya
// (IOS acepta cualquier prefijo único) y sigue bloqueado, pero un nombre como to-core no lo es.
func TestDenyToFileVsNombreToCore(t *testing.T) {
	for _, c := range []string{"show logging to-file flash:x", "show logging to-fi flash:x", "show logging to- flash:x"} {
		if err := CheckDenied("ios-xe", c); !errors.Is(err, ErrDenied) {
			t.Errorf("%q not denied", c)
		}
	}
	for _, c := range []string{"show running-config interface to-core", "show ip route vrf to-core", "ping vrf to-core 10.0.0.1"} {
		if err := CheckDenied("ios-xe", c); err != nil {
			t.Errorf("%q denied: %v", c, err)
		}
	}
}
