package fileserve

import (
	"strings"
	"testing"
)

// 43e-6 punto 1: en Windows no hay regla de redirección que quitar, así que el cierre no lleva «Cleanup»;
// en Linux solo si se sugirió una regla (puerto distinto del estándar).
func TestCleanupSoloSiHuboRegla(t *testing.T) {
	fijaWindows(t, "windows")
	for a, want := range map[string]string{"172.30.0.2:69": "Remove-NetFirewallRule -DisplayName 'MACUAHUITL tftp 172.30.0.2 69'", "127.0.0.1:69": ""} {
		if c := RedirectCleanupAddr("tftp", a); c != want {
			t.Errorf("windows %s: cleanup = %q", a, c)
		}
	}
	fijaWindows(t, "linux")
	if c := RedirectCleanupAddr("tftp", "10.0.0.5:69"); c != "" {
		t.Errorf("linux en el puerto estándar no sugirió regla: %q", c)
	}
	if c := RedirectCleanupAddr("tftp", "10.0.0.5:6969"); !strings.HasPrefix(c, "sudo nft delete table") {
		t.Errorf("linux con puerto propio: %q", c)
	}
}

// Punto 2: con loopback en Windows no se habla de firewall.
func TestHintLoopbackWindowsSinRegla(t *testing.T) {
	fijaWindows(t, "windows")
	for _, loc := range []string{"es", "en"} {
		for _, p := range []string{"tftp", "ftp", "scp"} {
			h := ServerHintIn(loc, Config{Proto: p}, Ready{Addr: "127.0.0.1:" + map[string]string{"tftp": "69", "ftp": "21", "scp": "22"}[p]}, []string{"a.bin"})
			if low := strings.ToLower(h); strings.Contains(low, "firewall") || strings.Contains(h, "NetFirewall") {
				t.Errorf("%s/%s habla de firewall:\n%s", loc, p, h)
			}
		}
	}
}

// Punto 4: IOS no decodifica %20: con espacios no se imprime un copy inservible, se avisa que se renombre.
func TestHintNombreConEspaciosAvisa(t *testing.T) {
	fijaWindows(t, "linux")
	r := Ready{Addr: "10.0.0.5:2121", User: "mac", Pass: "pw", Fingerprints: []string{"SHA256:aa", "SHA256:bb"}}
	for _, loc := range []string{"es", "en"} {
		for _, p := range []string{"tftp", "ftp", "scp", "sftp", "http"} {
			h := ServerHintIn(loc, Config{Proto: p}, r, []string{"mi archivo.bin", "ok.bin"})
			if p == "http" { // el servidor HTTP decodifica %20: se escapa y no hay aviso
				if !strings.Contains(h, "mi%20archivo.bin flash:") || strings.Contains(h, "renómbralo") || strings.Contains(h, "rename it") {
					t.Errorf("%s/http:\n%s", loc, h)
				}
				continue
			}
			if strings.Contains(h, "mi archivo.bin flash:") || !strings.Contains(h, "ok.bin flash:") || !strings.Contains(h, "mi archivo.bin") {
				t.Errorf("%s/%s:\n%s", loc, p, h)
			}
			want := map[string]string{"es": "renómbralo", "en": "rename it"}[loc]
			if !strings.Contains(h, want) {
				t.Errorf("%s/%s sin aviso %q:\n%s", loc, p, want, h)
			}
		}
	}
	if h := HintIn("en", "tftp", "10.0.0.5:6969", []string{"/x/mi archivo.bin"}); strings.Contains(h, "flash:") && strings.Contains(h, "mi archivo.bin flash:") || !strings.Contains(h, "rename it") {
		t.Errorf("HintIn:\n%s", h)
	}
}

// Punto 7: cada huella dice su tipo (el orden fijo de hostSigners es ed25519, RSA).
func TestHintHuellaConTipo(t *testing.T) {
	fijaWindows(t, "linux")
	r := Ready{Addr: "10.0.0.5:2222", User: "mac", Pass: "pw", Fingerprints: []string{"SHA256:aa", "SHA256:bb"}, FingerprintKinds: []string{"ssh-rsa", "ssh-ed25519"}}
	for _, loc := range []string{"es", "en"} {
		h := ServerHintIn(loc, Config{Proto: "scp"}, r, nil)
		if !strings.Contains(h, "SHA256:aa (RSA)") || !strings.Contains(h, "SHA256:bb (ed25519)") || strings.Contains(h, "(ed25519, RSA)") {
			t.Errorf("%s:\n%s", loc, h)
		}
	}
}

// Punto 7: el tipo sale de la llave real, no de la posición.
func TestHostSignersDanTipo(t *testing.T) {
	_, fps, kinds, err := hostSigners(false)
	if err != nil || len(fps) != 2 || len(kinds) != 2 || kinds[0] != "ssh-ed25519" || kinds[1] != "ssh-rsa" {
		t.Fatalf("%v %v %v", fps, kinds, err)
	}
}
