package fileserve

import (
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// 43e-6 punto 1: en Windows no hay regla de redirección que quitar, así que el cierre no lleva «Cleanup»;
// en Linux solo si se sugirió una regla (puerto distinto del estándar).
func TestCleanupSoloSiHuboRegla(t *testing.T) {
	fijaWindows(t, "windows")
	for _, a := range []string{"172.30.0.2:69", "127.0.0.1:69", "10.0.0.5:6969"} {
		if c := RedirectCleanupAddr("tftp", a); c != "" {
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

// Punto 3: puerto estándar ocupado → mensaje claro con sugerencia de un puerto alto; otros errores no se tocan.
func TestPuertoEstandarOcupado(t *testing.T) {
	busy := &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	if BusyErr("scp", "0.0.0.0:22", busy) == nil {
		t.Fatal("puerto 22 ocupado sin mensaje")
	}
	es, en := i18n.In(i18n.Es, BusyErr("scp", "10.0.0.5:22", busy)), i18n.In("en", BusyErr("scp", "10.0.0.5:22", busy))
	if !strings.Contains(es, "en uso") || !strings.Contains(es, "alto") || !strings.Contains(en, "in use") || !strings.Contains(en, "high") {
		t.Errorf("es=%q en=%q", es, en)
	}
	if BusyErr("scp", "10.0.0.5:2222", busy) != nil || BusyErr("scp", "10.0.0.5:22", os.ErrPermission) != nil {
		t.Error("solo el puerto estándar con dirección en uso")
	}
}

// Punto 4: IOS no decodifica %20: con espacios no se imprime un copy inservible, se avisa que se renombre.
func TestHintNombreConEspaciosAvisa(t *testing.T) {
	fijaWindows(t, "linux")
	r := Ready{Addr: "10.0.0.5:2121", User: "mac", Pass: "pw", Fingerprints: []string{"SHA256:aa", "SHA256:bb"}}
	for _, loc := range []string{"es", "en"} {
		for _, p := range []string{"tftp", "ftp", "scp", "sftp", "http"} {
			h := ServerHintIn(loc, Config{Proto: p}, r, []string{"mi archivo.bin", "ok.bin"})
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
	r := Ready{Addr: "10.0.0.5:2222", User: "mac", Pass: "pw", Fingerprints: []string{"SHA256:aa", "SHA256:bb"}}
	for _, loc := range []string{"es", "en"} {
		h := ServerHintIn(loc, Config{Proto: "scp"}, r, nil)
		if !strings.Contains(h, "SHA256:aa (ed25519)") || !strings.Contains(h, "SHA256:bb (RSA)") || strings.Contains(h, "(ed25519, RSA)") {
			t.Errorf("%s:\n%s", loc, h)
		}
	}
}
