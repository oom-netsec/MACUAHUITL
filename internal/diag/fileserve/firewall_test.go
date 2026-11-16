package fileserve

import (
	"strings"
	"testing"
)

func fijaPrivilegiados(t *testing.T, v bool) {
	t.Helper()
	old := privilegedPorts
	privilegedPorts = v
	t.Cleanup(func() { privilegedPorts = old })
}

func fijaWindows(t *testing.T, os string) {
	t.Helper()
	old, oldExe := hintOS, exePath
	hintOS, exePath = os, func() string { return `C:\Apps\macuahuitld.exe` }
	t.Cleanup(func() { hintOS, exePath = old, oldExe })
}

// ADR 0012 h: sin puertos privilegiados se acepta 69 y 21 y un rango pasivo bajo; el 0 y hi<lo siguen rechazados.
func TestSinPrivilegiadosAceptaPuertosBajos(t *testing.T) {
	fijaPrivilegiados(t, false)
	dir := t.TempDir()
	for _, a := range []string{"127.0.0.1:69", "127.0.0.1:21"} {
		if err := Check(Config{Addr: a, Proto: "tftp", FromDir: dir}); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	for r, ok := range map[[2]uint16]bool{{20000, 20010}: true, {100, 200}: true, {0, 5000}: false, {2000, 1500}: false} {
		if err := Check(Config{Addr: "127.0.0.1:21", Proto: "ftp", FromDir: dir, PassivePorts: r}); (err == nil) != ok {
			t.Errorf("rango %v: %v", r, err)
		}
	}
}

func TestReglaFirewallWindows(t *testing.T) {
	fijaWindows(t, "windows")
	want := `New-NetFirewallRule -DisplayName 'MACUAHUITL tftp 10.0.0.5 69' -Direction Inbound -Program 'C:\Apps\macuahuitld.exe' -LocalAddress 10.0.0.5 -Protocol UDP -LocalPort 69 -Action Allow`
	h := RedirectHintIn("es", "tftp", "10.0.0.5", 69)
	if !strings.HasPrefix(h, want) || !strings.Contains(h, `Remove-NetFirewallRule -DisplayName 'MACUAHUITL tftp 10.0.0.5 69'`) {
		t.Errorf("tftp:\n%s", h)
	}
	if h := RedirectHintIn("en", "ftp", "0.0.0.0", 21); !strings.Contains(h, "-LocalAddress IP-OF-THIS-MACHINE -Protocol TCP -LocalPort Any") || !strings.Contains(h, "'MACUAHUITL ftp any 21'") {
		t.Errorf("ftp:\n%s", h)
	}
	if got := RedirectCleanup("tftp", "10.0.0.5", 6969); got != `Remove-NetFirewallRule -DisplayName 'MACUAHUITL tftp 10.0.0.5 6969'` {
		t.Errorf("cleanup = %q", got)
	}
	if RedirectCleanupAddr("ftp", "10.0.0.5:21") != `Remove-NetFirewallRule -DisplayName 'MACUAHUITL ftp 10.0.0.5 21'` || RedirectCleanup("http", "10.0.0.5", 80) != "" || RedirectHintIn("es", "http", "10.0.0.5", 80) != "" {
		t.Error("cleanup addr/http")
	}
	if SetcapHintIn("es", "X") != "" {
		t.Error("setcap en Windows")
	}
	sh := ServerHintIn("es", Config{Proto: "tftp"}, Ready{Addr: "10.0.0.5:69"}, []string{"a.bin"})
	if !strings.Contains(sh, "New-NetFirewallRule") || strings.Contains(sh, "nft") || strings.Contains(sh, "setcap") || !strings.Contains(sh, "CANCELAS") {
		t.Errorf("ServerHint:\n%s", sh)
	}
	if hh := HintIn("en", "tftp", "10.0.0.5:69", []string{"/x/a.bin"}); !strings.Contains(hh, "New-NetFirewallRule") || strings.Contains(hh, "nft") || strings.Contains(hh, "open it on 69") {
		t.Errorf("Hint:\n%s", hh)
	}
}

// El nombre lleva protocolo e IP: quitar la regla de un servidor no toca la de otro.
func TestNombreReglaUnicoPorServidor(t *testing.T) {
	fijaWindows(t, "windows")
	n := map[string]bool{}
	for _, c := range [][2]string{{"tftp", "10.0.0.5"}, {"tftp", "10.0.0.6"}, {"scp", "10.0.0.5"}, {"sftp", "10.0.0.5"}} {
		n[RedirectCleanup(c[0], c[1], 22)] = true
	}
	if len(n) != 4 {
		t.Errorf("nombres repetidos: %v", n)
	}
}

// PowerShell expande $var, $(...) y el acento grave entre comillas dobles; con comillas simples no, y las comillas
// simples (también las tipográficas) se duplican.
func TestReglaFirewallCitaSimple(t *testing.T) {
	old := exePath
	t.Cleanup(func() { exePath = old })
	fijaWindows(t, "windows")
	exePath = func() string { return `C:\Tools\$(Start-Process calc)\it's‘x’\` + "`" + `macuahuitld.exe` }
	h := RedirectHintIn("es", "tftp", "10.0.0.5", 69)
	if !strings.Contains(h, `-Program 'C:\Tools\$(Start-Process calc)\it''s‘‘x’’\`+"`"+`macuahuitld.exe'`) || strings.Contains(h, `"`) {
		t.Errorf("cita:\n%s", h)
	}
}

func TestReglaFirewallSinRutaNoEmiteRegla(t *testing.T) {
	fijaWindows(t, "windows")
	exePath = func() string { return "" }
	h := RedirectHintIn("es", "tftp", "10.0.0.5", 69)
	if strings.Contains(h, "New-NetFirewallRule") || !strings.Contains(h, "macuahuitld.exe") {
		t.Errorf("sin ruta:\n%s", h)
	}
}

// FTP pasivo: con rango, el de control y el de datos; sin rango, Any (acotado por programa e IP).
func TestReglaFirewallFTPPasivo(t *testing.T) {
	fijaWindows(t, "windows")
	sh := ServerHintIn("es", Config{Proto: "ftp", PassivePorts: [2]uint16{50000, 50031}}, Ready{Addr: "10.0.0.5:21"}, nil)
	if !strings.Contains(sh, "-LocalPort 21,50000-50031") {
		t.Errorf("con rango:\n%s", sh)
	}
	sh = ServerHintIn("es", Config{Proto: "ftp"}, Ready{Addr: "10.0.0.5:21"}, nil)
	if !strings.Contains(sh, "-LocalPort Any") {
		t.Errorf("sin rango:\n%s", sh)
	}
}

// El texto dice la verdad según el puerto real.
func TestTextosWindowsSegunPuerto(t *testing.T) {
	fijaWindows(t, "windows")
	if h := HintIn("es", "tftp", "10.0.0.5:6969", nil); !strings.Contains(h, "ábrelo en el 69") {
		t.Errorf("6969:\n%s", h)
	}
	if h := HintIn("es", "tftp", "10.0.0.5:69", nil); strings.Contains(h, "ábrelo") {
		t.Errorf("69:\n%s", h)
	}
	if sh := ServerHintIn("es", Config{Proto: "tftp"}, Ready{Addr: "10.0.0.5:69"}, nil); !strings.Contains(sh, "solo falta") {
		t.Errorf("69:\n%s", sh)
	}
	if sh := ServerHintIn("es", Config{Proto: "tftp"}, Ready{Addr: "10.0.0.5:6969"}, nil); strings.Contains(sh, "solo falta") {
		t.Errorf("6969:\n%s", sh)
	}
}

// La zona de una IP link-local no llega a ningún comando (ni nft ni PowerShell).
func TestIPConZonaNoLlegaAlComando(t *testing.T) {
	for _, os := range []string{"linux", "windows"} {
		fijaWindows(t, os)
		for _, ip := range []string{"fe80::1%a;calc", "fe80::1%$(calc)"} {
			for _, h := range []string{RedirectHintIn("es", "tftp", ip, 6969), RedirectCleanup("tftp", ip, 6969)} {
				if strings.Contains(h, "calc") || strings.Contains(h, "%") {
					t.Errorf("%s %q:\n%s", os, ip, h)
				}
			}
		}
	}
}

// En Linux todo sigue igual: nftables y setcap, sin PowerShell.
func TestLinuxSinReglaFirewall(t *testing.T) {
	fijaWindows(t, "linux")
	if h := RedirectHintIn("es", "tftp", "10.0.0.5", 6969); strings.Contains(h, "NetFirewall") || !strings.Contains(h, "nft add table") {
		t.Error(h)
	}
	if SetcapHintIn("es", "X") == "" || strings.Contains(RedirectCleanup("tftp", "10.0.0.5", 6969), "NetFirewall") {
		t.Error("setcap/cleanup")
	}
}
