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
	want := `New-NetFirewallRule -DisplayName "MACUAHUITL UDP 69" -Direction Inbound -Program "C:\Apps\macuahuitld.exe" -LocalAddress 10.0.0.5 -Protocol UDP -LocalPort 69 -Action Allow`
	h := RedirectHintIn("es", "tftp", "10.0.0.5", 69)
	if !strings.HasPrefix(h, want) || !strings.Contains(h, `Remove-NetFirewallRule -DisplayName "MACUAHUITL UDP 69"`) {
		t.Errorf("tftp:\n%s", h)
	}
	if h := RedirectHintIn("en", "ftp", "0.0.0.0", 21); !strings.Contains(h, "-LocalAddress IP-OF-THIS-MACHINE -Protocol TCP -LocalPort 21") {
		t.Errorf("ftp:\n%s", h)
	}
	if got := RedirectCleanup("tftp", "10.0.0.5", 6969); got != `Remove-NetFirewallRule -DisplayName "MACUAHUITL UDP 6969"` {
		t.Errorf("cleanup = %q", got)
	}
	if RedirectCleanupAddr("ftp", "10.0.0.5:21") != `Remove-NetFirewallRule -DisplayName "MACUAHUITL TCP 21"` || RedirectCleanup("http", "10.0.0.5", 80) != "" || RedirectHintIn("es", "http", "10.0.0.5", 80) != "" {
		t.Error("cleanup addr/http")
	}
	if SetcapHintIn("es", "X") != "" {
		t.Error("setcap en Windows")
	}
	sh := ServerHintIn("es", Config{Proto: "tftp"}, Ready{Addr: "10.0.0.5:69"}, []string{"a.bin"})
	if !strings.Contains(sh, "New-NetFirewallRule") || strings.Contains(sh, "nft") || strings.Contains(sh, "setcap") {
		t.Errorf("ServerHint:\n%s", sh)
	}
	if hh := HintIn("en", "tftp", "10.0.0.5:69", []string{"/x/a.bin"}); !strings.Contains(hh, "New-NetFirewallRule") || strings.Contains(hh, "nft") {
		t.Errorf("Hint:\n%s", hh)
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
