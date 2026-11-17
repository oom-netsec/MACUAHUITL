package fileserve

import (
	"net"
	"strings"
	"testing"
)

// 43d-3 (4.1, 4.4, 4.5): una ruta del ejecutable que no se puede citar de forma segura NO emite regla; se avisa con
// win_no_exe. Unicode de formato escapado.
func TestReglaFirewallRutaHostilNoEmiteRegla(t *testing.T) {
	fijaWindows(t, "windows")
	for name, exe := range map[string]string{
		"salto LF":       "C:\\Apps\\a\nNew-NetFirewallRule x\\macuahuitld.exe",
		"salto CR":       "C:\\Apps\\a\rb.exe",
		"NEL U+0085":     "C:\\Apps\\a\u0085b.exe",
		"LS U+2028":      "C:\\Apps\\a\u2028b.exe",
		"PS U+2029":      "C:\\Apps\\a\u2029b.exe",
		"bidi U+202E":    "C:\\Apps\\a\u202eexe.b.exe",
		"aislado U+2066": "C:\\Apps\\\u2066a.exe",
		"NUL":            "C:\\Apps\\a\x00b.exe",
		"tab":            "C:\\Apps\\a\tb.exe",
		"ZWSP U+200B":    "C:\\Apps\\a\u200bb.exe",
		"relativa":       "macuahuitld.exe",
		"UNC":            `\\srv\share\macuahuitld.exe`,
		"extendida":      `\\?\C:\Apps\macuahuitld.exe`,
	} {
		exePath = func() string { return exe }
		for _, h := range []string{
			RedirectHintIn("es", "tftp", "10.0.0.5", 69),
			ServerHintIn("es", Config{Proto: "tftp"}, Ready{Addr: "10.0.0.5:69"}, nil),
		} {
			if strings.Contains(h, "New-NetFirewallRule") || strings.Contains(h, "Remove-NetFirewallRule") || !strings.Contains(h, "macuahuitld.exe") {
				t.Errorf("%s: se emitió regla o falta el aviso:\n%q", name, h)
			}
		}
		if c := RedirectCommandIn("en", "tftp", "10.0.0.5", 69) + RedirectCleanup("tftp", "10.0.0.5", 69) + RedirectCleanupAddr("tftp", "10.0.0.5:69"); c != "" {
			t.Errorf("%s: orden con ruta insegura (la nota no va en la orden ni se quita lo que no se puso): %q", name, c)
		}
	}
}

// ZWNJ y ZWJ no invierten texto y salen en nombres persas e índicos: la ruta sigue siendo citable.
func TestExeSeguroPermiteZWNJyZWJ(t *testing.T) {
	for _, p := range []string{"C:\\Apps\\\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645\\x.exe", "C:\\Apps\\\u0915\u094d\u200d\u0937\\x.exe"} {
		if !exeSeguro(p) {
			t.Errorf("rechazada: %q", p)
		}
	}
	if exeSeguro("C:\\Apps\\a\u200bb.exe") || exeSeguro("C:\\Apps\\a\u200eb.exe") {
		t.Error("ZWSP/LRM deben seguir rechazados")
	}
}

// 4.2: lo que sí es citable (comillas dobles, ;, %, &, |, #, $(), acento grave) sigue yendo entre comillas simples.
func TestReglaFirewallRutaCitableTabla(t *testing.T) {
	fijaWindows(t, "windows")
	for _, exe := range []string{
		`C:\a;b\x.exe`, `C:\a"b\x.exe`, `C:\100%\x.exe`, `C:\a&b|c#d\x.exe`, `C:\$(calc)\x.exe`, "C:\\a`b\\x.exe", `C:\it's\x.exe`, `C:\Archivos de programa\x.exe`,
	} {
		exePath = func() string { return exe }
		h := RedirectCommandIn("es", "tftp", "10.0.0.5", 69)
		want := "-Program " + psq(exe) + " -LocalAddress"
		if !strings.Contains(h, want) {
			t.Errorf("%q:\n%s", exe, h)
		}
	}
}

// 4.3 y 4.6: IP hostil; el nombre sale de una IP parseada o «any», y ni nft ni la regla de Windows llevan el texto crudo.
func TestReglaIPHostilNoLlegaAlComando(t *testing.T) {
	hostiles := []string{
		"10.0.0.5'; calc; '", `10.0.0.5" -x`, "10.0.0.5`n", "$(calc)", "10.0.0.5\n", "10.0.0.5\r", "10.0.0.5\u0085", "10.0.0.5\u2028",
		"10.0.0.5\u202e", "10.0.0.5\x00", "10.0.0.5%eth0", "fe80::1%$(calc)", "10.0.0.5;reboot", "10.0.0.5 69",
	}
	for _, os := range []string{"windows", "linux"} {
		fijaWindows(t, os)
		for _, ip := range hostiles {
			cmds := []string{RedirectCommandIn("en", "tftp", ip, 6969), RedirectHintIn("en", "scp", ip, 2222), RedirectCleanup("tftp", ip, 6969), RedirectCleanupAddr("ftp", ip+":2121")}
			for _, c := range cmds {
				for _, bad := range []string{"calc", "reboot", "-x", "eth0", "\n", "\r", "\x00", "\u0085", "\u2028", "\u202e", "$", "`", "10.0.0.5'", "10.0.0.5 69"} {
					if strings.Contains(c, bad) {
						t.Errorf("%s %q: el texto hostil llegó al comando (%q): %q", os, ip, bad, c)
					}
				}
			}
		}
	}
}

// Loopback: Windows no filtra el tráfico local, la regla no hace falta (QA de Windows). Sin regla y sin «quitar».
func TestReglaFirewallLoopbackNoEmiteRegla(t *testing.T) {
	fijaWindows(t, "windows")
	for _, ip := range []string{"127.0.0.1", "127.5.5.5", "::1", "[::1]", "::ffff:127.0.0.1"} {
		for _, h := range []string{
			RedirectHintIn("es", "tftp", ip, 69), RedirectCommandIn("es", "tftp", ip, 69), RedirectCleanup("tftp", ip, 69),
			ServerHintIn("es", Config{Proto: "tftp"}, Ready{Addr: net.JoinHostPort(strings.Trim(ip, "[]"), "69")}, nil),
		} {
			if strings.Contains(h, "NetFirewallRule") {
				t.Errorf("%s: regla en loopback:\n%s", ip, h)
			}
		}
	}
	if h := RedirectCommandIn("es", "tftp", "10.0.0.5", 69); !strings.Contains(h, "New-NetFirewallRule") {
		t.Errorf("no loopback sin regla:\n%s", h)
	}
}
