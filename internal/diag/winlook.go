package diag

import (
	"os"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Lógica de Windows sin dependencia del sistema (ADR 0012, f): corre y se prueba también en Linux.

// winAbs acepta solo «X:\…» sin «..», UNC, «\\?\» ni barras dobles; copia de la de internal/paths, que no es exportada.
func winAbs(s string) (string, bool) {
	if len(s) < 3 || !(s[0]|0x20 >= 'a' && s[0]|0x20 <= 'z') || s[1] != ':' || s[2] != '\\' {
		return "", false
	}
	if strings.Contains(s, "/") || strings.Contains(s[3:], `\\`) {
		return "", false
	}
	for _, e := range strings.Split(s[3:], `\`) {
		if e == ".." {
			return "", false
		}
	}
	if s = strings.TrimRight(s, `\`); len(s) == 2 {
		return "", false
	}
	return s, true
}

// winLook resuelve la herramienta a una ruta absoluta conocida; nunca consulta el PATH. exeDir es la carpeta del
// ejecutable del núcleo: iperf3 también se busca en <exeDir>\tools. Eso no abre un hueco nuevo: quien pueda escribir
// ahí ya puede reemplazar el propio núcleo.
func winLook(env func(string) string, exeDir string, isFile func(string) bool, bin string) (string, error) {
	var c []string
	add := func(root, rel string) {
		if r, ok := winAbs(env(root)); ok {
			c = append(c, r+rel)
		}
	}
	switch bin {
	case "ping":
		add("SystemRoot", `\System32\PING.EXE`)
	case "tracert":
		add("SystemRoot", `\System32\TRACERT.EXE`)
	case "nmap":
		add("ProgramFiles", `\Nmap\nmap.exe`)
		add("ProgramFiles(x86)", `\Nmap\nmap.exe`)
	case "dumpcap":
		add("ProgramFiles", `\Wireshark\dumpcap.exe`)
		add("ProgramFiles(x86)", `\Wireshark\dumpcap.exe`)
	case "iperf3":
		add("ProgramFiles", `\iperf3\iperf3.exe`)
		if d, ok := winAbs(exeDir); ok {
			c = append(c, d+`\tools\iperf3.exe`)
		}
	}
	for _, p := range c {
		if isFile(p) {
			return p, nil
		}
	}
	return "", os.ErrNotExist
}

// winChildEnv es el entorno del hijo en Windows: SystemRoot, TEMP/TMP y un PATH con System32 y la carpeta de la herramienta.
func winChildEnv(env func(string) string, tool string) []string {
	root, _ := winAbs(env("SystemRoot"))
	out := []string{"SystemRoot=" + root}
	for _, k := range []string{"TEMP", "TMP"} {
		t, ok := winAbs(env(k))
		if !ok { // nunca C:\Windows\Temp: sin TEMP válido, el de la cuenta; y si tampoco, ninguno
			if l, lok := winAbs(env("LOCALAPPDATA")); lok {
				t, ok = l+`\Temp`, true
			}
		}
		if ok {
			out = append(out, k+"="+t)
		}
	}
	dir := tool[:max(strings.LastIndexByte(tool, '\\'), 0)]
	return append(out, `PATH=`+root+`\System32;`+dir)
}

// winAdapter es un adaptador de red real del sistema: su nombre amistoso y su GUID («{…}»).
type winAdapter struct{ Friendly, Name string }

// winAdapters lista los adaptadores reales; en Windows lo reemplaza GetAdaptersAddresses.
var winAdapters = func() []winAdapter { return nil }

// winIfaceName traduce un nombre amistoso («Ethernet 2») a \Device\NPF_{GUID} solo si es IGUAL al de un adaptador
// real; todo lo demás queda como vino y lo decide winIfaceRe. Así no se acepta nada que el sistema no tenga.
func winIfaceName(name string, ads []winAdapter) string {
	for _, a := range ads {
		if a.Friendly == name {
			return `\Device\NPF_` + a.Name
		}
	}
	return name
}

// installErr es el error de herramienta no instalada, con la instrucción propia del sistema.
func installErr(goos, bin string) error {
	if goos != "windows" {
		return i18n.Wrap("diag.err.install", ErrNotInstalled, i18n.A("bin", bin, "pkg", packages[bin]))
	}
	switch bin {
	case "nmap":
		return i18n.Wrap("diag.err.install_win", ErrNotInstalled, i18n.A("bin", bin, "url", "https://nmap.org/download"))
	case "dumpcap":
		return i18n.Wrap("diag.err.install_win", ErrNotInstalled, i18n.A("bin", "dumpcap (Wireshark/Npcap)", "url", "https://www.wireshark.org/download.html"))
	case "iperf3":
		return i18n.Wrap("diag.err.install_iperf_win", ErrNotInstalled, nil)
	}
	return i18n.Wrap("diag.err.install_sys_win", ErrNotInstalled, i18n.A("bin", bin))
}
