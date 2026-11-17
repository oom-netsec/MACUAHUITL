package fileserve

import (
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unicode"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// hintOS y exePath son los que ven las pistas; variables para que las pruebas fijen el sistema y la ruta.
var (
	hintOS  = runtime.GOOS
	exePath = func() string {
		if p, err := os.Executable(); err == nil {
			return p
		}
		return "" // sin ruta no se emite regla: un -Program relativo no serviría
	}
)

// exeSeguro dice si la ruta se puede citar sin engañar al que la lee: unidad X:\ y nada de caracteres de control,
// saltos de línea (U+0085, U+2028/9), formato/bidi (Cf, salvo ZWNJ/ZWJ de los nombres persas e índicos) ni NUL. Si no, no se emite la regla (no se intenta escapar).
func exeSeguro(p string) bool {
	if len(p) < 3 || p[1] != ':' || p[2] != '\\' || !(p[0]|0x20 >= 'a' && p[0]|0x20 <= 'z') {
		return false
	}
	for _, r := range p {
		if unicode.IsControl(r) || (unicode.Is(unicode.Cf, r) && r != '\u200c' && r != '\u200d') || unicode.In(r, unicode.Zl, unicode.Zp) || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}

// esLoopback: Windows no filtra el tráfico local, así que con loopback no se emite regla.
func esLoopback(ip string) bool {
	a, err := netip.ParseAddr(strings.Trim(ip, "[]"))
	return err == nil && a.Unmap().IsLoopback()
}

// ruleOK: un solo criterio para emitir la regla y su limpieza: ni loopback ni ruta insegura.
func ruleOK(ip, exe string) bool { return !esLoopback(ip) && exeSeguro(exe) }

// NeedsRule dice si en Windows la IP necesita regla de firewall (loopback no).
func NeedsRule(ip string) bool { return !esLoopback(ip) }

// RedirectNoteIn explica, cuando la regla falta solo por la ruta del programa (Windows, IP que necesita regla,
// protocolo con puerto estándar), qué regla crear a mano: devuelve la clave del catálogo y el texto; "" si no aplica.
func RedirectNoteIn(loc, proto, ip string, port int) (code, text string) {
	s, ok := standard[proto]
	if !ok || !isWindows() || !NeedsRule(ip) || exeSeguro(exePath()) {
		return "", ""
	}
	_, addr := redirTarget(loc, ip)
	code = "fileserve.hint.win_rule_manual"
	return code, i18n.Msg(loc, code, i18n.A("trans", strings.ToUpper(s.trans), "ports", fwPorts(proto, port, [2]uint16{}), "ip", addr))
}

func isWindows() bool { return hintOS == "windows" }

// psq cita para PowerShell con comillas simples: ahí nada se expande ($var, $(...), acento grave). Dentro se duplica
// cada comilla simple, incluidas las tipográficas ‘ ’ ‚ ‛, que PowerShell también trata como comillas.
func psq(s string) string {
	for _, q := range []string{"'", "\u2018", "\u2019", "\u201a", "\u201b"} {
		s = strings.ReplaceAll(s, q, q+q)
	}
	return "'" + s + "'"
}

// fwName es el nombre de la regla; sirve para crearla y para quitarla. Lleva protocolo, IP y puerto para que quitar
// la de un servidor no toque la de otro (dos TFTP en IP distintas, scp y sftp en el 22). Sin IP concreta, «any».
func fwName(proto, ip string, port int) string {
	host := "any"
	if a, err := netip.ParseAddr(strings.Trim(ip, "[]")); err == nil && !a.IsUnspecified() && a.Zone() == "" {
		host = a.Unmap().String()
	}
	return fmt.Sprintf("MACUAHUITL %s %s %d", proto, host, port)
}

// firewallRule es la regla de entrada del Firewall de Windows (ADR 0012 h) que el usuario corre una vez como
// administrador; la app nunca la aplica. No hay redirección: IOS usa el puerto estándar y el servidor escucha
// ahí mismo, así que la regla abre el puerto de escucha, solo para esa IP y ese programa.
// FTP: los datos pasivos van por otros puertos; con rango (pasv) se abren junto al de control y sin rango los de
// ftp.go (puerto+1 a puerto+ftpPassive), o Any si se saldrían de 65535. Sin ruta del programa (exe vacío) no hay regla
// y se dice. firewallRule le agrega cómo quitarla; firewallCommand es solo el comando (lo que se copia).
func firewallRule(loc, proto, ip string, port int, exe string, pasv [2]uint16) string {
	c := firewallCommand(loc, proto, ip, port, exe, pasv)
	if c == "" {
		if _, ok := standard[proto]; ok && NeedsRule(ip) { // solo aquí viaja la nota: esta pista es prosa, no se copia
			return i18n.Msg(loc, "fileserve.hint.win_no_exe", nil)
		}
		return ""
	}
	return c + "   " + i18n.Msg(loc, "fileserve.hint.nft_remove", i18n.A("cmd", firewallRemove(proto, ip, port, exe)))
}

func firewallCommand(loc, proto, ip string, port int, exe string, pasv [2]uint16) string {
	s, ok := standard[proto]
	if !ok {
		return ""
	}
	if !ruleOK(ip, exe) {
		return ""
	}
	_, addr := redirTarget(loc, ip)
	return fmt.Sprintf(`New-NetFirewallRule -DisplayName %s -Direction Inbound -Program %s -LocalAddress %s -Protocol %s -LocalPort %s -Action Allow`,
		psq(fwName(proto, ip, port)), psq(exe), addr, strings.ToUpper(s.trans), fwPorts(proto, port, pasv))
}

// fwPorts son los puertos locales de la regla. FTP: con los pasivos (el rango dado o los de ftp.go).
func fwPorts(proto string, port int, pasv [2]uint16) string {
	if proto != "ftp" {
		return strconv.Itoa(port)
	}
	switch {
	case pasv[0] != 0 || pasv[1] != 0:
		return fmt.Sprintf("%d,%d-%d", port, pasv[0], pasv[1])
	case port+ftpPassive < 65536:
		return fmt.Sprintf("%d,%d-%d", port, port+1, port+ftpPassive)
	default:
		return "Any" // ftp.go tampoco fija rango ahí: el sistema elige
	}
}

// firewallRemove quita la regla de firewallRule ("" si el protocolo no tiene puerto estándar).
func firewallRemove(proto, ip string, port int, exe string) string {
	if _, ok := standard[proto]; !ok || !ruleOK(ip, exe) {
		return ""
	}
	return "Remove-NetFirewallRule -DisplayName " + psq(fwName(proto, ip, port))
}
