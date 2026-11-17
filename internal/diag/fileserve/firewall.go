package fileserve

import (
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"

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
	if c == "" || exe == "" {
		return c
	}
	return c + "   " + i18n.Msg(loc, "fileserve.hint.nft_remove", i18n.A("cmd", firewallRemove(proto, ip, port)))
}

func firewallCommand(loc, proto, ip string, port int, exe string, pasv [2]uint16) string {
	s, ok := standard[proto]
	if !ok {
		return ""
	}
	if exe == "" {
		return i18n.Msg(loc, "fileserve.hint.win_no_exe", nil)
	}
	_, addr := redirTarget(loc, ip)
	lp := strconv.Itoa(port)
	if proto == "ftp" {
		switch {
		case pasv[0] != 0 || pasv[1] != 0:
			lp = fmt.Sprintf("%d,%d-%d", port, pasv[0], pasv[1])
		case port+ftpPassive < 65536:
			lp = fmt.Sprintf("%d,%d-%d", port, port+1, port+ftpPassive)
		default:
			lp = "Any" // ftp.go tampoco fija rango ahí: el sistema elige
		}
	}
	return fmt.Sprintf(`New-NetFirewallRule -DisplayName %s -Direction Inbound -Program %s -LocalAddress %s -Protocol %s -LocalPort %s -Action Allow`,
		psq(fwName(proto, ip, port)), psq(exe), addr, strings.ToUpper(s.trans), lp)
}

// firewallRemove quita la regla de firewallRule ("" si el protocolo no tiene puerto estándar).
func firewallRemove(proto, ip string, port int) string {
	if _, ok := standard[proto]; !ok {
		return ""
	}
	return "Remove-NetFirewallRule -DisplayName " + psq(fwName(proto, ip, port))
}
