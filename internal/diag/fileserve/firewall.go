package fileserve

import (
	"fmt"
	"os"
	"runtime"
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
		return "macuahuitld.exe"
	}
)

func isWindows() bool { return hintOS == "windows" }

// fwName es el nombre de la regla; sirve para crearla y para quitarla. Una por protocolo y puerto.
func fwName(proto string, port int) string {
	return fmt.Sprintf("MACUAHUITL %s %d", strings.ToUpper(standard[proto].trans), port)
}

// firewallRule es la regla de entrada del Firewall de Windows (ADR 0012 h) que el usuario corre una vez como
// administrador; la app nunca la aplica. No hay redirección: IOS usa el puerto estándar y el servidor escucha
// ahí mismo, así que la regla abre el puerto de escucha, solo para esa IP y ese programa.
// shortcut: FTP pasivo necesitaría otra regla para su rango de datos; no se genera, se documenta en la UI.
func firewallRule(loc, proto, ip string, port int, exe string) string {
	s, ok := standard[proto]
	if !ok {
		return ""
	}
	_, addr := redirTarget(loc, ip)
	return fmt.Sprintf(`New-NetFirewallRule -DisplayName "%s" -Direction Inbound -Program "%s" -LocalAddress %s -Protocol %s -LocalPort %d -Action Allow   %s`,
		fwName(proto, port), exe, addr, strings.ToUpper(s.trans), port, i18n.Msg(loc, "fileserve.hint.nft_remove", i18n.A("cmd", firewallRemove(proto, port))))
}

// firewallRemove quita la regla de firewallRule ("" si el protocolo no tiene puerto estándar).
func firewallRemove(proto string, port int) string {
	if _, ok := standard[proto]; !ok {
		return ""
	}
	return fmt.Sprintf(`Remove-NetFirewallRule -DisplayName "%s"`, fwName(proto, port))
}
