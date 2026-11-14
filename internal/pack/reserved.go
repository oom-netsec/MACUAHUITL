package pack

import "regexp"

// thirdPartyEditor es la forma del editor de un paquete que no es oficial: minúsculas y dígitos, sin guion. Así su
// prefijo «<editor>-» nunca puede empezar con el primer segmento de un ID oficial (ADR 0010).
var thirdPartyEditor = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// reservedSegments es la ÚNICA lista de segmentos que un editor de terceros no puede usar: el primer segmento (antes
// del «-») de los IDs de playbook y de script que un paquete oficial ya trae o traerá. Una prueba de CI
// (TestSegmentosOficialesEstanReservados) falla si el contenido base, lo movido a oom/ios-xe o un packs/* usa un primer
// segmento que no esté aquí: quien agregue un segmento oficial debe reservarlo en esta lista.
var reservedSegments = map[string]bool{
	// El editor de los paquetes oficiales y el prefijo de todos los scripts de biblioteca.
	"oom": true, "lib": true,
	// Plataformas (playbook.knownPlatforms y scripts.Platforms, partidas por el guion).
	"ios": true, "xe": true, "nx": true, "os": true, "cat9k": true, "ftd": true, "ise": true, "sda": true,
	"wlc": true, "9800": true, "aireos": true, "asa": true, "cualquiera": true,
	// Primer segmento de los IDs del contenido base: playbooks que siguen embebidos y scripts de configuración.
	"pre": true, "upgrade": true, "metricas": true, "analisis": true, "tac": true, "cfg": true,
	// Los de los playbooks movidos a oom/ios-xe.
	"l1": true, "l2": true, "l3": true, "plat": true, "svc": true, "vpn": true, "cpu": true, "errores": true,
	"flota": true, "topologia": true, "wan": true,
	// Previstos para paquetes oficiales posteriores (ADR 0010: nx-os, fw, aci, wireless, ise, sda).
	"fw": true, "aci": true, "wireless": true,
	// Los de oom/nx-os (además de plat, l1, l2, l3, sec, svc y tac, ya reservados).
	"vxlan": true, "fex": true,
	// Los de oom/wlc-9800 (controlador inalámbrico Catalyst 9800).
	// Los de oom/cat9k y oom/sda (además de plat, l1, l2, l3, cpu, sec, svc y tac, ya reservados).
	"stack": true, "svl": true, "poe": true, "asic": true, "lisp": true, "fabric": true, "edge": true, "border": true,
	"ctrl": true, "ap": true, "cli": true, "rf": true, "wlan": true, "sec": true, "mob": true,
}

// IsReservedSegment dice si s es un primer segmento reservado para contenido oficial.
func IsReservedSegment(s string) bool { return reservedSegments[s] }
