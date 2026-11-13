package i18n

// Texto de los informes de la flota (internal/fleet/text.go, Stamp y el CSV/Markdown del inventario). Los datos
// (equipos, puertos, VLAN, MAC, IP, comandos) no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"fleet.text.warn":          e("AVISO: {w}", "WARNING: {w}", "w"),
		"fleet.text.find_head":     e("Búsqueda {query:q} ({mode}) en {n} equipos: {hits} coincidencia(s)", "Search {query:q} ({mode}) in {n} devices: {hits} match(es)", "query", "mode", "n", "hits"),
		"fleet.text.trace_head":    e("Rastreo L2 de {query} {mac}", "L2 trace of {query} {mac}", "query", "mac"),
		"fleet.text.trace_access":  e("Puerto de acceso: {device} {port} VLAN {vlan}", "Access port: {device} {port} VLAN {vlan}", "device", "port", "vlan"),
		"fleet.text.trace_noend":   e("Sin llegar al puerto de acceso ({end})", "Did not reach the access port ({end})", "end"),
		"fleet.text.path_head":     e("Camino {src} -> {dst}", "Path {src} -> {dst}", "src", "dst"),
		"fleet.text.path_via":      e(" (vía {via} por {out})", " (via {via} through {out})", "via", "out"),
		"fleet.text.path_via_ecmp": e(" (vía {via} por {out}, rama ECMP)", " (via {via} through {out}, ECMP branch)", "via", "out"),
		"fleet.text.path_route":    e(" ruta {route}", " route {route}", "route"),
		"fleet.text.path_arrived":  e(" LLEGÓ: {reason}", " ARRIVED: {reason}", "reason"),
		"fleet.text.path_cut":      e(" CORTE: {reason}", " CUT: {reason}", "reason"),
		"fleet.text.health_head":   e("Interfaces con problema: {n} (contadores acumulados desde el último clear counters); equipos con dato: estado {st}/{dev} · contadores {ct}/{dev}", "Interfaces with problems: {n} (counters accumulated since the last clear counters); devices with data: status {st}/{dev} · counters {ct}/{dev}", "n", "st", "dev", "ct"),
		"fleet.text.summary_head":  e("Tablero: {dev} equipos; con dato: cpu {cpu} · ntp {ntp} · reinicio {reboot} · memoria {mem} · flash {flash}", "Dashboard: {dev} devices; with data: cpu {cpu} · ntp {ntp} · reboot {reboot} · memory {mem} · flash {flash}", "dev", "cpu", "ntp", "reboot", "mem", "flash"),
		"fleet.text.no_alerts":     e("Sin alertas.", "No alerts."),
		"fleet.text.need":          e("Flash: se necesitan {size}", "Flash: {size} needed", "size"),
		"fleet.text.fits":          e("CABE", "FITS"),
		"fleet.text.no_fit":        e("NO CABE", "DOES NOT FIT"),
		"fleet.text.free_of":       e("libre {free} de {total}", "free {free} of {total}", "free", "total"),
		"fleet.text.used":          e("{pct} % usada", "{pct} % used", "pct"),
		"fleet.text.no_flash":      e("sin dato de flash", "no flash data"),
		"fleet.text.pool":          e("pool libre {free} ({pct} % usado)", "pool free {free} ({pct} % used)", "free", "pct"),
		"fleet.text.no_dram":       e("sin dato de DRAM", "no DRAM data"),
		"fleet.ago.now":            e("ahora", "now"),
		"fleet.ago.min":            e("hace {n} min", "{n} min ago", "n"),
		"fleet.ago.h":              e("hace {n} h", "{n} h ago", "n"),
		"fleet.ago.d":              e("hace {n} d", "{n} d ago", "n"),
		"fleet.stale":              e("DATO VIEJO", "OLD DATA"),
		"fleet.inv.head":           e("Equipo,Tipo,Nombre,Descripción,PID,VID,Serie,Modelo,Versión,Fuente,Evidencia", "Device,Type,Name,Description,PID,VID,Serial,Model,Version,Source,Evidence"),
		"fleet.inv.kind.equipo":    e("equipo", "device"),
		"fleet.inv.kind.modulo":    e("modulo", "module"),
	})
}
