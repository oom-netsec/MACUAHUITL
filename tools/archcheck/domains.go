package archcheck

// Domains es la única lista de paquetes de dominio (ADR 0008): un paquete
// internal/<área> más sus subpaquetes. Un área nueva suma una línea aquí.
// Quedan fuera a propósito la infraestructura: core, service, vault, store,
// transport, ipc, sys, engine, platform, playbook, mask, secret; audit (la
// cadena de auditoría que escribe todo el núcleo, no una herramienta) y patrol
// (el motor que ejecuta los trabajos del núcleo).
var Domains = []string{
	"internal/acl",
	"internal/analyze",
	"internal/calc",
	"internal/capture",
	"internal/change",
	"internal/compliance",
	"internal/diag",
	"internal/fleet",
	"internal/ikedec",
	"internal/imgverify",
	"internal/iosconf",
	"internal/pcapan",
	"internal/pki",
	"internal/topo",
	"internal/upgrade",
	"internal/assist",
	"internal/adhoc",
	"internal/drift",
	"internal/cleaner",
	"internal/backup",
	"internal/terminal",
	"internal/msgkb",
	"internal/crashinfo",
	"internal/logintel",
	"internal/metrics",
	"internal/devices",
	"internal/scripts",
}

// Shared es lo que un dominio puede importar de otro dominio: parsers y
// utilidades sin estado. capture junta las salidas de un trabajo para
// change y upgrade (pre y post); iosconf (configuración IOS) y pcapan (pcap)
// son analizadores de texto o de captura que usan varios dominios; msgkb es la base de
// mensajes de Cisco que consultan el análisis de logs y el de crashinfo.
var Shared = []string{
	"internal/parse",
	"internal/capture",
	"internal/iosconf",
	"internal/pcapan",
	"internal/msgkb",
}
