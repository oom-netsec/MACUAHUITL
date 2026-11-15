package i18n

// Plantillas snmp-trap-host y netflow-export: etiquetas de unicastIPv4, motivos de rechazo y avisos del plan, y los textos de las plantillas.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"assist.what.snmp_trap_host":    e("destino de traps SNMP", "SNMP trap destination"),
		"assist.what.netflow_collector": e("colector de NetFlow", "NetFlow collector"),

		"assist.refused.ya_tiene_un_snmp_server_host":    e("{device} ya tiene un snmp-server host hacia {addr}: la reversa no lo restauraría", "{device} already has an snmp-server host to {addr}: the rollback would not restore it", "device", "addr"),
		"assist.refused.ya_tiene_objetos_flow":           e("{device} ya tiene {name}: la plantilla no toca objetos de Flexible NetFlow que ya existen", "{device} already has {name}: the template does not touch Flexible NetFlow objects that already exist", "device", "name"),
		"assist.refused.la_interfaz_ya_tiene_un_monitor": e("{port} de {device} ya tiene un ip flow monitor de entrada: la reversa no lo restauraría", "{port} on {device} already has an input ip flow monitor: the rollback would not restore it", "port", "device"),
		"assist.refused.la_interfaz_source_no_existe":    e("la interfaz de origen {port} no existe en {device}", "the source interface {port} does not exist on {device}", "port", "device"),

		"assist.note.snmp_trap_community_new": e("La community no existía: IOS la crea sola, de solo lectura y SIN ACL, al nombrarla en el snmp-server host: mientras exista, cualquier origen que la conozca puede leer por SNMP. La reversa la quita al final.", "The community did not exist: IOS creates it by itself, read-only and WITHOUT an ACL, when it is named in the snmp-server host: while it exists, any source that knows it can read over SNMP. The rollback removes it last."),
		"assist.note.netflow_input_only":      e("Solo se monitorea el tráfico de entrada (input): solo se ofrece input (algunos switches, como el 3560-CX, no admiten output en puertos físicos). Los contadores de bytes y paquetes son «long».", "Only ingress traffic (input) is monitored: only input is offered (some switches, such as the 3560-CX, do not support output on physical ports). The byte and packet counters are \"long\"."),

		"snippet.snmp-trap-host.name":                 e("Destino de traps SNMP", "SNMP trap destination"),
		"snippet.snmp-trap-host.field.address":        e("Servidor de traps", "Trap receiver"),
		"snippet.snmp-trap-host.field.port":           e("Puerto UDP", "UDP port"),
		"snippet.snmp-trap-host.field.port.help":      e("1-65535; por omisión 162.", "1-65535; default 162."),
		"snippet.snmp-trap-host.field.community":      e("Community", "Community"),
		"snippet.snmp-trap-host.field.community.help": e("4-32 caracteres, sin espacios ni @. No se muestra en ninguna parte. Si no existe en el equipo, IOS la crea de solo lectura y la reversa la quita.", "4-32 characters, no spaces or @. It is not shown anywhere. If it does not exist on the device, IOS creates it read-only and the rollback removes it."),
		"snippet.snmp-trap-host.field.traps":          e("Traps", "Traps"),
		"snippet.snmp-trap-host.field.traps.help":     e("snmp = linkdown, linkup y coldstart; config = cambios de configuración. Solo se agregan (y se quitan) los que el equipo no tenía.", "snmp = linkdown, linkup and coldstart; config = configuration changes. Only the ones the device did not have are added (and removed)."),

		"snippet.netflow-export.name":                 e("Exportar NetFlow (Flexible NetFlow v9)", "Export NetFlow (Flexible NetFlow v9)"),
		"snippet.netflow-export.field.address":        e("Colector", "Collector"),
		"snippet.netflow-export.field.port":           e("Puerto UDP", "UDP port"),
		"snippet.netflow-export.field.port.help":      e("1-65535; por omisión 2055.", "1-65535; default 2055."),
		"snippet.netflow-export.field.interface":      e("Interfaz", "Interface"),
		"snippet.netflow-export.field.interface.help": e("Puerto físico donde se monitorea el tráfico de entrada; no Vlan, Port-channel, Loopback ni Tunnel.", "Physical port where ingress traffic is monitored; not Vlan, Port-channel, Loopback or Tunnel."),
		"snippet.netflow-export.field.source":         e("Interfaz de origen", "Source interface"),
		"snippet.netflow-export.field.source.help":    e("Opcional, por ejemplo Vlan1: la IP desde la que el equipo exporta.", "Optional, for example Vlan1: the IP the device exports from."),

		"assist.refused.la_interfaz_no_esta_up":    e("{port} de {device} no está up/up (estado {status}): si ya estaba caída, después del apply no se sabría si la plantilla la tiró", "{port} on {device} is not up/up (state {status}): if it was already down, after the apply there would be no way to tell whether the template took it down", "port", "device", "status"),
		"assist.refused.no_se_pudo_leer_el_estado": e("no se pudo leer el estado de {port} en {device}", "could not read the state of {port} on {device}", "port", "device"),
	})
}
