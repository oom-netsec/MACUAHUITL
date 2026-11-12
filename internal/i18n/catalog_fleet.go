package i18n

// Flota: avisos de carga y de cada consulta, motivos del camino, notas del rastreo y textos de las filas del
// tablero. Los valores (equipos, IPs, MAC, puertos, comandos, salidas de equipos) viajan como argumentos y no
// se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		// avisos de carga
		"fleet.warn.cap_devs":       e("tope de {max} equipos alcanzado: el resto de las carpetas no se cargó; la flota está incompleta", "limit of {max} devices reached: the remaining folders were not loaded; the fleet is incomplete", "max"),
		"fleet.warn.cap_entries":    e("tope de {max} archivos alcanzado: el resto no se cargó; la flota está incompleta", "limit of {max} files reached: the rest was not loaded; the fleet is incomplete", "max"),
		"fleet.warn.cap_bytes":      e("tope de lectura de {mib} MiB alcanzado: el resto no se cargó; la flota está incompleta", "read limit of {mib} MiB reached: the rest was not loaded; the fleet is incomplete", "mib"),
		"fleet.warn.dir_unreadable": e("{dir}: no se pudo leer la carpeta: {error}", "{dir}: could not read the folder: {error}", "dir", "error"),
		"fleet.warn.system":         e("{error}", "{error}", "error"),
		"fleet.warn.file_error":     e("{file}: {error}", "{file}: {error}", "file", "error"),
		"fleet.warn.zip_entry":      e("{file} · {entry}: {error}", "{file} · {entry}: {error}", "file", "entry", "error"),
		"fleet.warn.no_outputs":     e("{job}/{dir}: ningún archivo con salidas de Patrol (encabezados =====); se ignora", "{job}/{dir}: no file with Patrol outputs (===== headers); ignored", "job", "dir"),
		"fleet.warn.output_over":    e("{key} · {cmd}: la salida pasa de los topes de lectura y quedó truncada; se ignora", "{key} · {cmd}: the output exceeds the read limits and was truncated; ignored", "key", "cmd"),
		"fleet.warn.read_error":     e("{key}: error de lectura, el resto del archivo no se leyó: {error}", "{key}: read error, the rest of the file was not read: {error}", "key", "error"),
		"fleet.warn.file_cap":       e("{key}: se alcanzó un tope de lectura (archivo de más de {mib} MiB o carga total); el resto del archivo no se leyó", "{key}: a read limit was reached (file over {mib} MiB or total load); the rest of the file was not read", "key", "mib"),

		// lectura de una tabla
		"fleet.warn.only_filtered":  e("{dev} · {cmd}: solo hay salida filtrada con pipe ({at}); no sirve como tabla completa, se ignora", "{dev} · {cmd}: only piped, filtered output exists ({at}); it is not a full table, ignored", "dev", "cmd", "at"),
		"fleet.warn.newer_filtered": e("{dev} · {cmd}: hay una salida filtrada con pipe más reciente ({at}) que se ignora; se usa la completa de {full}", "{dev} · {cmd}: there is a more recent piped, filtered output ({at}) that is ignored; the full one from {full} is used", "dev", "cmd", "at", "full"),
		"fleet.warn.truncated":      e("{dev} · {cmd}: salida truncada por los topes de lectura ({at}); se ignora", "{dev} · {cmd}: output truncated by the read limits ({at}); ignored", "dev", "cmd", "at"),
		"fleet.warn.rejected":       e("{dev} · {cmd}: el equipo rechazó el comando ({at}); se ignora", "{dev} · {cmd}: the device rejected the command ({at}); ignored", "dev", "cmd", "at"),
		"fleet.warn.format":         e("{dev} · {cmd}: formato inesperado, se ignora esta salida ({at})", "{dev} · {cmd}: unexpected format, this output is ignored ({at})", "dev", "cmd", "at"),

		// búsqueda y rastreo L2
		"fleet.warn.no_source":       e("sin {cmd}: {devs} (la búsqueda no cubre esos equipos en esa fuente)", "no {cmd}: {devs} (the search does not cover those devices in that source)", "cmd", "devs"),
		"fleet.warn.mac_absent":      e("la MAC {mac} no aparece en ninguna tabla de direcciones de la flota", "MAC {mac} does not appear in any address table of the fleet", "mac"),
		"fleet.warn.mac_missing":     e("{dev} no tiene la MAC {mac} en su tabla (la entrada pudo expirar o la evidencia es de otra hora)", "{dev} does not have MAC {mac} in its table (the entry may have aged out or the evidence is from another time)", "dev", "mac"),
		"fleet.warn.trace_loop":      e("bucle en el seguimiento: {dev} {port} ya se visitó; se corta (revisa STP o evidencia de horas distintas)", "loop while tracing: {dev} {port} was already visited; stopping (check STP or evidence from different times)", "dev", "port"),
		"fleet.warn.trunk_no_nbr":    e("{dev} {port} es un trunk o port-channel sin vecino CDP/LLDP: puede faltar evidencia de un equipo; el rastreo se corta ahí", "{dev} {port} is a trunk or port-channel with no CDP/LLDP neighbor: a device's evidence may be missing; the trace stops there", "dev", "port"),
		"fleet.warn.nbr_no_evidence": e("el vecino {neighbor} ({ip}) no tiene evidencia en la flota: el rastreo se corta ahí", "neighbor {neighbor} ({ip}) has no evidence in the fleet: the trace stops there", "neighbor", "ip"),
		"fleet.warn.trace_hops":      e("el rastreo pasó de {max} saltos; se corta", "the trace went over {max} hops; stopping", "max"),
		"fleet.warn.ip_many_macs":    e("la IP {ip} tiene {n} MAC distintas en el ARP de la flota; se usa la de la evidencia más reciente ({mac})", "IP {ip} has {n} different MACs in the fleet's ARP; the one from the most recent evidence is used ({mac})", "ip", "n", "mac"),
		"fleet.warn.ip_no_arp":       e("ningún equipo tiene la IP {ip} en su ARP: no se puede saber su MAC", "no device has IP {ip} in its ARP: its MAC cannot be determined", "ip"),
		"fleet.warn.bad_query":       e("{query:q} no es una MAC ni una IP", "{query:q} is neither a MAC nor an IP", "query"),
		"fleet.warn.mac_also":        e("la MAC también aparece en {dev} puerto {port}, fuera de este recorrido", "the MAC also appears on {dev} port {port}, outside this path", "dev", "port"),

		// salud y capacidad
		"fleet.warn.no_status":   e("{dev}: sin evidencia utilizable de show interfaces status; no se evaluó err-disabled ni half-duplex", "{dev}: no usable evidence of show interfaces status; err-disabled and half-duplex were not evaluated", "dev"),
		"fleet.warn.no_counters": e("{dev}: sin evidencia utilizable de show interfaces; no se evaluaron CRC, errores ni drops", "{dev}: no usable evidence of show interfaces; CRC, errors and drops were not evaluated", "dev"),
		"fleet.warn.no_flash":    e("{dev}: sin dato de flash (dir flash: / dir bootflash:); no se sabe si cabe", "{dev}: no flash data (dir flash: / dir bootflash:); it is not known whether it fits", "dev"),

		// camino L3
		"fleet.warn.global_only":    e("solo tabla global; VRF, PBR y NAT no modelados", "global table only; VRF, PBR and NAT are not modeled"),
		"fleet.warn.bad_endpoints":  e("origen y destino deben ser IP o el nombre de un equipo de la flota ({src:q} → {dst:q})", "source and destination must be an IP or the name of a device in the fleet ({src:q} → {dst:q})", "src", "dst"),
		"fleet.warn.route_unread":   e("{dev} · show ip route: línea con forma de ruta no leída, la tabla puede estar incompleta: {line:q}", "{dev} · show ip route: a route-shaped line was not read, the table may be incomplete: {line:q}", "dev", "line"),
		"fleet.warn.cef_fallback":   e("{dev}: sin show ip route; se usa show ip cef (sin distancia ni códigos de protocolo)", "{dev}: no show ip route; show ip cef is used (no distance or protocol codes)", "dev"),
		"fleet.warn.many_gateways":  e("el origen {src} tiene {n} puertas de enlace en la flota ({first}...); se sigue la primera con ARP del origen", "source {src} has {n} gateways in the fleet ({first}...); the first one with an ARP entry for the source is followed", "src", "n", "first"),
		"fleet.warn.no_arp_l2":      e("{dev} no tiene {ip} en su ARP: no se puede ubicar el tramo L2", "{dev} does not have {ip} in its ARP: the L2 segment cannot be located", "dev", "ip"),
		"fleet.warn.path_hops":      e("el camino pasó de {max} saltos (ramas ECMP); se corta", "the path went over {max} hops (ECMP branches); stopping", "max"),
		"fleet.warn.no_arp":         e("{dev} no tiene {ip} en su ARP", "{dev} does not have {ip} in its ARP", "dev", "ip"),
		"fleet.warn.recursive":      e("{dev}: el siguiente salto {nh} es recursivo; se resolvió a {to} por {iface}", "{dev}: next hop {nh} is recursive; it was resolved to {to} via {iface}", "dev", "nh", "to", "iface"),
		"fleet.warn.recursive_ecmp": e("{dev}: el salto recursivo {nh} tiene {n} salidas ECMP; se sigue la primera", "{dev}: recursive hop {nh} has {n} ECMP exits; the first one is followed", "dev", "nh", "n"),

		// motivos de un salto del camino
		"fleet.reason.too_many_hops":  e("demasiados saltos", "too many hops"),
		"fleet.reason.no_routes":      e("sin show ip route ni show ip cef de {dev}", "no show ip route or show ip cef from {dev}", "dev"),
		"fleet.reason.no_route":       e("sin ruta a {dst} en {dev}", "no route to {dst} on {dev}", "dst", "dev"),
		"fleet.reason.discard":        e("descartado (Null0/drop): la ruta {prefix} en {dev} no reenvía", "discarded (Null0/drop): route {prefix} on {dev} does not forward", "prefix", "dev"),
		"fleet.reason.no_nexthop":     e("la ruta {prefix} en {dev} no tiene siguiente salto ni interfaz", "route {prefix} on {dev} has no next hop or interface", "prefix", "dev"),
		"fleet.reason.l2_ended":       e("red conectada pero el rastreo L2 del destino terminó en: {end}", "connected network but the L2 trace of the destination ended at: {end}", "end"),
		"fleet.reason.no_arp":         e("red conectada ({iface}) pero sin entrada ARP del destino: no se sabe en qué puerto está", "connected network ({iface}) but no ARP entry for the destination: the port it is on is unknown", "iface"),
		"fleet.reason.no_evidence":    e("sin evidencia del siguiente equipo (el salto {nh} no es de ningún equipo recolectado)", "no evidence of the next device (hop {nh} does not belong to any collected device)", "nh"),
		"fleet.reason.routing_loop":   e("bucle de enrutamiento: vuelve a {dev}", "routing loop: returns to {dev}", "dev"),
		"fleet.reason.local_dest":     e("el destino es una interfaz de este equipo", "the destination is an interface of this device"),
		"fleet.reason.access_port":    e("puerto de acceso {dev} {port} VLAN {vlan}", "access port {dev} {port} VLAN {vlan}", "dev", "port", "vlan"),
		"fleet.reason.no_source":      e("ningún equipo de la flota tiene una ruta conectada al origen {src} (sin evidencia del equipo de origen)", "no device in the fleet has a connected route to source {src} (no evidence from the source device)", "src"),
		"fleet.reason.rec_not_ip":     e("siguiente salto recursivo no resuelto: el salto {ip} no es una IP", "unresolved recursive next hop: hop {ip} is not an IP", "ip"),
		"fleet.reason.rec_no_route":   e("siguiente salto recursivo no resuelto: sin ruta a {ip} en {dev}", "unresolved recursive next hop: no route to {ip} on {dev}", "ip", "dev"),
		"fleet.reason.rec_no_nexthop": e("siguiente salto recursivo no resuelto: la ruta a {ip} no tiene siguiente salto", "unresolved recursive next hop: the route to {ip} has no next hop", "ip"),
		"fleet.reason.rec_depth":      e("siguiente salto recursivo no resuelto: más de {n} niveles de recursión", "unresolved recursive next hop: more than {n} levels of recursion", "n"),

		// notas de un salto del rastreo L2
		"fleet.note.self":        e("la MAC es del propio equipo", "the MAC belongs to the device itself"),
		"fleet.note.loop":        e("bucle", "loop"),
		"fleet.note.access_edge": e("puerto de acceso (equipo extremo: {caps})", "access port (end device: {caps})", "caps"),
		"fleet.note.trunk":       e("trunk sin vecino CDP/LLDP", "trunk with no CDP/LLDP neighbor"),
		"fleet.note.access":      e("puerto de acceso", "access port"),

		// filas del tablero y evidencias
		"fleet.value.ntp_unsynced": e("no sincronizado", "not synchronized"),
		"fleet.value.used":         e("{pct} % usada", "{pct} % used", "pct"),
		"fleet.detail.reboot":      e("reinicio en las 24 h previas a la evidencia", "reload in the 24 h before the evidence"),
		"fleet.detail.mem_free":    e("libre {free} de {total}", "{free} free of {total}", "free", "total"),
		"fleet.detail.flash_free":  e("{free} libre de {total}", "{free} free of {total}", "free", "total"),
		"fleet.evidence.half":      e("{port} duplex {duplex} velocidad {speed}", "{port} duplex {duplex} speed {speed}", "port", "duplex", "speed"),
	})
}

// Errores gRPC y de carga de la flota.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"fleet.err.relative_path": e("la ruta {path:q} debe ser absoluta", "the path {path:q} must be absolute", "path"),
		"fleet.err.empty_query":   e("indica una IP, MAC o nombre", "give an IP, MAC or name"),
		"fleet.err.empty_trace":   e("indica una MAC o una IP", "give a MAC or an IP"),
		"fleet.err.empty_path":    e("indica origen y destino", "give a source and a destination"),
		"fleet.err.bad_size":      e("tamaño {size:q} inválido: usa 800M, 1.2G, 500000", "invalid size {size:q}: use 800M, 1.2G, 500000", "size"),
		"fleet.err.not_dir":       e("{path} no es una carpeta", "{path} is not a folder", "path"),
		"fleet.err.load":          e("flota: {cause}", "fleet: {cause}", "cause"),
		"fleet.err.no_outputs":    e("flota: {dir} no contiene salidas de Patrol (carpetas <equipo>_<ip> con encabezados =====)", "fleet: {dir} has no Patrol outputs (<device>_<ip> folders with ===== headers)", "dir"),
	})
}
