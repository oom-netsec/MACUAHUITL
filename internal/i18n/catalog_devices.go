package i18n

import (
	"regexp"
	"slices"
)

var tplArgRe = regexp.MustCompile(`\{([a-z_0-9]+)(?::q|\|[^}]*)?\}`)

// tplArgs son los argumentos que usan las plantillas (para no listarlos a mano en cada código).
func tplArgs(tpls ...string) []string {
	var out []string
	for _, t := range tpls {
		for _, m := range tplArgRe.FindAllStringSubmatch(t, -1) {
			if !slices.Contains(out, m[1]) {
				out = append(out, m[1])
			}
		}
	}
	slices.Sort(out)
	return out
}

// Fase 30e: libreta de hosts, archivos de import y lista de equipos (internal/devices y su servicio).
func init() {
	e := func(es, en string) entry { return entry{Es: es, En: en, Args: tplArgs(es, en)} }
	add(map[string]entry{
		// Campos de un host
		"hostfield.addr_len":      e("la dirección va de 1 a 253 caracteres", "the address must be 1 to 253 characters long"),
		"hostfield.addr_zone":     e("la dirección no admite zona (%)", "the address does not accept a zone (%)"),
		"hostfield.addr_dns":      e("dirección {addr:q}: use una IP o un nombre DNS (letras, números y guiones), sin espacios, @, esquema, puerto ni ruta", "address {addr:q}: use an IP or a DNS name (letters, digits and hyphens), without spaces, @, scheme, port or path"),
		"hostfield.addr_ip":       e("dirección {addr:q}: parece una IP inválida", "address {addr:q}: looks like an invalid IP"),
		"hostfield.name":          e("el nombre va de 1 a 64 caracteres, sin espacios en los extremos ni caracteres de control", "the name must be 1 to 64 characters, with no leading or trailing spaces and no control characters"),
		"hostfield.port":          e("el puerto va de 1 a 65535", "the port must be between 1 and 65535"),
		"hostfield.platform":      e("plataforma {platform:q} fuera de la lista ({list})", "platform {platform:q} is not in the list ({list})"),
		"hostfield.folder":        e("la carpeta es de un solo nivel: 1 a 48 caracteres entre letras, números, espacio, _, . y -", "the folder is a single level: 1 to 48 characters among letters, digits, space, _, . and -"),
		"hostfield.tags_max":      e("máximo {max} etiquetas", "at most {max} tags"),
		"hostfield.tag_bad":       e("etiqueta {tag:q} inválida o repetida: 1 a 24 caracteres entre a-z, 0-9 y -", "tag {tag:q} is invalid or repeated: 1 to 24 characters among a-z, 0-9 and -"),
		"hostfield.notes":         e("las notas pasan de {max} caracteres o traen caracteres de control", "the notes exceed {max} characters or contain control characters"),
		"hostfield.credential_id": e("no es un id de la bóveda", "not a vault id"),
		"hostfield.not_int":       e("{value:q} no es un número entero", "{value:q} is not an integer"),
		"hostfield.label":         e("la etiqueta de credencial pasa de {max} caracteres o trae caracteres de control", "the credential label exceeds {max} characters or contains control characters"),
		"hostfield.name_dup_row":  e("el nombre ya está en la fila {row}", "the name is already in row {row}"),
		"hostfield.addr_dup_row":  e("{key} ya está en la fila {row}", "{key} is already in row {row}"),

		// Archivos de import (CSV y JSON)
		"hostfile.too_big":        e("el archivo pasa de 5 MB", "the file exceeds 5 MB"),
		"hostfile.not_utf8":       e("el archivo no es UTF-8", "the file is not UTF-8"),
		"hostfile.empty":          e("el archivo está vacío: falta el encabezado {header}", "the file is empty: the header {header} is missing"),
		"hostfile.header_read":    e("encabezado ilegible: {cause}", "unreadable header: {cause}"),
		"hostfile.too_many_rows":  e("el archivo trae más de {max} filas; el tope es {max}", "the file has more than {max} rows; the limit is {max}"),
		"hostfile.header_order":   e("encabezado inválido: las columnas deben ir en este orden: {want}", "invalid header: the columns must come in this order: {want}"),
		"hostfile.header_diff":    e("encabezado inválido (se espera {want}): faltan [{missing}]; sobran [{extra}]", "invalid header (expected {want}): missing [{missing}]; extra [{extra}]"),
		"hostfile.quote_open":     e("comillas sin cerrar: se ignoró el resto del archivo desde la línea {line}", "unclosed quotes: the rest of the file was ignored from line {line}"),
		"hostfile.quote_bad":      e("comillas mal cerradas o sobrantes", "badly closed or stray quotes"),
		"hostfile.columns":        e("tiene {got} columnas; se esperaban {want}", "has {got} columns; {want} were expected"),
		"hostfile.not_hosts":      e("no es un archivo de hosts: {cause}", "not a hosts file: {cause}"),
		"hostfile.bad_format":     e("formato {got:q}: se esperaba {want:q}", "format {got:q}: expected {want:q}"),
		"hostfile.bad_version":    e("versión {got} no soportada (solo la {want})", "version {got} not supported (only {want})"),
		"hostfile.trailing":       e("hay datos después del JSON del archivo", "there is data after the file's JSON"),
		"hostfile.no_list":        e("falta la lista «hosts»", "the \"hosts\" list is missing"),
		"hostfile.not_list":       e("«hosts» no es una lista: {cause}", "\"hosts\" is not a list: {cause}"),
		"hostfile.too_many_hosts": e("el archivo trae {n} hosts; el tope es {max}", "the file has {n} hosts; the limit is {max}"),
		"hostfile.entry":          e("entrada ilegible: {cause}", "unreadable entry: {cause}"),
		"hostfile.checksum":       e("la suma de verificación no coincide: el archivo está dañado o fue modificado", "the checksum does not match: the file is damaged or was modified"),
		"hostfile.format_unknown": e("formato no reconocido para {path:q}: use la extensión .csv o .json, o pida el formato csv o json", "unrecognized format for {path:q}: use the .csv or .json extension, or ask for the csv or json format"),

		// Decisiones del import
		"hostimport.extra_keys":   e("decisión para destinos que no están en el archivo: {keys}", "decision for targets that are not in the file: {keys}"),
		"hostimport.unknown":      e("decisión {action:q} desconocida para {key}", "unknown decision {action:q} for {key}"),
		"hostimport.only_skip":    e("{key} es {state:q}: solo se puede omitir", "{key} is {state:q}: it can only be skipped"),
		"hostimport.no_rename":    e("{key} ya existe con otros datos: solo se puede reemplazar u omitir (renombrar dejaría dos hosts en el mismo destino)", "{key} already exists with other data: it can only be replaced or skipped (renaming would leave two hosts at the same target)"),
		"hostimport.missing":      e("falta la decisión de {n} conflicto(s): {keys}", "the decision for {n} conflict(s) is missing: {keys}"),
		"hostimport.twice":        e("dos decisiones reemplazan el mismo host guardado ({name})", "two decisions replace the same saved host ({name})"),
		"hostimport.dup_name":     e("reemplazar {old} dejaría dos hosts con el nombre {name:q}", "replacing {old} would leave two hosts named {name:q}"),
		"hostimport.dup_target":   e("reemplazar {old} dejaría dos hosts en {key}", "replacing {old} would leave two hosts at {key}"),
		"hostimport.name_exists":  e("el nombre {name:q} ya existe", "the name {name:q} already exists"),
		"hostimport.key_exists":   e("{key} ya existe", "{key} already exists"),
		"hostimport.over_max":     e("la libreta pasaría de {max} hosts", "the address book would exceed {max} hosts"),
		"hostimport.dup_decision": e("decisión repetida para {key}", "repeated decision for {key}"),

		// Libreta (servicio)
		"hosts.err.full":           e("la libreta llegó a {max} hosts", "the address book has reached {max} hosts"),
		"hosts.err.no_id":          e("no hay un host de la libreta con id {id:q}", "there is no address-book host with id {id:q}"),
		"hosts.err.dup_name":       e("ya hay un host llamado {name:q}", "there is already a host named {name:q}"),
		"hosts.err.dup_target":     e("{key:q} ya está en la libreta como {name:q}", "{key:q} is already in the address book as {name:q}"),
		"hosts.err.export_count":   e("son más de {max} hosts y el import no los aceptaría en un solo archivo: parte el export en varios archivos eligiendo los hosts por ids (por ejemplo, los de cada carpeta, que da la lista de la libreta)", "that is more than {max} hosts and the import would not accept them in a single file: split the export into several files by choosing the hosts by id (for example, those of each folder, which the address-book list gives)"),
		"hosts.warn.vault_closed":  e("la bóveda está cerrada: la credencial se guardó sin validar", "the vault is closed: the credential was saved without validation"),
		"hosts.warn.label_lost":    e("{name}: no se pudo leer la etiqueta de su credencial (bóveda cerrada o credencial borrada); sale sin credencial", "{name}: could not read its credential label (vault closed or credential deleted); it is exported without a credential"),
		"hosts.warn.no_sum":        e("archivo sin suma de verificación: nada comprueba que no esté dañado o modificado; revisa su contenido", "file without a checksum: nothing verifies that it is not damaged or modified; review its contents"),
		"hosts.warn.import_closed": e("la bóveda está cerrada: {n} host(s) con credencial quedarían sin ella; ábrela y vuelve a abrir el archivo", "the vault is closed: {n} host(s) with a credential would be left without it; open it and open the file again"),
		"hosts.warn.import_label":  e("{n} host(s) traen una etiqueta de credencial que no está en la bóveda (o está repetida) y quedarían sin credencial", "{n} host(s) carry a credential label that is not in the vault (or is repeated) and would be left without a credential"),

		// Lista de equipos conocidos
		"devices.err.read":              e("devices: {cause}", "devices: {cause}"),
		"devices.err.not_regular":       e("no es un archivo regular o pasa de {mib} MiB", "not a regular file or larger than {mib} MiB"),
		"devices.warn.read":             e("{where}: {cause}", "{where}: {cause}"),
		"devices.warn.manifest":         e("{name}/manifest.json ilegible: {cause}", "{name}/manifest.json unreadable: {cause}"),
		"devices.warn.too_many_dirs":    e("más de {max} carpetas en outputs/: el resto no se leyó", "more than {max} folders in outputs/: the rest was not read"),
		"devices.warn.too_many_zips":    e("{name}: más de {max} zips, el resto no se leyó", "{name}: more than {max} zips, the rest was not read"),
		"devices.warn.too_many_entries": e("{where}: más de {max} entradas, el resto no se leyó", "{where}: more than {max} entries, the rest was not read"),
		"devices.warn.too_many":         e("más de {max} equipos: la lista está incompleta", "more than {max} devices: the list is incomplete"),
	})
}

// Carpeta y archivo de salida de adhoc, diag y field, y errores sueltos de field.
func init() {
	e := func(es, en string) entry { return entry{Es: es, En: en, Args: tplArgs(es, en)} }
	add(map[string]entry{
		"out.err.dir":  e("carpeta de salida: {cause}", "output folder: {cause}"),
		"out.err.file": e("archivo de salida: {cause}", "output file: {cause}"),
	})
}

// Paquetes: errores de la instalación que envuelven un error del sistema.
func init() {
	e := func(es, en string) entry { return entry{Es: es, En: en, Args: tplArgs(es, en)} }
	add(map[string]entry{
		"pack.err.hidden_save": e("no se instaló nada: no se pudo guardar lo oculto: {cause}", "nothing was installed: the hidden items could not be saved: {cause}"),
		"pack.err.hidden_read": e("el paquete quedó instalado, pero no se pudo leer lo oculto: {cause}", "the package was installed, but the hidden items could not be read: {cause}"),
	})
}

// Núcleo: trabajos de Patrol.
func init() {
	add(map[string]entry{
		"patrol.err.job_missing": {Es: "trabajo {id} no existe", En: "job {id} does not exist", Args: []string{"id"}},
	})
}

// Puente de la app (ui/bridge): validaciones propias que llegan a la UI.
func init() {
	e := func(es, en string) entry { return entry{Es: es, En: en, Args: tplArgs(es, en)} }
	add(map[string]entry{
		"bridge.err.disconnected":   e("núcleo desconectado", "core disconnected"),
		"bridge.err.round":          e("ronda {round} inválida", "invalid round {round}"),
		"bridge.err.rounds":         e("rondas {from} y {to} inválidas", "invalid rounds {from} and {to}"),
		"bridge.err.instant":        e("instante {value:q} inválido: usa RFC 3339 (2026-11-04T10:09:18Z)", "invalid instant {value:q}: use RFC 3339 (2026-11-04T10:09:18Z)"),
		"bridge.err.phase":          e("fase {phase:q} desconocida", "unknown phase {phase:q}"),
		"bridge.err.request":        e("solicitud inválida: {cause}", "invalid request: {cause}"),
		"bridge.err.calc":           e("calculadora {kind:q} desconocida", "unknown calculator {kind:q}"),
		"bridge.err.burst":          e("ráfaga inválida: {burst} en {window} s", "invalid burst: {burst} in {window} s"),
		"bridge.err.threshold_full": e("umbral inválido: {count} en {window} s, delta {delta}", "invalid threshold: {count} in {window} s, delta {delta}"),
		"bridge.err.threshold":      e("umbral inválido", "invalid threshold"),
		"bridge.err.save_abs":       e("guardar: la ruta debe ser absoluta", "save: the path must be absolute"),
		"bridge.err.save_base64":    e("guardar: base64 inválido: {cause}", "save: invalid base64: {cause}"),
		"bridge.err.save_encoding":  e("guardar: codificación {encoding:q} desconocida", "save: unknown encoding {encoding:q}"),
		"bridge.err.save_big":       e("guardar: el archivo pasa de 64 MiB", "save: the file exceeds 64 MiB"),
		"bridge.err.tool":           e("herramienta {tool:q} desconocida", "unknown tool {tool:q}"),
		"bridge.err.run_gone":       e("ejecución {id:q} no existe o ya terminó", "run {id:q} does not exist or has already finished"),
		"bridge.err.dns_mode":       e("modo DNS {mode:q} desconocido", "unknown DNS mode {mode:q}"),
		"bridge.err.port":           e("puerto {port} inválido", "invalid port {port}"),
		"bridge.err.range":          e("{name} fuera de rango: {value}", "{name} out of range: {value}"),
		"bridge.err.console_gone":   e("consola {id:q} no existe o ya terminó", "console {id:q} does not exist or has already finished"),
		"bridge.err.terminal_gone":  e("terminal {id:q} no existe o ya terminó", "terminal {id:q} does not exist or has already finished"),
		"bridge.err.out_abs":        e("la ruta de salida debe ser absoluta", "the output path must be absolute"),
		"bridge.err.top":            e("top fuera de rango: {value}", "top out of range: {value}"),
		"bridge.err.only_empty":     e("solo se borra un archivo regular vacío", "only an empty regular file is deleted"),
	})
}

// Descripción y tipo de los campos del archivo de import de hosts (HostsImportFormat); el inglés es el de la app.
func init() {
	e := func(es, en string) entry { return entry{Es: es, En: en} }
	add(map[string]entry{
		"hostfield.type.texto":            e("texto", "text"),
		"hostfield.type.entero":           e("entero", "integer"),
		"hostfield.type.lista":            e("lista", "list"),
		"hostfield.desc.name":             e("Nombre del host: 1 a 64 caracteres, sin espacios en los extremos. No se repite (sin importar mayúsculas).", "Host name: 1 to 64 characters, no leading or trailing spaces. Not repeated (case-insensitive)."),
		"hostfield.desc.address":          e("IP o nombre DNS, sin usuario, esquema, puerto ni ruta. La dirección con el puerto no se repite.", "IP or DNS name, without user, scheme, port or path. The address with the port is not repeated."),
		"hostfield.desc.port":             e("Puerto SSH, de 1 a 65535. Vacío = 22.", "SSH port, from 1 to 65535. Empty = 22."),
		"hostfield.desc.platform":         e("Plataforma: ios, ios-xe, nx-os, asa, iosxr, wlc. Vacío = sin definir.", "Platform: ios, ios-xe, nx-os, asa, iosxr, wlc. Empty = not set."),
		"hostfield.desc.folder":           e("Carpeta de un solo nivel: 1 a 48 caracteres entre letras, números, espacio, _, . y -. Vacío = sin carpeta.", "Single-level folder: 1 to 48 characters among letters, digits, space, _, . and -. Empty = no folder."),
		"hostfield.desc.tags":             e("Hasta 10 etiquetas de 1 a 24 caracteres entre a-z, 0-9 y -. En CSV separadas por «;»; en JSON, un arreglo.", "Up to 10 tags of 1 to 24 characters among a-z, 0-9 and -. In CSV separated by \";\"; in JSON, an array."),
		"hostfield.desc.credential_label": e("Etiqueta de una credencial de la bóveda local (nunca el usuario ni la contraseña). Si al importar no existe una con esa etiqueta, el host queda sin credencial.", "Label of a credential in the local vault (never the user or the password). If none with that label exists on import, the host is left without a credential."),
		"hostfield.desc.notes":            e("Notas libres, hasta 2000 caracteres.", "Free notes, up to 2000 characters."),
	})
}
