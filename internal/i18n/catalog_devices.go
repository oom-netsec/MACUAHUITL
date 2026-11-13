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
