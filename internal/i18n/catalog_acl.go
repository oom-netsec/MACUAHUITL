package i18n

// ACL: errores de importación, validación y generación, y el detalle de los hallazgos. Los valores (nombres,
// direcciones, puertos, operadores, protocolos) viajan como argumentos y no se traducen; las líneas de config
// de IOS, NX-OS y ASA tampoco.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"acl.finding.covered": e("la regla {n} ({action}) ya cubre todo lo que esta coincide", "rule {n} ({action}) already covers everything this one matches", "n", "action"),

		"acl.err.line":           e("línea {line}: {cause}", "line {line}: {cause}", "line", "cause"),
		"acl.err.import":         e("acl: {cause}", "acl: {cause}", "cause"),
		"acl.err.vendor":         e("acl: fabricante {vendor:q} no soportado ({list})", "acl: vendor {vendor:q} not supported ({list})", "vendor", "list"),
		"acl.err.other_acl":      e("el texto trae otra ACL ({name}); importa una a la vez", "the text has another ACL ({name}); import one at a time", "name"),
		"acl.err.std_acl":        e("ACL estándar no soportada; usa una extendida", "standard ACL not supported; use an extended one"),
		"acl.err.fragments":      e("'fragments' cambia el trato de fragmentos y no se puede traducir; quítalo o tradúcelo a mano", "'fragments' changes how fragments are handled and cannot be translated; remove it or translate it by hand"),
		"acl.err.asa_form":       e("se esperaba 'access-list NOMBRE extended …' o 'remark …'", "expected 'access-list NAME extended …' or 'remark …'"),
		"acl.err.no_header":      e("falta el encabezado de la ACL", "the ACL header is missing"),
		"acl.err.none":           e("no se encontró ninguna ACL", "no ACL was found"),
		"acl.err.incomplete":     e("regla incompleta", "incomplete rule"),
		"acl.err.expect_action":  e("se esperaba permit o deny, no {got:q}", "expected permit or deny, not {got:q}", "got"),
		"acl.err.bad_proto":      e("protocolo {proto:q} desconocido", "unknown protocol {proto:q}", "proto"),
		"acl.err.src":            e("origen: {cause}", "source: {cause}", "cause"),
		"acl.err.dst":            e("destino: {cause}", "destination: {cause}", "cause"),
		"acl.err.unknown_flag":   e("no se entiende {flag:q} (tipos ICMP, time-range y objetos no están soportados todavía)", "{flag:q} is not understood (ICMP types, time-range and objects are not supported yet)", "flag"),
		"acl.err.no_address":     e("falta la dirección", "the address is missing"),
		"acl.err.no_args":        e("{op} sin argumentos", "{op} without arguments", "op"),
		"acl.err.neq_multi":      e("neq con varios puertos no tiene una traducción segura; escribe una regla por puerto", "neq with several ports has no safe translation; write one rule per port"),
		"acl.err.bad_ipv4":       e("dirección IPv4 {addr:q} inválida", "invalid IPv4 address {addr:q}", "addr"),
		"acl.err.wild_noncontig": e("wildcard {wild} no es contigua; no se puede expresar como CIDR", "wildcard {wild} is not contiguous; it cannot be expressed as CIDR", "wild"),
		"acl.err.mask_noncontig": e("máscara {mask} no es contigua", "mask {mask} is not contiguous", "mask"),
		"acl.err.host_no_addr":   e("host sin dirección", "host without an address"),
		"acl.err.no_wildcard":    e("falta la wildcard", "the wildcard is missing"),
		"acl.err.wildcard":       e("wildcard: {cause}", "wildcard: {cause}", "cause"),
		"acl.err.bad_prefix":     e("prefijo {prefix:q} inválido", "invalid prefix {prefix:q}", "prefix"),
		"acl.err.no_mask":        e("falta la máscara", "the mask is missing"),
		"acl.err.mask":           e("máscara: {cause}", "mask: {cause}", "cause"),

		"acl.err.bad_port":    e("puerto {port:q} inválido", "invalid port {port:q}", "port"),
		"acl.err.need_args":   e("{op} necesita {n} argumento(s)", "{op} needs {n} {n|argument|arguments}", "op", "n"),
		"acl.err.gt_max":      e("gt 65535 no coincide con ningún puerto", "gt 65535 does not match any port"),
		"acl.err.lt_min":      e("lt 0 no coincide con ningún puerto", "lt 0 does not match any port"),
		"acl.err.range_empty": e("range {a} {b} está vacío", "range {a} {b} is empty", "a", "b"),
		"acl.err.bad_op":      e("operador de puerto {op:q} desconocido", "unknown port operator {op:q}", "op"),

		"acl.err.src_dst_required": e("origen y destino son obligatorios", "source and destination are required"),
		"acl.err.ipv4_only":        e("{prefix}: solo IPv4 en esta versión", "{prefix}: IPv4 only in this version", "prefix"),
		"acl.err.host_bits":        e("{prefix} tiene bits de host; usa {masked}", "{prefix} has host bits; use {masked}", "prefix", "masked"),
		"acl.err.remark_newline":   e("el remark no puede tener saltos de línea", "the remark cannot contain line breaks"),
		"acl.err.ports_proto":      e("los puertos solo aplican a tcp/udp, no a {proto}", "ports only apply to tcp/udp, not to {proto}", "proto"),
		"acl.err.established":      e("established solo aplica a tcp", "established only applies to tcp"),
		"acl.err.port_range_empty": e("rango de puertos {lo}-{hi} vacío", "port range {lo}-{hi} is empty", "lo", "hi"),

		"acl.err.bad_name":        e("acl: nombre {name:q} inválido", "acl: invalid name {name:q}", "name"),
		"acl.err.rule":            e("acl: regla {n}: {cause}", "acl: rule {n}: {cause}", "n", "cause"),
		"acl.err.asa_established": e("acl: regla {n}: ASA no tiene 'established'; usa inspección de estado", "acl: rule {n}: ASA has no 'established'; use stateful inspection", "n"),

		"acl.err.rule_src":         e("regla {n}: origen {src:q}: {cause}", "rule {n}: source {src:q}: {cause}", "n", "src", "cause"),
		"acl.err.rule_dst":         e("regla {n}: destino {dst:q}: {cause}", "rule {n}: destination {dst:q}: {cause}", "n", "dst", "cause"),
		"acl.err.rule_cause":       e("regla {n}: {cause}", "rule {n}: {cause}", "n", "cause"),
		"acl.err.ports_incomplete": e("puertos {ports:q} incompletos", "incomplete ports {ports:q}", "ports"),
	})
}
