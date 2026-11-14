package i18n

// Errores de validación de pki, msgkb, del EgressGuard y del driver iosxe. Los textos del sistema y de x509
// (la causa) entran como {cause} y no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		// pki
		"pki.err.algorithm":    e("pki: algoritmo {alg:q} no soportado ({algs})", "pki: algorithm {alg:q} not supported ({algs})", "alg", "algs"),
		"pki.err.not_sealed":   e("pki: no es una llave sellada por MACUAHUITL ({type})", "pki: not a key sealed by MACUAHUITL ({type})", "type"),
		"pki.err.open_key":     e("pki: abrir la llave: {cause}", "pki: opening the key: {cause}", "cause"),
		"pki.err.key_type":     e("pki: tipo de llave no soportado", "pki: key type not supported"),
		"pki.err.no_cn":        e("pki: falta el CN", "pki: the CN is missing"),
		"pki.err.country":      e("pki: el país (C) es de 2 letras ISO 3166", "pki: the country (C) is 2 ISO 3166 letters"),
		"pki.err.bad_ip":       e("pki: IP {ip:q} inválida", "pki: invalid IP {ip:q}", "ip"),
		"pki.err.validity":     e("pki: validez de {days} días fuera de 1–{max}", "pki: validity of {days} days is outside 1–{max}", "days", "max"),
		"pki.err.no_ca_name":   e("pki: falta el nombre de la CA", "pki: the CA name is missing"),
		"pki.err.want_cert":    e("pki: se esperaba un certificado PEM", "pki: a PEM certificate was expected"),
		"pki.err.not_ca":       e("pki: el certificado indicado no es de una CA", "pki: the given certificate is not a CA's"),
		"pki.err.profile":      e("pki: perfil {profile:q} desconocido (server, client, server-client)", "pki: unknown profile {profile:q} (server, client, server-client)", "profile"),
		"pki.err.want_csr":     e("pki: se esperaba un CSR PEM", "pki: a PEM CSR was expected"),
		"pki.err.csr":          e("pki: CSR: {cause}", "pki: CSR: {cause}", "cause"),
		"pki.err.csr_sig":      e("pki: la firma del CSR no verifica: {cause}", "pki: the CSR signature does not verify: {cause}", "cause"),
		"pki.err.chain":        e("pki: cadena: {cause}", "pki: chain: {cause}", "cause"),
		"pki.err.key_mismatch": e("pki: la llave no corresponde al certificado", "pki: the key does not match the certificate"),
		"pki.err.p12_needs":    e("pki: PKCS#12 necesita la llave y una contraseña de exportación", "pki: PKCS#12 needs the key and an export password"),
		"pki.err.format":       e("pki: formato {format:q} desconocido (pem, der, p12, p12-legacy)", "pki: unknown format {format:q} (pem, der, p12, p12-legacy)", "format"),
		"pki.err.cert":         e("pki: certificado: {cause}", "pki: certificate: {cause}", "cause"),
		"pki.err.pem_block":    e("pki: bloque PEM {type:q} no soportado (solo certificados y CSR; no pegues llaves privadas)", "pki: PEM block {type:q} not supported (only certificates and CSRs; do not paste private keys)", "type"),
		"pki.err.unrecognized": e("pki: no se reconoce un certificado ni un CSR (PEM o DER)", "pki: neither a certificate nor a CSR is recognized (PEM or DER)"),

		// transport (EgressGuard)
		"transport.err.empty_addr": e("transport: dirección vacía", "transport: empty address"),
		"transport.err.resolve":    e("transport: resolver {host:q}: {cause}", "transport: resolving {host:q}: {cause}", "host", "cause"),
		"transport.err.host_bits":  e("transport: {addr} tiene bits de host; ¿quisiste decir {masked}?", "transport: {addr} has host bits; did you mean {masked}?", "addr", "masked"),
		"transport.err.network":    e("transport: red {network:q} no soportada", "transport: network {network:q} not supported", "network"),

		// platform / iosxe
		"platform.err.config_line": e("platform: línea de configuración no permitida", "platform: configuration line not allowed"),
		"iosxe.err.newline":        e("platform: el comando {cmd:q} tiene saltos de línea", "platform: the command {cmd:q} contains line breaks", "cmd"),
		"iosxe.err.cfg_chars":      e("{cause}: {line:q} tiene caracteres fuera de ASCII imprimible o '?'", "{cause}: {line:q} has characters outside printable ASCII or '?'", "line", "cause"),
		"iosxe.err.cfg_empty":      e("{cause}: línea vacía", "{cause}: empty line", "cause"),
		"iosxe.err.cfg_mode":       e("{cause}: {line:q} cambia de modo o ejecuta fuera de la configuración", "{cause}: {line:q} changes mode or runs outside configuration", "line", "cause"),
		"iosxe.err.no_config_mode": e("platform: el equipo no entró a configuración: {output}", "platform: the device did not enter configuration mode: {output}", "output"),

		// msgkb (carga de la base)
		"msgkb.err.yaml":     e("msgkb: {cause}", "msgkb: {cause}", "cause"),
		"msgkb.err.bad_id":   e("msgkb: ID inválido {id:q}", "msgkb: invalid ID {id:q}", "id"),
		"msgkb.err.dup_id":   e("msgkb: ID repetido {id}", "msgkb: duplicate ID {id}", "id"),
		"msgkb.err.fields":   e("msgkb: {id}: faltan significado, causa, acción o verificación", "msgkb: {id}: meaning, cause, action or verification is missing", "id"),
		"msgkb.err.verify":   e("msgkb: {id}: {cause}", "msgkb: {id}: {cause}", "id", "cause"),
		"msgkb.err.empty_kb": e("msgkb: la base incrustada está vacía", "msgkb: the embedded base is empty"),
	})
}
