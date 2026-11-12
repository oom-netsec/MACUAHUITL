package i18n

// Inspección TLS (internal/diag/tlsinspect): detalle de los hallazgos (tls.finding.*). Las fechas, nombres, SAN y
// algoritmos que cita el texto son datos y no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"tls.finding.legacy_version":   e("{version} sigue habilitado; deshabilítalo", "{version} is still enabled; disable it", "version"),
		"tls.finding.expired":          e("el certificado venció el {date}", "the certificate expired on {date}", "date"),
		"tls.finding.not_yet_valid":    e("el certificado es válido desde {date}", "the certificate is valid from {date}", "date"),
		"tls.finding.expires_soon":     e("el certificado vence en {days} días", "the certificate expires in {days} days", "days"),
		"tls.finding.name_mismatch":    e("el certificado no cubre {name:q} (SAN: {san})", "the certificate does not cover {name:q} (SAN: {san})", "name", "san"),
		"tls.finding.self_signed":      e("el certificado es autofirmado; los clientes no lo validarán sin fijarlo", "the certificate is self-signed; clients will not validate it unless it is pinned"),
		"tls.finding.incomplete_chain": e("no se pudo construir la cadena hasta una raíz de confianza (¿falta el intermedio?)", "the chain could not be built up to a trusted root (is the intermediate missing?)"),
		"tls.finding.weak_key":         e("certificado {index} con RSA de {bits} bits", "certificate {index} with {bits}-bit RSA", "index", "bits"),
		"tls.finding.weak_signature":   e("certificado {index} firmado con {algorithm}", "certificate {index} signed with {algorithm}", "index", "algorithm"),
	})
}
