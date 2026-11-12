package i18n

// Seguridad: pruebas RADIUS y TACACS+ (textos del informe, errores por paso y hallazgos) y certificados
// (etiquetas del informe y avisos). Los valores (servidor, atributos, números de serie, huellas) no pasan por aquí.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		// severidades y estados cerrados (en el informe de texto)
		"security.severity.warning": e("aviso", "warning"),
		"security.severity.error":   e("error", "error"),
		"security.severity.info":    e("info", "info"),
		"security.ma.absent":        e("ausente", "absent"),
		"security.ma.valid":         e("válido", "valid"),
		"security.ma.invalid":       e("inválido", "invalid"),
		"security.findings_head":    e("Hallazgos:", "Findings:"),
		"security.yes":              e("sí", "yes"),
		"security.no":               e("no", "no"),

		// RADIUS: texto del informe
		"security.radius.text.server":      e("Servidor RADIUS {server}", "RADIUS server {server}", "server"),
		"security.radius.text.method":      e(" (método {method})", " (method {method})", "method"),
		"security.radius.text.no_response": e("sin respuesta", "no response"),
		"security.radius.text.exchange":    e("{code} en {rtt} ms (intento {attempt}, Message-Authenticator {ma})", "{code} in {rtt} ms (attempt {attempt}, Message-Authenticator {ma})", "code", "rtt", "attempt", "ma"),

		// RADIUS: error de un intercambio
		"security.radius.err.system":      e("{error}", "{error}", "error"),
		"security.radius.err.unauth":      e("llegó una respuesta ({code}) cuyo autenticador no verifica: el secreto compartido no coincide con el del servidor (o la respuesta es falsificada); se descarta", "a response ({code}) arrived whose authenticator does not verify: the shared secret does not match the server's (or the response is forged); it is discarded", "code"),
		"security.radius.err.no_response": e("sin respuesta tras {attempts} intentos de {timeout}", "no response after {attempts} attempts of {timeout}", "attempts", "timeout"),

		// RADIUS: hallazgos
		"security.radius.finding.no_response":      e("{kind}: el servidor no respondió. Causas usuales: este equipo no está dado de alta como NAS/dispositivo de red en el servidor, secreto compartido distinto (la petición se descarta por Message-Authenticator), UDP {port} filtrado o puerto equivocado (1645/1646 heredados).", "{kind}: the server did not answer. Usual causes: this device is not registered as a NAS/network device on the server, a different shared secret (the request is dropped because of Message-Authenticator), UDP {port} filtered or a wrong port (legacy 1645/1646).", "kind", "port"),
		"security.radius.finding.invalid_response": e("{kind}: {error}", "{kind}: {error}", "kind", "error"),
		"security.radius.finding.blast_radius":     e("{kind}: la respuesta no trae Message-Authenticator; el servidor es vulnerable a Blast-RADIUS (CVE-2024-3596). Actualízalo y exige Message-Authenticator.", "{kind}: the response has no Message-Authenticator; the server is vulnerable to Blast-RADIUS (CVE-2024-3596). Update it and require Message-Authenticator.", "kind"),
		"security.radius.finding.ma_invalid":       e("{kind}: Message-Authenticator inválido en la respuesta (secreto distinto o paquete alterado).", "{kind}: invalid Message-Authenticator in the response (different secret or tampered packet).", "kind"),
		"security.radius.finding.reject":           e("El servidor rechazó la autenticación. Revisa en el servidor (ISE: Operations > RADIUS > Live Logs) el motivo exacto; Reply-Message: {reply}", "The server rejected the authentication. Check the exact reason on the server (ISE: Operations > RADIUS > Live Logs); Reply-Message: {reply}", "reply"),
		"security.radius.finding.reject_none":      e("El servidor rechazó la autenticación. Revisa en el servidor (ISE: Operations > RADIUS > Live Logs) el motivo exacto; Reply-Message: (ninguno)", "The server rejected the authentication. Check the exact reason on the server (ISE: Operations > RADIUS > Live Logs); Reply-Message: (none)"),

		// TACACS+: texto del informe
		"security.tacacs.text.server":      e("Servidor TACACS+ {server}", "TACACS+ server {server}", "server"),
		"security.tacacs.text.no_response": e("sin respuesta", "no response"),
		"security.tacacs.text.status":      e("{status} en {rtt} ms", "{status} in {rtt} ms", "status", "rtt"),
		"security.tacacs.text.prompt":      e("servidor pidió: {prompt:q}", "server asked: {prompt:q}", "prompt"),
		"security.tacacs.text.message":     e("mensaje: {message}", "message: {message}", "message"),
		"security.tacacs.text.data":        e("datos: {data}", "data: {data}", "data"),
		"security.tacacs.text.sent":        e("enviado  {pair}", "sent     {pair}", "pair"),
		"security.tacacs.text.received":    e("recibido {pair}", "received {pair}", "pair"),

		// TACACS+: errores por paso
		"security.tacacs.err.system":           e("{error}", "{error}", "error"),
		"security.tacacs.err.closed":           e("el servidor cerró la conexión sin responder: este equipo no está dado de alta como cliente/dispositivo de red o el secreto compartido no coincide", "the server closed the connection without answering: this device is not registered as a client/network device or the shared secret does not match"),
		"security.tacacs.err.out_of_sequence":  e("respuesta fuera de secuencia (sesión {session} tipo {type} seq {seq})", "out-of-sequence response (session {session} type {type} seq {seq})", "session", "type", "seq"),
		"security.tacacs.err.unencrypted":      e("el servidor respondió sin cifrar (TAC_PLUS_UNENCRYPTED_FLAG): no tiene secreto configurado para este equipo", "the server answered unencrypted (TAC_PLUS_UNENCRYPTED_FLAG): it has no secret configured for this device"),
		"security.tacacs.err.bad_secret":       e("no se pudo interpretar la respuesta descifrada: casi siempre es un secreto compartido distinto", "the decrypted response could not be interpreted: almost always a different shared secret"),
		"security.tacacs.err.too_many_prompts": e("demasiadas preguntas del servidor", "too many questions from the server"),

		// TACACS+: hallazgos
		"security.tacacs.finding.secret":      e("{kind}: la respuesta no se descifra. Revisa que el secreto del equipo en el servidor (ISE: Network Devices > TACACS Authentication Settings) sea el mismo.", "{kind}: the response cannot be decrypted. Check that the device secret on the server (ISE: Network Devices > TACACS Authentication Settings) is the same.", "kind"),
		"security.tacacs.finding.no_response": e("{kind}: {error}. Revisa conectividad a TCP {port} y que el equipo esté dado de alta.", "{kind}: {error}. Check connectivity to TCP {port} and that the device is registered.", "kind", "error", "port"),
		"security.tacacs.finding.authen_fail": e("Autenticación rechazada: usuario o contraseña incorrectos, cuenta deshabilitada o la política (Device Admin) no permite este equipo.", "Authentication rejected: wrong username or password, disabled account or the policy (Device Admin) does not allow this device."),
		"security.tacacs.finding.author_fail": e("El comando no está autorizado: revisa el Command Set / perfil de shell de la política de Device Admin.", "The command is not authorized: check the Command Set / shell profile of the Device Admin policy."),
		"security.tacacs.finding.state":       e("{kind}: estado {status} {message}", "{kind}: status {status} {message}", "kind", "status", "message"),

		// Certificados: texto del informe
		"security.pki.kind.certificate":    e("certificado", "certificate"),
		"security.pki.kind.csr":            e("CSR", "CSR"),
		"security.pki.label.issuer":        e("Emisor", "Issuer"),
		"security.pki.label.serial":        e("Serie", "Serial"),
		"security.pki.label.validity":      e("Validez", "Validity"),
		"security.pki.label.key":           e("Llave", "Key"),
		"security.pki.label.signature":     e("Firma", "Signature"),
		"security.pki.label.san":           e("SAN", "SAN"),
		"security.pki.label.key_usage":     e("Uso de llave", "Key usage"),
		"security.pki.label.ext_key_usage": e("Uso extendido", "Extended key usage"),
		"security.pki.label.ca":            e("CA", "CA"),
		"security.pki.label.sig_valid":     e("Firma válida", "Signature valid"),
		"security.pki.label.sha1":          e("SHA-1", "SHA-1"),
		"security.pki.label.sha256":        e("SHA-256", "SHA-256"),
		"security.pki.validity":            e("{from} → {to} ({days} días)", "{from} → {to} ({days} days)", "from", "to", "days"),
		"security.pki.lab_warning":         e("CA SOLO DE LABORATORIO: no la instales como raíz de confianza fuera del laboratorio ni firmes con ella equipos de producción.", "LAB-ONLY CA: do not install it as a trusted root outside the lab or sign production devices with it."),

		// Certificados: avisos
		"security.pki.warn.rsa_small":     e("llave RSA de menos de 2048 bits: ISE y navegadores la rechazan", "RSA key shorter than 2048 bits: ISE and browsers reject it"),
		"security.pki.warn.weak_sig":      e("firma con {algorithm}: algoritmo obsoleto", "signature with {algorithm}: obsolete algorithm", "algorithm"),
		"security.pki.warn.no_san":        e("sin SAN: los clientes modernos ignoran el CN; agrega el nombre DNS/IP como SAN", "no SAN: modern clients ignore the CN; add the DNS/IP name as a SAN"),
		"security.pki.warn.expired":       e("vencido", "expired"),
		"security.pki.warn.not_yet":       e("todavía no es válido (revisa el reloj/NTP)", "not valid yet (check the clock/NTP)"),
		"security.pki.warn.expires_soon":  e("vence en {days} días", "expires in {days} days", "days"),
		"security.pki.warn.self_signed":   e("autofirmado", "self-signed"),
		"security.pki.warn.csr_signature": e("la firma del CSR no verifica", "the CSR signature does not verify"),
	})
}
