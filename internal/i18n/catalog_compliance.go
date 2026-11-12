package i18n

// Cumplimiento: reglas de endurecimiento (título y detalle), evaluación de la plantilla dorada, errores de la
// plantilla y texto del informe. Las líneas de configuración, comandos y referencias a la guía de Cisco
// viajan tal cual y no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"compliance.note": e("Reglas basadas en la guía pública de Cisco para endurecer IOS/IOS-XE; sin validar en laboratorio. Con salidas enmascaradas por Patrol no se distinguen comunidades ni contraseñas por defecto.",
			"Rules based on the public Cisco guide to harden IOS/IOS-XE; not validated in the lab. With outputs masked by Patrol, default communities and passwords cannot be told apart."),

		"compliance.err.empty":              e("compliance: la configuración está vacía", "compliance: the configuration is empty"),
		"compliance.err.no_rules":           e("compliance: la plantilla no tiene reglas", "compliance: the template has no rules"),
		"compliance.err.forbidden_children": e("compliance: plantilla línea {n}: una línea prohibida no puede tener hijos", "compliance: template line {n}: a forbidden line cannot have children", "n"),
		"compliance.err.optional_empty":     e("compliance: plantilla línea {n}: una sección opcional necesita reglas", "compliance: template line {n}: an optional section needs rules", "n"),
		"compliance.err.regex":              e("compliance: plantilla línea {n}: {error}", "compliance: template line {n}: {error}", "n", "error"),

		"compliance.title.aaa-new-model":  e("AAA habilitado (aaa new-model)", "AAA enabled (aaa new-model)"),
		"compliance.title.ssh-v2":         e("Solo SSH versión 2", "SSH version 2 only"),
		"compliance.title.vty-transport":  e("VTY solo por SSH (sin telnet)", "VTY over SSH only (no telnet)"),
		"compliance.title.http-server":    e("Sin HTTP en claro; HTTPS solo con autenticación", "No cleartext HTTP; HTTPS only with authentication"),
		"compliance.title.ntp-auth":       e("NTP autenticado", "Authenticated NTP"),
		"compliance.title.logging-host":   e("Logging a un servidor remoto", "Logging to a remote server"),
		"compliance.title.secret-types":   e("Secretos tipo 8/9 en vez de contraseñas reversibles", "Type 8/9 secrets instead of reversible passwords"),
		"compliance.title.banner":         e("Banner de acceso legal", "Legal access banner"),
		"compliance.title.exec-timeout":   e("exec-timeout en consola y VTY", "exec-timeout on console and VTY"),
		"compliance.title.copp":           e("Control Plane Policing presente", "Control Plane Policing present"),
		"compliance.title.snmp-community": e("SNMP sin comunidades por defecto ni v1/v2c sin ACL", "SNMP without default communities or v1/v2c without an ACL"),

		"compliance.detail.no_aaa":            e("sin aaa new-model: la autenticación depende de contraseñas de línea", "no aaa new-model: authentication depends on line passwords"),
		"compliance.detail.no_ssh2":           e("falta ip ssh version 2; decláralo para no aceptar SSHv1", "ip ssh version 2 is missing; declare it so SSHv1 is not accepted"),
		"compliance.detail.no_logging":        e("sin logging host: los eventos solo quedan en el equipo", "no logging host: events stay only on the device"),
		"compliance.detail.no_pwenc":          e("sin service password-encryption: las contraseñas tipo 0 se ven en claro", "no service password-encryption: type 0 passwords are visible in cleartext"),
		"compliance.detail.no_banner":         e("sin banner login ni motd", "no login or motd banner"),
		"compliance.detail.no_srcroute":       e("falta no ip source-route; el enrutamiento por origen viene habilitado por defecto", "no ip source-route is missing; source routing is enabled by default"),
		"compliance.detail.no_keepalives":     e("sin service tcp-keepalives-in: sesiones VTY huérfanas quedan abiertas", "no service tcp-keepalives-in: orphaned VTY sessions stay open"),
		"compliance.detail.no_vty":            e("no hay líneas VTY en la configuración", "there are no VTY lines in the configuration"),
		"compliance.detail.vty_no_transport":  e("{line}: sin transport input (el valor por defecto depende de la versión; decláralo)", "{line}: no transport input (the default depends on the version; declare it)", "line"),
		"compliance.detail.vty_transport":     e("{line}: {transport}", "{line}: {transport}", "line", "transport"),
		"compliance.detail.http_server":       e("ip http server habilitado: la gestión web viaja en claro", "ip http server enabled: web management travels in cleartext"),
		"compliance.detail.http_secure":       e("ip http secure-server sin ip http authentication local|aaa", "ip http secure-server without ip http authentication local|aaa"),
		"compliance.detail.no_ntp":            e("sin ntp server: los registros no tendrán hora confiable", "no ntp server: logs will not have a reliable time"),
		"compliance.detail.ntp_missing":       e("falta: {items}", "missing: {items}", "items"),
		"compliance.detail.ntp_nokey":         e("servidores sin key ({lines})", "servers without a key ({lines})", "lines"),
		"compliance.detail.secret_reversible": e("contraseñas reversibles (usa secret tipo 8 o 9): {lines}", "reversible passwords (use a type 8 or 9 secret): {lines}", "lines"),
		"compliance.detail.secret_also":       e("además: {lines}", "also: {lines}", "lines"),
		"compliance.detail.secret_weak":       e("secretos tipo 4 (SHA-256 sin sal) o 5 (MD5) o contraseñas de línea: {lines}", "type 4 (unsalted SHA-256) or 5 (MD5) secrets or line passwords: {lines}", "lines"),
		"compliance.detail.exec_none":         e("{line}: sin exec-timeout (10 min por defecto)", "{line}: no exec-timeout (10 min by default)", "line"),
		"compliance.detail.exec_zero":         e("{line}: {timeout} (sin límite)", "{line}: {timeout} (no limit)", "line", "timeout"),
		"compliance.detail.no_copp":           e("sin service-policy input bajo control-plane (en Catalyst 9000 es system-cpp-policy)", "no service-policy input under control-plane (on Catalyst 9000 it is system-cpp-policy)"),
		"compliance.detail.snmp_default":      e("línea {n}: comunidad por defecto {name:q}", "line {n}: default community {name:q}", "n", "name"),
		"compliance.detail.snmp_noacl":        e("línea {n}: comunidad v1/v2c sin ACL", "line {n}: v1/v2c community without an ACL", "n"),
		"compliance.detail.snmp_acl":          e("línea {n}: v1/v2c con ACL {acl}; la comunidad viaja en claro, prefiere SNMPv3 priv", "line {n}: v1/v2c with ACL {acl}; the community travels in cleartext, prefer SNMPv3 priv", "n", "acl"),
		"compliance.line":                     e("línea {n}: {text}", "line {n}: {text}", "n", "text"),

		"compliance.detail.tpl_optional":   e("la sección opcional no existe; no aplica", "the optional section does not exist; it does not apply"),
		"compliance.detail.tpl_no_section": e("la sección {name:q} no existe", "the section {name:q} does not exist", "name"),
		"compliance.detail.tpl_lacking":    e("falta en {scopes}", "missing in {scopes}", "scopes"),
		"compliance.detail.tpl_present":    e("presente en {lines}", "present in {lines}", "lines"),
		"compliance.scope.global":          e("la configuración global", "the global configuration"),
		"compliance.scope.section":         e("{path:q} (línea {n})", "{path:q} (line {n})", "path", "n"),

		"compliance.status.pass":    e("OK", "OK"),
		"compliance.status.fail":    e("FALLA", "FAIL"),
		"compliance.status.warn":    e("REVISAR", "REVIEW"),
		"compliance.text.template":  e("Plantilla", "Template"),
		"compliance.text.hardening": e("Endurecimiento", "Hardening"),
		"compliance.text.summary":   e("{pass} OK, {fail} fallas, {warn} por revisar", "{pass} OK, {fail} {fail|failure|failures}, {warn} to review", "pass", "fail", "warn"),
	})
}

func init() {
	// marca interna del recorrido de la plantilla: no se muestra
	add(map[string]entry{"compliance.optional_absent": {Es: "-", En: "-"}})
}
