package i18n

// Errores de snmp y gnmic (parámetros). Los textos del sistema o del agente que cita el mensaje son datos.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"snmp.err.invalid":        e("snmp: parámetros inválidos", "snmp: invalid parameters"),
		"snmp.err.no_target":      e("{cause}: destino vacío", "{cause}: empty target", "cause"),
		"snmp.err.no_oids":        e("{cause}: sin OIDs", "{cause}: no OIDs", "cause"),
		"snmp.err.no_community":   e("{cause}: falta la comunidad", "{cause}: the community is missing", "cause"),
		"snmp.err.auth":           e("{cause}: autenticación {proto:q} no soportada (SHA, SHA224, SHA256, SHA384, SHA512; MD5 no)", "{cause}: authentication {proto:q} not supported (SHA, SHA224, SHA256, SHA384, SHA512; not MD5)", "cause", "proto"),
		"snmp.err.priv":           e("{cause}: privacidad {proto:q} no soportada (AES, AES192, AES256; DES no)", "{cause}: privacy {proto:q} not supported (AES, AES192, AES256; not DES)", "cause", "proto"),
		"snmp.err.v3":             e("{cause}: v3 requiere usuario y llaves de al menos 8 caracteres (authPriv)", "{cause}: v3 requires a user and keys of at least 8 characters (authPriv)", "cause"),
		"snmp.err.version":        e("{cause}: versión {version:q} no soportada (2c o 3)", "{cause}: version {version:q} not supported (2c or 3)", "cause", "version"),
		"snmp.err.agent":          e("snmp: el agente respondió {error}", "snmp: the agent answered {error}", "error"),
		"snmp.err.profile":        e("{cause}: perfil {profile:q} desconocido ({profiles})", "{cause}: unknown profile {profile:q} ({profiles})", "cause", "profile", "profiles"),
		"snmp.trap.malformed":     e("paquete malformado: {detail}", "malformed packet: {detail}", "detail"),
		"snmp.trap.empty":         e("paquete vacío", "empty packet"),
		"snmp.trap.not_trap":      e("PDU {pdu} no es trap ni inform", "PDU {pdu} is neither a trap nor an inform", "pdu"),
		"snmp.trap.v3_raw":        e("v3 sin decodificar ({bytes} bytes): {error}", "undecoded v3 ({bytes} bytes): {error}", "bytes", "error"),
		"snmp.poll.rates_skipped": e("tasas omitidas: el equipo se reinició entre muestras (sysUpTime bajó)", "rates skipped: the device restarted between samples (sysUpTime went down)"),
		"snmp.err.trap_v3":        e("snmp traps: credencial v3 incompleta (usuario, SHA*, AES*)", "snmp traps: incomplete v3 credential (user, SHA*, AES*)"),

		"gnmi.err.invalid":         e("gnmi: parámetros inválidos", "gnmi: invalid parameters"),
		"gnmi.err.no_target":       e("{cause}: destino vacío", "{cause}: empty target", "cause"),
		"gnmi.err.ca":              e("{cause}: la CA no contiene certificados PEM válidos", "{cause}: the CA holds no valid PEM certificates", "cause"),
		"gnmi.err.no_paths":        e("{cause}: sin rutas", "{cause}: no paths", "cause"),
		"gnmi.err.encoding":        e("{cause}: codificación {encoding:q} desconocida", "{cause}: unknown encoding {encoding:q}", "cause", "encoding"),
		"gnmi.err.mode":            e("{cause}: modo {mode:q} desconocido (sample u on_change)", "{cause}: unknown mode {mode:q} (sample or on_change)", "cause", "mode"),
		"gnmi.err.path_empty":      e("{cause}: ruta vacía", "{cause}: empty path", "cause"),
		"gnmi.err.path_close":      e("{cause}: falta ] en {path:q}", "{cause}: missing ] in {path:q}", "cause", "path"),
		"gnmi.err.path_key":        e("{cause}: clave inválida en {path:q}", "{cause}: invalid key in {path:q}", "cause", "path"),
		"gnmi.err.path_nokey_elem": e("{cause}: clave sin elemento en {path:q}", "{cause}: key without an element in {path:q}", "cause", "path"),
		"gnmi.err.path_open":       e("{cause}: ] sin [ en {path:q}", "{cause}: ] without [ in {path:q}", "cause", "path"),
		"gnmi.err.path_text":       e("{cause}: texto tras una clave en {path:q}", "{cause}: text after a key in {path:q}", "cause", "path"),
	})
}

// Errores de internal/diag/serialcon.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"serial.err.path":            e("serialcon: {path:q} no es un dispositivo bajo /dev", "serialcon: {path:q} is not a device under /dev", "path"),
		"serial.err.baud":            e("serialcon: velocidad {baud} no soportada", "serialcon: speed {baud} not supported", "baud"),
		"serial.err.data_bits":       e("serialcon: bits de datos {bits} inválidos (5 a 8)", "serialcon: invalid data bits {bits} (5 to 8)", "bits"),
		"serial.err.parity":          e("serialcon: paridad {parity:q} inválida (none, even, odd)", "serialcon: invalid parity {parity:q} (none, even, odd)", "parity"),
		"serial.err.stop_bits":       e("serialcon: bits de parada {bits} inválidos (1 o 2)", "serialcon: invalid stop bits {bits} (1 or 2)", "bits"),
		"serial.err.flow":            e("serialcon: control de flujo {flow:q} inválido (none, rtscts, xonxoff)", "serialcon: invalid flow control {flow:q} (none, rtscts, xonxoff)", "flow"),
		"serial.err.permission":      e("sin permiso sobre el puerto serie", "no permission on the serial port"),
		"serial.err.not_serial":      e("serialcon: {path} no es un puerto serie: {cause}", "serialcon: {path} is not a serial port: {cause}", "path", "cause"),
		"serial.err.permission_hint": e("{cause} {path}: agrega tu usuario al grupo dialout con «sudo usermod -aG dialout $USER» y cierra todas tus sesiones o reinicia para que el servicio macuahuitld tome el grupo (no hace falta ejecutar MACUAHUITL como root)", "{cause} {path}: add your user to the dialout group with `sudo usermod -aG dialout $USER` and close all your sessions or reboot so the macuahuitld service picks up the group (MACUAHUITL does not need to run as root)", "cause", "path"),
		"serial.err.busy":            e("serialcon: {path} está en uso por otro programa (minicom, screen…)", "serialcon: {path} is in use by another program (minicom, screen…)", "path"),
		"serial.err.missing":         e("serialcon: {path} no existe; ¿está conectado el cable USB-serie?", "serialcon: {path} does not exist; is the USB-serial cable connected?", "path"),
		"serial.err.configure":       e("serialcon: configurar {path}: {cause}", "serialcon: configuring {path}: {cause}", "path", "cause"),
	})
}

// Errores de internal/diag/radiustest.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"radius.err.short":       e("radius: paquete de menos de 20 bytes", "radius: packet of less than 20 bytes"),
		"radius.err.length":      e("radius: longitud {length} inválida (recibidos {got} bytes)", "radius: invalid length {length} ({got} bytes received)", "length", "got"),
		"radius.err.attr_length": e("radius: atributo con longitud inválida", "radius: attribute with an invalid length"),
		"radius.err.value":       e("valor {value:q} desconocido", "unknown value {value:q}", "value"),
		"radius.err.nas_ip":      e("NAS-IP-Address {ip:q}: debe ser IPv4", "NAS-IP-Address {ip:q}: must be IPv4", "ip"),
		"radius.err.too_long":    e("{name} de más de 253 bytes", "{name} of more than 253 bytes", "name"),
		"radius.err.attr_enum":   e("{name}: {cause}", "{name}: {cause}", "name", "cause"),
		"radius.err.host":        e("radius: servidor inválido", "radius: invalid server"),
		"radius.err.secret":      e("radius: falta el secreto compartido", "radius: the shared secret is missing"),
		"radius.err.wrap":        e("radius: {cause}", "radius: {cause}", "cause"),
		"radius.err.user":        e("radius: usuario vacío o de más de 253 bytes", "radius: empty user or of more than 253 bytes"),
		"radius.err.password":    e("radius: contraseña de más de 128 bytes", "radius: password of more than 128 bytes"),
		"radius.err.method":      e("radius: método {method:q} no soportado (pap, chap, mschapv2)", "radius: method {method:q} not supported (pap, chap, mschapv2)", "method"),
		"radius.val.truncated":   e("0x{hex} (truncado)", "0x{hex} (truncated)", "hex"),
		"radius.val.mschap_ok":   e("respuesta del servidor verificada (autenticación mutua)", "server response verified (mutual authentication)"),
		"radius.val.mschap_bad":  e("NO verifica: el servidor no conoce la contraseña o hay un intermediario", "does NOT verify: the server does not know the password or there is a man in the middle"),
	})
}

// Errores de internal/diag/tacacstest (configuración y lectura de paquetes).
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"tacacs.err.host":       e("tacacs: servidor inválido", "tacacs: invalid server"),
		"tacacs.err.secret":     e("tacacs: falta el secreto compartido (sin él el tráfico viaja en claro)", "tacacs: the shared secret is missing (without it the traffic travels in clear)"),
		"tacacs.err.user":       e("tacacs: usuario vacío o campos de más de 255 bytes", "tacacs: empty user or fields of more than 255 bytes"),
		"tacacs.err.authen":     e("tacacs: tipo de autenticación {type:q} no soportado (ascii, pap)", "tacacs: authentication type {type:q} not supported (ascii, pap)", "type"),
		"tacacs.err.av_pair":    e("tacacs: el AV pair {pair}… mide {length} bytes; el máximo es 255 (acorta el comando)", "tacacs: the AV pair {pair}… is {length} bytes; the maximum is 255 (shorten the command)", "pair", "length"),
		"tacacs.err.version":    e("versión mayor {version}: no es TACACS+", "major version {version}: not TACACS+", "version"),
		"tacacs.err.body_limit": e("cuerpo de {length} bytes excede el límite", "body of {length} bytes exceeds the limit", "length"),
		"tacacs.err.short":      e("cuerpo truncado", "truncated body"),
	})
}

// Errores de internal/diag/flows (decodificación de NetFlow, IPFIX y sFlow).
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"flows.err.short":         e("paquete truncado", "truncated packet"),
		"flows.err.version":       e("versión {version} no soportada (NetFlow v5/v9, IPFIX, sFlow v5)", "version {version} not supported (NetFlow v5/v9, IPFIX, sFlow v5)", "version"),
		"flows.err.v5":            e("v5: {n} registros no caben en {bytes} bytes", "v5: {n} records do not fit in {bytes} bytes", "n", "bytes"),
		"flows.err.set":           e("set {id} con largo {length} inválido", "set {id} with invalid length {length}", "id", "length"),
		"flows.err.no_template":   e("{n} sets de datos sin plantilla (aún no llega del exportador)", "{n} data sets without a template (it has not arrived from the exporter yet)", "n"),
		"flows.err.template":      e("plantilla {id} inválida ({fields} campos)", "invalid template {id} ({fields} fields)", "id", "fields"),
		"flows.err.max_exporters": e("límite de {max} exportadores alcanzado; se ignora {exporter}", "limit of {max} exporters reached; {exporter} is ignored", "max", "exporter"),
		"flows.err.max_total":     e("límite global de {max} plantillas alcanzado; se ignora la de {exporter}", "global limit of {max} templates reached; the one from {exporter} is ignored", "max", "exporter"),
		"flows.err.max_templates": e("límite de {max} plantillas para {exporter}", "limit of {max} templates for {exporter}", "max", "exporter"),
		"flows.err.sflow_agent":   e("sflow: tipo de dirección de agente desconocido", "sflow: unknown agent address type"),
		"flows.err.sflow":         e("sflow: {cause}", "sflow: {cause}", "cause"),
	})
}

// Motivos de transferencia de internal/diag/fileserve que faltaban (fileserve.reason.*).
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"fileserve.reason.stopped":          e("servidor detenido", "server stopped"),
		"fileserve.reason.no_reply":         e("sin respuesta tras {tries} intentos", "no reply after {tries} attempts", "tries"),
		"fileserve.reason.client_abort_msg": e("el cliente abortó: {msg}", "the client aborted: {msg}", "msg"),
		"fileserve.reason.file_closed":      e("archivo ya cerrado", "file already closed"),
		"fileserve.reason.no_pasv":          e("sin PASV", "no PASV"),
	})
}

// Errores de internal/diag/ingest (archivo de salida) y transfer.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"ingest.err.out_dir":        e("carpeta de salida: {cause}", "output folder: {cause}", "cause"),
		"ingest.err.out_file":       e("archivo de salida: {cause}", "output file: {cause}", "cause"),
		"ingest.err.too_many_names": e("demasiados archivos con el mismo nombre", "too many files with the same name"),
		"xfer.err.local_name":       e("transfer: nombre local: {cause}", "transfer: local name: {cause}", "cause"),
	})
}

// Errores de internal/imgverify y textos del servicio de campo (HashFile, consola).
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"imgverify.err.hex":    e("imgverify: el {name} esperado debe tener {digits} dígitos hexadecimales", "imgverify: the expected {name} must have {digits} hexadecimal digits", "name", "digits"),
		"field.err.names_busy": e("archivo de salida: demasiados nombres ocupados", "output file: too many names in use"),
		"field.err.port_lost":  e("puerto perdido: {cause}", "port lost: {cause}", "cause"),
		"field.err.proto":      e("protocolo {proto:q} no soportado (tftp o http)", "protocol {proto:q} not supported (tftp or http)", "proto"),
		"field.hash.file":      e("archivo", "file"),
		"field.hash.match":     e("coincide", "matches"),
		"field.hash.differ":    e("NO COINCIDE", "DOES NOT MATCH"),
		"field.hash.on_device": e("en el equipo, tras copiarla:", "on the device, after copying it:"),
		"serial.val.flow":      e("flujo", "flow"),
		"imgverify.err.abs":    e("imgverify: la ruta debe ser absoluta", "imgverify: the path must be absolute"),
	})
}
