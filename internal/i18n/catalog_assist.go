package i18n

// Asistente de cambios: los valores de un snippet que no pasan la validación (assist.invalid_value, con el motivo
// {why} = required | range | pattern | choice | type | unknown_field y el {field} del primer problema) y las
// negativas por el estado del equipo (assist.refused). Los valores secretos nunca van en la metadata ni en el texto.
func init() {
	m := map[string]entry{}
	val := func(key, why string, e entry) {
		e.Reason = "assist.invalid_value"
		e.Meta = map[string]string{"why": why}
		m["assist.invalid_value."+key] = e
	}
	// Una pieza por problema; las que citan el valor lo llevan entre comillas, salvo en los secretos.
	val("unknown_field", "unknown_field", entry{Es: "campo desconocido {field:q}", En: "unknown field {field:q}", Args: []string{"field"}})
	val("required", "required", entry{Es: "falta {label} ({field})", En: "{field} is required", Args: []string{"label", "field"}})
	val("ascii", "pattern", entry{Es: "{value:q}: tiene caracteres fuera de ASCII imprimible (0x20-0x7e)", En: "{value:q}: contains characters outside printable ASCII (0x20-0x7e)", Args: []string{"value"}})
	val("special", "pattern", entry{Es: "{value:q}: '?' y el tabulador no se admiten", En: "{value:q}: '?' and the tab character are not allowed", Args: []string{"value"}})
	val("trim", "pattern", entry{Es: "{value:q}: sin espacios al inicio ni al final", En: "{value:q}: no leading or trailing spaces", Args: []string{"value"}})
	val("length", "range", entry{Es: "mide {n} caracteres y debe medir entre {min} y {max}", En: "is {n} characters long and must be between {min} and {max}", Args: []string{"n", "min", "max"}})
	val("internal_pattern", "pattern", entry{Es: "patrón interno inválido", En: "invalid internal pattern"})
	val("format", "pattern", entry{Es: "{value:q} no cumple el formato esperado", En: "{value:q} does not match the expected format", Args: []string{"value"}})
	val("not_int", "type", entry{Es: "{value:q} no es un entero (sin signo ni ceros a la izquierda)", En: "{value:q} is not an integer (no sign or leading zeros)", Args: []string{"value"}})
	val("out_of_range", "range", entry{Es: "{value} fuera de {range}", En: "{value} is outside {range}", Args: []string{"value", "range"}})
	val("not_decimal", "type", entry{Es: "{value:q} no es un número con hasta dos decimales", En: "{value:q} is not a number with up to two decimals", Args: []string{"value"}})
	val("bool", "choice", entry{Es: "{value:q}: solo true o false", En: "{value:q}: only true or false", Args: []string{"value"}})
	val("choice", "choice", entry{Es: "{value:q}: elige una de {choices}", En: "{value:q}: choose one of {choices}", Args: []string{"value", "choices"}})
	val("ipv4", "type", entry{Es: "dirección IPv4 inválida {value:q}", En: "invalid IPv4 address {value:q}", Args: []string{"value"}})
	val("mask", "type", entry{Es: "máscara inválida {value:q} (usa la forma 255.255.255.0)", En: "invalid mask {value:q} (use the form 255.255.255.0)", Args: []string{"value"}})
	val("mask_gap", "type", entry{Es: "máscara {value:q} no contigua", En: "mask {value:q} is not contiguous", Args: []string{"value"}})
	val("interface", "type", entry{Es: "{value:q} no es un puerto físico ni un Port-channel", En: "{value:q} is neither a physical port nor a Port-channel", Args: []string{"value"}})
	val("iface_range", "range", entry{Es: "rango {value:q} inválido (de menor a mayor y hasta {max} puertos)", En: "invalid range {value:q} (ascending and up to {max} ports)", Args: []string{"value", "max"}})
	val("iface_count", "range", entry{Es: "más de {max} puertos en un solo plan", En: "more than {max} ports in a single plan", Args: []string{"max"}})
	val("type_unknown", "type", entry{Es: "tipo de campo desconocido {value:q}", En: "unknown field type {value:q}", Args: []string{"value"}})
	val("secret_chars", "pattern", entry{Es: "el secreto lleva caracteres no permitidos (solo ASCII visible, sin espacios ni '?')", En: "the secret has characters that are not allowed (visible ASCII only, no spaces or '?')"})
	val("secret_length", "range", entry{Es: "el secreto debe medir entre {min} y {max} caracteres", En: "the secret must be between {min} and {max} characters long", Args: []string{"min", "max"}})
	// Un problema que aún no tiene su código: el texto sale tal cual lo escribió el núcleo.
	val("other", "type", entry{Es: "{detail}", En: "{detail}", Args: []string{"detail"}})
	// El mensaje completo: lleva el prefijo y las piezas ya unidas con «; ».
	m["assist.invalid_value"] = entry{Es: "assist: valores del snippet inválidos: {pieces}", En: "assist: invalid snippet values: {pieces}",
		Args: []string{"pieces"}, Extra: []string{"template", "field", "why"}}
	// El equipo no admite el snippet; el motivo concreto sigue en el idioma del núcleo hasta su fase de traducción.
	m["assist.refused"] = entry{Es: "assist: el equipo no admite este snippet: {detail}", En: "assist: the device does not support this snippet: {detail}",
		Args: []string{"detail"}, Extra: []string{"template", "device"}}
	add(m)
}
