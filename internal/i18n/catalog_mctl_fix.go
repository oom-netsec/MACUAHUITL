package i18n

// Mensajes sueltos de mctl que faltaban (revisión de 30e).
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"mctl.change.checks_failed": e("{n} verificaciones fallaron", "{n} checks failed", "n"),
		"mctl.change.rules_failed":  e("{n} reglas fallaron", "{n} rules failed", "n"),
		"mctl.calc.route_key":       e("ruta {route:q}: clave {key:q} desconocida", "route {route:q}: unknown key {key:q}", "route", "key"),
	})
}
