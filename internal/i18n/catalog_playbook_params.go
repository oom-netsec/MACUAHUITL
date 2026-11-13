package i18n

// Datos de los playbooks (Fase 34): errores de carga y de sustitución (playbook.err.*).
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"playbook.err.param_undeclared": e("el comando usa {name:q} pero no está en params", "the command uses {name:q} but it is not in params", "name"),
		"playbook.err.param_unused":     e("el dato {name:q} está declarado y ningún comando lo usa", "the parameter {name:q} is declared but no command uses it", "name"),
		"playbook.err.param_kind":       e("el dato {name:q} tiene un tipo {kind:q} desconocido (mac, ap, interface o ip)", "parameter {name:q} has an unknown type {kind:q} (mac, ap, interface or ip)", "name", "kind"),
		"playbook.err.param_name":       e("nombre de dato {name:q} inválido (minúsculas, dígitos y _)", "invalid parameter name {name:q} (lowercase, digits and _)", "name"),
		"playbook.err.param_dup":        e("el dato {name:q} está repetido", "parameter {name:q} is repeated", "name"),
		"playbook.err.param_in_pre":     e("pre no admite datos ({name:q})", "pre does not accept parameters ({name:q})", "name"),
		"playbook.err.param_missing":    e("falta el dato {name:q} ({kind})", "missing parameter {name:q} ({kind})", "name", "kind"),
		"playbook.err.param_unknown":    e("el playbook no pide el dato {name:q}", "the playbook does not take the parameter {name:q}", "name"),
		"playbook.err.param_invalid":    e("el dato {name:q} no es un valor {kind} válido", "the parameter {name:q} is not a valid {kind} value", "name", "kind"),
	})
}
