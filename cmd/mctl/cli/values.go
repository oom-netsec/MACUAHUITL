package cli

// stateEn lleva el estado de import del cable (en español, histórico) al inglés canónico que ve el usuario.
var stateEn = map[string]string{
	"nuevo": "new", "nueva": "new", "igual": "same", "conflicto": "conflict",
	"conflicto_etiqueta": "label_conflict", "conflicto_id": "id_conflict", "conflicto_nombre": "name_conflict",
	"reservada": "reserved", "fusionar": "merge",
}

// StateText es el estado de import como se imprime (inglés). Solo para mostrar: las comparaciones y el JSON siguen con
// el valor del cable. Lo desconocido pasa tal cual.
func StateText(wire string) string {
	if v, ok := stateEn[wire]; ok {
		return v
	}
	return wire
}

// scriptWire: tecnologías y plataformas de scripts, inglés canónico → valor del cable (español, histórico).
var scriptWire = map[string]string{
	"management": "gestion", "security": "seguridad", "diagnostics": "diagnostico", "other": "otro", "any": "cualquiera",
}

// ScriptValueWire lleva el valor de --tech o --platform al del cable; el alias en español y lo desconocido pasan tal cual.
func ScriptValueWire(v string) string {
	if w, ok := scriptWire[v]; ok {
		return w
	}
	return v
}

// ScriptValueText es el inverso, para mostrar (el JSON sigue con el valor del cable).
func ScriptValueText(wire string) string {
	for en, w := range scriptWire {
		if w == wire {
			return en
		}
	}
	return wire
}
