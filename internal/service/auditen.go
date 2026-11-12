package service

// DecisionEN es el verbo de una decisión de importación en inglés, para la auditoría (que va siempre en
// inglés). Los verbos del cable siguen en español; uno desconocido sale tal cual.
func DecisionEN(a string) string {
	if en, ok := map[string]string{"reemplazar": "replace", "renombrar": "rename", "omitir": "skip", "fusionar": "merge"}[a]; ok {
		return en
	}
	return a
}

// DirEN es el sentido de una transferencia de fileserve («lectura» o «escritura») en inglés, para la auditoría.
func DirEN(d string) string {
	switch d {
	case "lectura":
		return "read"
	case "escritura":
		return "write"
	}
	return d
}
