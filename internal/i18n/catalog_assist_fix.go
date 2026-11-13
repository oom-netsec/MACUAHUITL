package i18n

// Piezas del motivo de una reversa que no dejó el equipo como estaba (assist/run.go). Las líneas de configuración no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"assist.residue.missing":      e("falta «{line}»", "missing \"{line}\"", "line"),
		"assist.residue.extra":        e("sobra «{line}»", "extra \"{line}\"", "line"),
		"assist.residue.missing_in":   e("falta «{line}» en {head}", "missing \"{line}\" in {head}", "line", "head"),
		"assist.residue.extra_in":     e("sobra «{line}» en {head}", "extra \"{line}\" in {head}", "line", "head"),
		"assist.residue.more":         e("y {n} más", "and {n} more", "n"),
		"assist.residue.hidden":       e("(línea oculta)", "(hidden line)"),
		"assist.residue.cmd":          e("{command}: {residue}", "{command}: {residue}", "command", "residue"),
		"assist.residue.err_disabled": e("{port} quedó err-disabled; la reversa no lo recupera: shutdown/no shutdown a mano", "{port} ended up err-disabled; the rollback does not recover it: shutdown/no shutdown by hand", "port"),
	})
}
