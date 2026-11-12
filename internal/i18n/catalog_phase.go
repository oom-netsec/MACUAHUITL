package i18n

// Detalle de las fases de un trabajo de Patrol. El motivo de cada fase es su propio código (phase.*), con los
// argumentos que usa su texto.
func init() {
	add(map[string]entry{
		"phase.devices":          {Es: "{n} {n|equipo|equipos}", En: "{n} {n|device|devices}", Args: []string{"n"}},
		"phase.devices_excluded": {Es: "{n} {n|equipo|equipos}, {excluded} {excluded|excluido|excluidos}", En: "{n} {n|device|devices}, {excluded} excluded", Args: []string{"n", "excluded"}},
		"phase.ok_failed":        {Es: "{ok} {ok|correcto|correctos}, {failed} con fallas", En: "{ok} successful, {failed} failed", Args: []string{"ok", "failed"}},
		"phase.rounds":           {Es: "{n} {n|ronda|rondas}", En: "{n} {n|round|rounds}", Args: []string{"n"}},
		"phase.packaged":         {Es: "{path}", En: "{path}", Args: []string{"path"}},
		"phase.round_zip_failed": {Es: "zip de la ronda: {error}", En: "round zip: {error}", Args: []string{"error"}},
		"phase.close_failed":     {Es: "cierre (manifest o zip): {error}", En: "closing (manifest or zip): {error}", Args: []string{"error"}},
		"phase.before_arming":    {Es: "antes de armar", En: "before arming"},
		"phase.core_stopped":     {Es: "el núcleo se detuvo con el trabajo armado; no se reanuda", En: "the core stopped while the job was armed; it does not resume"},
	})
}
