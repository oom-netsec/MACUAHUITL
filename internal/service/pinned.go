package service

import "context"

// PinnedJob es un trabajo de Patrol que otro flujo todavía necesita aunque ya no corra: no se quita del historial.
// Reason es el código estable que sale en SkippedJob (change_pre, backup_import, adhoc_unread).
type PinnedJob struct{ ID, Reason string }

// ArmedOnly deja de la lista los trabajos que nunca se armaron (estado created, p. ej. ArmJob falló al arrancar) o que ya
// no existen: no tienen evidencia que proteger. Se llama sin los mutex del servicio (Job toma el del núcleo).
func ArmedOnly(ctx context.Context, d Deps, in []PinnedJob) []PinnedJob {
	var out []PinnedJob
	for _, p := range in {
		if j, err := d.Job(ctx, p.ID); err == nil && j.State != "created" {
			out = append(out, p)
		}
	}
	return out
}
