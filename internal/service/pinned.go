package service

// PinnedJob es un trabajo de Patrol que otro flujo todavía necesita aunque ya no corra: no se quita del historial.
// Reason es el código estable que sale en SkippedJob (change_pre, backup_import, adhoc_unread).
type PinnedJob struct{ ID, Reason string }
