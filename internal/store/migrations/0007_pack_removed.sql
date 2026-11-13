-- Paquetes de contenido (fase 32, ADR 0010): los IDs de playbook de un paquete quitado. Un trabajo que todavía pide
-- uno falla con pack.missing y dice qué paquete instalar. Solo IDs públicos del contenido; nunca rutas ni secretos.
CREATE TABLE pack_removed (
    playbook_id TEXT PRIMARY KEY,
    pack        TEXT NOT NULL
);
