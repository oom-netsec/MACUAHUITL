-- Fase 44c1: orden de inicio del terminal para hosts linux y windows. Vacía = shell normal.
-- El número 0009 es de otro cambio (índice de auditoría); las migraciones se aplican por nombre, así que el hueco no importa.
ALTER TABLE hosts ADD COLUMN startup_command TEXT NOT NULL DEFAULT '';
