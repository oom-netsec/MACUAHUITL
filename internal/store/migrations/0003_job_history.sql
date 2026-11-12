-- Historial del trabajo (fases, ronda, conteos, carpeta). '{}' en los trabajos guardados antes.
ALTER TABLE jobs ADD COLUMN history_json TEXT NOT NULL DEFAULT '{}';
