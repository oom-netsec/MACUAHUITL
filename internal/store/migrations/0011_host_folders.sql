-- Carpetas de hosts (fase 44d): entidad propia, única sin distinguir mayúsculas. hosts.folder sigue siendo el
-- nombre (sin llave foránea: agregarla exige reconstruir hosts); el servicio mantiene que todo hosts.folder no
-- vacío exista aquí con el mismo texto.
CREATE TABLE host_folders (
    name       TEXT PRIMARY KEY COLLATE NOCASE,
    created_at TEXT NOT NULL
);

-- «Lab» y «lab» ya eran una carpeta para el filtro: queda la primera en orden binario.
INSERT OR IGNORE INTO host_folders(name, created_at)
    SELECT folder, MIN(created_at) FROM hosts WHERE folder <> '' GROUP BY folder ORDER BY folder;

UPDATE hosts SET folder = (SELECT name FROM host_folders f WHERE f.name = hosts.folder) WHERE folder <> '';
