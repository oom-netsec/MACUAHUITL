-- Colecciones de scripts (fase 29c): listas ordenadas de IDs de script (de usuario o «lib-*», sin FK porque la
-- biblioteca no está en la base) y la barra de fijados. Los favoritos de la 0004 pasan a la colección «favoritos».
CREATE TABLE script_collections (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    position    INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE script_collection_items (
    collection_id TEXT NOT NULL REFERENCES script_collections(id) ON DELETE CASCADE,
    script_id     TEXT NOT NULL,
    position      INTEGER NOT NULL,
    PRIMARY KEY (collection_id, script_id)
);

CREATE TABLE script_pins (
    script_id TEXT PRIMARY KEY,
    position  INTEGER NOT NULL
);

INSERT INTO script_collections(id, name, description, position, created_at, updated_at)
VALUES ('favoritos', 'Favoritos', '', 0, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));

-- No hay fecha de marcado: el orden es por nombre sin importar mayúsculas. Los «lib-*» no tienen nombre en la base
-- (la biblioteca viene embebida en el binario), así que ordenan por su ID y no por el nombre que se ve en la vista.
-- Se descartan filas de scripts de usuario que ya no existen.
INSERT INTO script_collection_items(collection_id, script_id, position)
SELECT 'favoritos', f.id, ROW_NUMBER() OVER (ORDER BY COALESCE(s.name, f.id) COLLATE NOCASE, f.id) - 1
FROM script_favorites f LEFT JOIN scripts s ON s.id = f.id
WHERE f.id LIKE 'lib-%' OR s.id IS NOT NULL;

DROP TABLE script_favorites;
