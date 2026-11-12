-- Libreta de hosts (fase 29b): la fuente «manual» del inventario. credential_id es solo la referencia a la
-- bóveda; nunca un secreto. La dirección se guarda canónica (minúsculas / IP normalizada).
CREATE TABLE hosts (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    address       TEXT NOT NULL,
    port          INTEGER NOT NULL,
    platform      TEXT NOT NULL,
    folder        TEXT NOT NULL,
    tags_json     TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    notes         TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (address, port)
);

-- Respaldo de la unicidad de nombres (el servicio compara sin distinguir mayúsculas de Unicode).
CREATE UNIQUE INDEX hosts_name ON hosts (name COLLATE NOCASE);
