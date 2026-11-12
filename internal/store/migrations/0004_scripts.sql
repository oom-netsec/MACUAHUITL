-- Bóveda de scripts (fase 28c): solo los del usuario; la biblioteca viene embebida en el binario.
CREATE TABLE scripts (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    tech          TEXT NOT NULL,
    platform      TEXT NOT NULL,
    description   TEXT NOT NULL,
    commands_json TEXT NOT NULL,
    tags_json     TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- Favoritos aparte: también se marcan los de la biblioteca (id «lib-*»).
CREATE TABLE script_favorites (
    id TEXT PRIMARY KEY
);
