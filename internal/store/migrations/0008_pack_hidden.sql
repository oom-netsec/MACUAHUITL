-- Paquetes de contenido (fase 32b, ADR 0010): lo que el usuario ocultó de un paquete instalado, por paquete y por ID
-- (de playbook o de script). Ocultar solo quita de las listas; el ID se sigue resolviendo. Solo IDs públicos del contenido.
CREATE TABLE pack_hidden (
    pack    TEXT NOT NULL,
    item_id TEXT NOT NULL,
    PRIMARY KEY (pack, item_id)
);
