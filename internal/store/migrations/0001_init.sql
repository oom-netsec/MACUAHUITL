-- Esquema inicial (spec §14). Los planes 1c y 1d agregan columnas con migraciones nuevas.

CREATE TABLE device_profiles (
    id                      TEXT PRIMARY KEY,
    port                    INTEGER NOT NULL DEFAULT 22,
    allow_legacy_algorithms INTEGER NOT NULL DEFAULT 0,
    uses_enable             INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE devices (
    id         TEXT PRIMARY KEY,
    hostname   TEXT NOT NULL DEFAULT '',
    address    TEXT NOT NULL,
    platform   TEXT NOT NULL DEFAULT '',
    profile_id TEXT REFERENCES device_profiles(id),
    created_at TEXT NOT NULL
);

-- Solo el ID opaco: el contenido vive cifrado en vault.mcv.
CREATE TABLE credentials_ref (
    id TEXT PRIMARY KEY
);

CREATE TABLE playbooks_index (
    id       TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    name     TEXT NOT NULL,
    sha256   TEXT NOT NULL,
    source   TEXT NOT NULL
);

CREATE TABLE jobs (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    spec_json  TEXT NOT NULL,
    state      TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE job_runs (
    job_id     TEXT NOT NULL REFERENCES jobs(id),
    round      INTEGER NOT NULL,
    state      TEXT NOT NULL,
    started_at TEXT,
    ended_at   TEXT,
    PRIMARY KEY (job_id, round)
);

CREATE TABLE run_devices (
    job_id    TEXT NOT NULL,
    round     INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    state     TEXT NOT NULL,
    detail    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (job_id, round, device_id),
    FOREIGN KEY (job_id, round) REFERENCES job_runs(job_id, round)
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE audit_log (
    seq    INTEGER PRIMARY KEY,
    at     TEXT NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT NOT NULL,
    prev   TEXT NOT NULL,
    hash   TEXT NOT NULL
);

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log es solo inserción'); END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log es solo inserción'); END;
