-- Fase 48-4: protocolo del host de la libreta (ssh o telnet). Los hosts que ya existían quedan en ssh.
ALTER TABLE hosts ADD COLUMN protocol TEXT NOT NULL DEFAULT 'ssh';
