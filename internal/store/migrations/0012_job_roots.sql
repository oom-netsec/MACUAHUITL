-- Carpetas de corrida de los trabajos (fase 46b): sobreviven a quitar el trabajo del historial, para que
-- fleet e inventory sigan viendo la evidencia que sigue en disco. Solo la ruta; sin llaves ni datos previos.
CREATE TABLE job_roots (
    dir TEXT PRIMARY KEY
);
