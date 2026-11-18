// Única definición de estados de un trabajo: vivo = sigue corriendo; quitable del historial = todo lo demás
// (created sin armar, completed, cancelled, failed). El núcleo tiene la última palabra y devuelve `skipped`.
export const isLive = (j: { state: string }) => ["armed", "arming", "running", "paused"].includes(j.state);
// 46c2: el arranque falló y el trabajo volvió a created; la última fase (ARM_FAILED) trae el motivo.
export const armFailed = (j: { state: string }, phases: { kind: string }[] = []) => j.state === "created" && phases.at(-1)?.kind === "JOB_PHASE_KIND_ARM_FAILED";
export const isRemovable = (j: { state: string }) => !isLive(j);
