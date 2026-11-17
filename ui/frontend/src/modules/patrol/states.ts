// Única definición de estados de un trabajo: vivo = sigue corriendo; quitable del historial = todo lo demás
// (created sin armar, completed, cancelled, failed). El núcleo tiene la última palabra y devuelve `skipped`.
export const isLive = (j: { state: string }) => ["armed", "arming", "running", "paused"].includes(j.state);
export const isRemovable = (j: { state: string }) => !isLive(j);
