import type { Key } from "./i18n/es";

// Vocabularios cerrados que el núcleo manda como palabras sueltas (estados, severidades, tipos, orígenes).
// Cada valor conocido tiene su clave `vocab.<grupo>.<valor>` en es.ts y en.ts (lo exige vocab.test.ts);
// un valor nuevo del núcleo que aún no tenga clave se muestra tal cual, sin romper la vista.
export const VOCAB = {
  assistState: ["planned", "waiting-confirm", "running", "done", "aborted", "failed", "rolled-back", "abandoned"],
  findingSev: ["error", "warning", "info"],
  exchange: ["access-request", "status-server", "accounting-start", "accounting-stop", "authentication", "authorization"],
  ma: ["absent", "valid", "invalid"],
  phase: ["established", "failed", "mixed", "incomplete", "no_data"],
  proposal: ["accepted", "rejected"],
  source: ["patrol", "hallazgo", "log-equipo", "syslog", "auditoria", "pcap", "carpeta de Patrol"],
  hit: ["mac-table", "arp", "dhcp-snooping", "interface", "device"],
  inv: ["equipo", "modulo", "sfp"],
  problem: ["err-disabled", "half-duplex", "crc", "input_errors", "output_errors", "runts", "giants", "drops"],
  choice: ["fabrica"], // opciones de plantillas que no son palabras de IOS (modo-puerto)
} as const;

export type VocabGroup = keyof typeof VOCAB;
type T = (key: Key, vars?: Record<string, string | number>) => string;

// Sin acentos ni mayúsculas ni espacios: «válido» → «valido», «carpeta de Patrol» → «carpeta-de-patrol».
export const vocabKey = (group: VocabGroup, value: string) =>
  `vocab.${group}.${value.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/\s+/g, "-")}`;

/** Texto traducido de un valor del núcleo; si no hay clave, el valor tal cual. */
export function vocab(t: T, group: VocabGroup, value: string): string {
  const k = vocabKey(group, value) as Key;
  const r = t(k);
  return r === k ? value : r;
}

export const JOB_STATES = ["created", "arming", "armed", "completed", "cancelled", "failed", "closed"] as const;
/** Estado de un trabajo de Patrol (claves patrol.state.*); un estado desconocido se muestra tal cual. */
export function jobState(t: T, state: string): string {
  const k = `patrol.state.${state}` as Key;
  const r = t(k);
  return r === k ? state : r;
}
