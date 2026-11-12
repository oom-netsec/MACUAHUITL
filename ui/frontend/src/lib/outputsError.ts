import type { Key } from "./i18n/es";

// Motivos estables del núcleo (internal/service/outputs.go): cada uno tiene su explicación traducida.
export const OUTPUTS_REASONS = ["relativa", "punto_punto", "no_existe", "ilegible", "no_directorio", "otro_dueno", "reservada", "permisos", "ancestro_inseguro", "no_escribible"];

/** Código del rechazo y, si trae la orden `chmod 700 <ruta>`, la ruta (vacía si no). */
export function parseOutputsError(msg: string): { code: string; path: string } | null {
  const m = /^prefs\.outputs\.([a-z_]+):/.exec(msg);
  if (!m) return null;
  // Sin trim: una carpeta que termina en espacio es otra carpeta.
  return { code: m[1], path: /chmod 700 (\S.*)$/.exec(msg)?.[1] ?? "" };
}

// La ruta va entre comillas solo si lo necesita, para que la orden se pueda pegar tal cual.
const shellQuote = (p: string) => (/^[\w@%+=:,./-]+$/.test(p) ? p : `'${p.replaceAll("'", "'\\''")}'`);

/** La orden `chmod 700 <ruta>` lista para pegar; vacía si la ruta trae `\`, `'` o un carácter de control (en fish `\'` escapa dentro de comillas simples: no hay cita segura). */
export function chmodCommand(path: string): string {
  // eslint-disable-next-line no-control-regex
  if (!path || /[\\'\x00-\x1f\x7f]/.test(path)) return "";
  return `chmod 700 ${shellQuote(path)}`;
}

/** La clave traducida de un motivo del núcleo. */
export const outputsReasonKey = (code: string): Key => (OUTPUTS_REASONS.includes(code) ? (`settings.storage.err.${code}` as Key) : "settings.storage.err.other");

/** Texto para mostrar un error del núcleo: si es un rechazo de carpeta, su explicación traducida (y el chmod); si no, tal cual. */
export function outputsErrorText(msg: string, t: (k: Key) => string): string {
  const p = parseOutputsError(msg);
  if (!p) return msg;
  const cmd = p.code === "permisos" ? chmodCommand(p.path) : "";
  return t(outputsReasonKey(p.code)) + (cmd ? ` ${cmd}` : "");
}
