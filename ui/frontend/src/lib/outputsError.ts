import { errorText } from "../components/Field";
import { errInfo } from "./coreError";
import type { Key } from "./i18n/es";

// Motivos estables del núcleo (internal/service/outputs.go): cada uno tiene su explicación traducida.
export const OUTPUTS_REASONS = ["relativa", "punto_punto", "no_existe", "ilegible", "no_directorio", "otro_dueno", "reservada", "permisos", "ancestro_inseguro", "no_escribible"];

/** Código del rechazo y la ruta (vacía si no viene): de reason/metadata; el texto en español solo sirve si el error no trae reason. */
export function parseOutputsError(e: unknown): { code: string; path: string } | null {
  const i = errInfo(e);
  if (i) return i.reason.startsWith("prefs.outputs.") ? { code: i.metadata.code || i.reason.slice(14), path: i.metadata.path ?? "" } : null;
  const msg = errorText(e);
  const m = /^prefs\.outputs\.([a-z_]+):/.exec(msg);
  if (!m) return null;
  // Sin trim: una carpeta que termina en espacio es otra carpeta.
  return { code: m[1], path: /corrígelo con: chmod 700 (\S.*)$/.exec(msg)?.[1] ?? "" };
}

// La ruta va entre comillas solo si lo necesita, para que la orden se pueda pegar tal cual.
const shellQuote = (p: string) => (/^[\w@%+=:,./-]+$/.test(p) ? p : `'${p.replaceAll("'", "'\\''")}'`);

/** La orden `chmod 700 <ruta>` lista para pegar; vacía si la ruta trae `\`, `'` o un carácter de control (en fish `\'` escapa dentro de comillas simples: no hay cita segura). */
export function chmodCommand(path: string): string {
  // eslint-disable-next-line no-control-regex
  // También los invisibles (ancho cero, marcas de dirección, separadores de línea, BOM): la orden se vería distinta de lo que se pega.
  if (!path || /[\\'\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/.test(path)) return "";
  return `chmod 700 ${shellQuote(path)}`;
}

/** La clave traducida de un motivo del núcleo. */
export const outputsReasonKey = (code: string): Key => (OUTPUTS_REASONS.includes(code) ? (`settings.storage.err.${code}` as Key) : "settings.storage.err.other");

/** Texto para mostrar un error del núcleo: si es un rechazo de carpeta, su explicación traducida (y el chmod); si no, tal cual. */
export function outputsErrorText(e: unknown, t: (k: Key) => string): string {
  const p = parseOutputsError(e);
  if (!p) return errorText(e);
  const cmd = p.code === "permisos" ? chmodCommand(p.path) : "";
  return t(outputsReasonKey(p.code)) + (cmd ? ` ${cmd}` : "");
}
