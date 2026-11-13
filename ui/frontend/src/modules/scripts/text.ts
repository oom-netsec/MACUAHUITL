import type { Key } from "../../lib/i18n/es";
import { errInfo } from "../../lib/coreError";

// Lo que se inserta en la terminal: los comandos tal cual, incluidas las líneas «!» (dentro de un banner son texto).
export const scriptText = (commands: string[]) => commands.join("\n");

// Un script de configuración de varias líneas nunca va a la terminal: cada salto de línea ejecutaría una línea (ADR 0007).
// Se copia y la persona lo pega o lo aplica con un snippet en modo asistido.
export const needsCopy = (s: { commands: string[]; readOnly: boolean }) => s.commands.length > 1 && !s.readOnly;

// Lo que viaja por el canal «terminal-insert» (el buzón entre módulos solo lleva texto).
export interface Insert { name: string; text: string; readOnly: boolean }
export const encodeInsert = (i: Insert) => JSON.stringify(i);
export function decodeInsert(data: string): Insert | null {
  try {
    const i = JSON.parse(data);
    return typeof i?.text === "string" ? { name: String(i.name ?? ""), text: i.text, readOnly: i.readOnly === true } : null;
  } catch { return null; }
}

export const parseTags = (s: string) => s.split(/[\s,]+/).filter(Boolean);
// Una línea en blanco es solo estética: el núcleo la rechazaría como comando vacío.
export const parseCommands = (s: string) => s.split(/\r?\n/).filter((l) => l.trim() !== "");

export type FormField = "name" | "desc" | "tags" | "commands";
export type FormErrors = Partial<Record<FormField, { k: Key; n?: number }>>;

// Las mismas reglas que aplica el núcleo, para avisar junto al campo antes de enviar.
export function validateScript(f: { name: string; description: string; tags: string[]; commands: string[] }): FormErrors {
  const e: FormErrors = {};
  const name = f.name.trim();
  if (!name || name.length > 64) e.name = { k: "scripts.v.name" };
  if (f.description.length > 512) e.desc = { k: "scripts.v.desc" };
  if (f.tags.length > 10 || new Set(f.tags).size !== f.tags.length || f.tags.some((x) => !/^[a-z0-9-]{1,24}$/.test(x))) e.tags = { k: "scripts.v.tags" };
  if (f.commands.length === 0) e.commands = { k: "scripts.v.cmdEmpty" };
  else if (f.commands.length > 200) e.commands = { k: "scripts.v.cmdMax" };
  else {
    const bad = f.commands.findIndex((c) => c.length > 512 || !/^[\x20-\x7e]*$/.test(c));
    if (bad >= 0) e.commands = { k: "scripts.v.cmdAscii", n: bad + 1 };
  }
  return e;
}

type T = (k: Key, v?: Record<string, string | number>) => string;

// «favoritos» viaja con el nombre del núcleo («Favoritos»); en pantalla va en el idioma elegido.
export const colName = (t: T, c: { id: string; name: string }) => (c.id === "favoritos" ? t("scripts.col.favName") : c.name);

// Los avisos del import llegan en español del núcleo. Los tres que conoce se traducen; otro texto se muestra tal cual.
export function warningText(t: T, w: string): string {
  if (w === "archivo sin suma de verificación") return t("scripts.warn.noSum");
  const m = /^colección "(.*)": el script (\S+) (no está en la biblioteca local; se omiti(?:ó|rá)|no se importó; se quitó de la colección)$/.exec(w);
  if (!m) return w;
  // «se omitirá» es el aviso de la vista previa; «se omitió» y «no se importó» llegan en el resultado de aplicar.
  return t(m[3].endsWith("rá") ? "scripts.warn.libMissingNext" : m[3].startsWith("no está") ? "scripts.warn.libMissing" : "scripts.warn.dropped", { col: m[1], id: m[2] });
}

// NotFound (token gastado o desconocido) y FailedPrecondition (vencido) no se corrigen con otra decisión; InvalidArgument sí.
const rawMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));
export const tokenGone = (e: unknown) => /code = (NotFound|FailedPrecondition)\b/.test(rawMsg(e));
// El sexto fijado: FailedPrecondition. Se mira el mensaje crudo (errorText ya quita el prefijo) y no la redacción del motivo.
export const isPinLimit = (e: unknown) => /code = FailedPrecondition\b/.test(rawMsg(e));

// Campo de cada reason de validación del núcleo (catalog_scripts.go).
const REASON_FIELD: Record<string, FormField> = {
  "scripts.err.name": "name", "scripts.svc.name_taken": "name", "scripts.err.description": "desc",
  "scripts.err.tags_max": "tags", "scripts.err.tag_bad": "tags", "scripts.err.tag_dup": "tags",
  "scripts.err.commands": "commands", "scripts.err.command_empty": "commands", "scripts.err.command_ascii": "commands",
};

// Un error del núcleo se pone junto al campo que nombra (por su reason; sin reason, por el texto en español); el resto queda como aviso general.
export function fieldOfError(e: unknown): FormField | "" {
  const info = errInfo(e);
  if (info) return REASON_FIELD[info.reason] ?? "";
  const msg = e instanceof Error ? e.message : String(e);
  if (/llamado|^el nombre/i.test(msg)) return "name";
  if (/etiqueta/i.test(msg)) return "tags";
  if (/descripci/i.test(msg)) return "desc";
  if (/comando/i.test(msg)) return "commands";
  return "";
}
