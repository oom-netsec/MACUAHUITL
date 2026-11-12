// Opciones de los receptores syslog, traps y flujos: formulario en texto, validación en vivo con la regla del núcleo y el nombre de ejemplo.
import type { SyslogOptions } from "../../modules/tools/api";
import type { Key } from "../../lib/i18n/es";
import type { ErrInfo } from "../../lib/coreError";

/** Receptor al que sirven las opciones: cambian los defaults de tasa (flujos), la plantilla y las unidades. */
export type IngestKind = "syslog" | "traps" | "flows";

export type NumKey = "ratePerSource" | "burstPerSource" | "rateGlobal" | "burstGlobal" | "queueSize" | "rotateMb" | "rotateMinutes" | "maxFiles";
export type SyslogFormat = "texto" | "crudo" | "jsonl";
export type OptKey = NumKey | "nameTemplate" | "format" | "addr";
export type OptForm = Record<NumKey, string> & { nameTemplate: string; format: SyslogFormat };
/** Código de error por campo; el texto sale de `syslog.err.<código>`. */
export type OptError = "int" | "range" | "tplLen" | "tplNeed" | "tplTokens" | "tplChars" | "tplDots";

// Rangos y defaults del contrato (docs/plans/contratos-front.md, fases 28a y 29a). def vacío: sin valor fijo.
export const RANGES: Record<NumKey, { lo: number; hi: number; def: string }> = {
  ratePerSource: { lo: 1, hi: 10000, def: "100" },
  burstPerSource: { lo: 1, hi: 1000000, def: "" },
  rateGlobal: { lo: 1, hi: 100000, def: "1000" },
  burstGlobal: { lo: 1, hi: 1000000, def: "" },
  queueSize: { lo: 64, hi: 65536, def: "4096" },
  rotateMb: { lo: 1, hi: 1024, def: "50" },
  rotateMinutes: { lo: 1, hi: 10080, def: "" },
  maxFiles: { lo: 1, hi: 1000, def: "20" },
};
export const DEFAULT_TEMPLATES: Record<IngestKind, string> = { syslog: "syslog_{fecha}_{hora}", traps: "traps_{fecha}_{hora}", flows: "flujos_{fecha}_{hora}" };
export const DEFAULT_TEMPLATE = DEFAULT_TEMPLATES.syslog;
const NUM_KEYS = Object.keys(RANGES) as NumKey[];
const FILE_KEYS: NumKey[] = ["rotateMb", "rotateMinutes", "maxFiles"];
const FLOOD_KEYS: NumKey[] = ["ratePerSource", "burstPerSource", "rateGlobal", "burstGlobal", "queueSize"];

/** Rango y default del campo para ese receptor: un exportador manda muchos más datagramas que un equipo syslog. */
export function rangeOf(kind: IngestKind, k: NumKey) {
  if (kind !== "flows") return RANGES[k];
  return k === "ratePerSource" ? { ...RANGES[k], def: "1000" } : k === "rateGlobal" ? { ...RANGES[k], def: "5000" } : RANGES[k];
}

/** Los campos que aplican: en flujos los topes solo rigen al guardar en archivo (sin archivo no hay tope ni descartes). */
const applies = (kind: IngestKind, k: NumKey, save: boolean) => save || !(FILE_KEYS.includes(k) || (kind === "flows" && FLOOD_KEYS.includes(k)));

export const emptyForm: OptForm = {
  ratePerSource: "", burstPerSource: "", rateGlobal: "", burstGlobal: "", queueSize: "",
  rotateMb: "", rotateMinutes: "", maxFiles: "", nameTemplate: "", format: "texto",
};

// Solo se manda lo escrito: vacío es el default del núcleo. Las opciones de archivo solo con save.
export function buildOpts(f: OptForm, save: boolean, kind: IngestKind = "syslog"): SyslogOptions {
  const o: SyslogOptions = {};
  for (const k of NUM_KEYS) if (applies(kind, k, save) && f[k].trim()) o[k] = Number(f[k].trim());
  if (save) {
    if (f.nameTemplate.trim()) o.nameTemplate = f.nameTemplate.trim();
    if (f.format !== "texto") o.format = f.format;
  }
  return o;
}

// Misma regla que syslogd.ValidateTemplate; "" es el default.
function templateError(t: string): OptError | undefined {
  if (!t) return undefined;
  if (t.length > 64) return "tplLen";
  if (!t.includes("{fecha}") && !t.includes("{hora}")) return "tplNeed";
  const s = t.replaceAll("{fecha}", "0").replaceAll("{hora}", "0").replaceAll("{origen}", "0");
  if (/[{}]/.test(s)) return "tplTokens";
  if (/[^A-Za-z0-9_.-]/.test(s)) return "tplChars";
  if (s.includes("..")) return "tplDots";
  return undefined;
}

export function validateOpts(f: OptForm, save: boolean, kind: IngestKind = "syslog"): Partial<Record<OptKey, OptError>> {
  const e: Partial<Record<OptKey, OptError>> = {};
  for (const k of NUM_KEYS) {
    const v = f[k].trim();
    if (!v || !applies(kind, k, save)) continue;
    if (!/^\d+$/.test(v)) e[k] = "int";
    else if (Number(v) < RANGES[k].lo || Number(v) > RANGES[k].hi) e[k] = "range";
  }
  const te = save ? templateError(f.nameTemplate.trim()) : undefined;
  if (te) e.nameTemplate = te;
  return e;
}

const p2 = (n: number) => String(n).padStart(2, "0");
/** Nombre de ejemplo con la fecha y hora de ahora y un origen ficticio. */
export function previewName(template: string, format: SyslogFormat, now: Date, kind: IngestKind = "syslog"): string {
  const fecha = `${now.getFullYear()}${p2(now.getMonth() + 1)}${p2(now.getDate())}`;
  const hora = `${p2(now.getHours())}${p2(now.getMinutes())}${p2(now.getSeconds())}`;
  const base = (template.trim() || DEFAULT_TEMPLATES[kind]).replaceAll("{fecha}", fecha).replaceAll("{hora}", hora).replaceAll("{origen}", "10.0.0.9");
  return base + (format === "jsonl" ? ".jsonl" : ".log");
}

// Campo que nombra el error de inicio del núcleo (textos de internal/diag/{ingest,syslogd}, los mismos en traps y flujos); null si no nombra ninguno.
const FIELD_PATTERNS: [RegExp, OptKey][] = [
  [/tasa por origen/, "ratePerSource"], [/ráfaga por origen/, "burstPerSource"], [/tasa global/, "rateGlobal"], [/ráfaga global/, "burstGlobal"],
  [/la cola/, "queueSize"], [/tamaño de rotación/, "rotateMb"], [/rotación por tiempo/, "rotateMinutes"], [/máximo de archivos/, "maxFiles"],
  [/plantilla/, "nameTemplate"], [/formato ".*" no soportado/, "format"], [/dirección (de escucha )?inválida|puerto|el host debe/, "addr"],
];
export const mapStartError = (msg: string): OptKey | null => FIELD_PATTERNS.find(([re]) => re.test(msg))?.[1] ?? null;

const CORE_FIELDS: Record<string, OptKey> = {
  rate_per_source: "ratePerSource", burst_per_source: "burstPerSource", rate_global: "rateGlobal", burst_global: "burstGlobal", queue_size: "queueSize",
  rotate_mb: "rotateMb", rotate_minutes: "rotateMinutes", max_files: "maxFiles", name_template: "nameTemplate", format: "format", addr: "addr",
};
const TPL_PROBLEMS = { len: "tplLen", need: "tplNeed", tokens: "tplTokens", dots: "tplDots" } as const;
type Tr = (k: Key, v?: Record<string, string | number>) => string;

/** Campo del formulario y texto para un `ingest.invalid` del núcleo (por metadata); texto "" = usar el del núcleo; null si no es ese motivo o el campo no está en el formulario. */
export function coreFieldError(info: ErrInfo, t: Tr): [OptKey, string] | null {
  const m = info.metadata;
  const k = info.reason === "ingest.invalid" ? CORE_FIELDS[m.field] : undefined;
  if (!k) return null;
  if (k === "nameTemplate") {
    const p = m.template_problem;
    return [k, p === "chars" ? t("syslog.err.tplCh", { ch: m.ch ?? "" }) : p in TPL_PROBLEMS ? t(`syslog.err.${TPL_PROBLEMS[p as keyof typeof TPL_PROBLEMS]}`) : t("syslog.err.coreValue", { value: m.value ?? "" })];
  }
  if (k === "format") return [k, t("syslog.err.coreValue", { value: m.value ?? "" })];
  if (k === "addr") return [k, ""]; // el texto del núcleo dice qué hacer (p. ej. puerto privilegiado → uno alto) y ya viene en el idioma pedido
  return [k, t("syslog.err.range", { lo: m.min, hi: m.max })];
}

// Textos que cambian según el receptor (unidades, a quién se refiere cada ayuda); el resto de las claves son `syslog.*` para los tres.
export type KindText = "opt.ratePerSource" | "opt.rateGlobal" | "opts.floodHint" | "opt.tokens" | "fmt.texto" | "fmt.crudo" | "fmt.jsonl"
  | "recv" | "file.none" | "drops" | "drops.top" | "drops.live" | "capped" | "cappedNoSave";
export const kindKey = (kind: IngestKind, name: KindText) => `${kind}.${name}` as Key;
