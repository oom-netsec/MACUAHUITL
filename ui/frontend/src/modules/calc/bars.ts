// Lectura de las tablas del núcleo para las barras de Subred y VLSM. Con las claves de la fase 30b (titleKey, rowLabels,
// columns, notesStructured) no depende del idioma; sin ellas (núcleo anterior) lee las etiquetas en español de internal/calc.
import type { CalcResult } from "./api";

export interface SubnetFacts { title: string; network: string; broadcast?: string; first: string; last: string; total: number; usable: number; usableRaw: string }
export interface VlsmFacts { parent: string; parentLen: number; allocations: { name: string; prefix: string }[]; free: string[] }

// Etiqueta en español -> nombre de la clave calc.row.*, para el camino sin claves.
const LEGACY_ROWS: Record<string, string> = { "Red": "network", "Broadcast": "broadcast", "Primera usable": "first_usable", "Última usable": "last_usable", "Direcciones": "addresses", "Hosts usables": "usable_hosts" };

export function subnetFacts(r: CalcResult): SubnetFacts | null {
  const t = r.tables[0];
  if (!t) return null;
  const keyed = !!t.titleKey && t.rowLabels?.length === t.rows.length;
  if (keyed ? t.titleKey !== "calc.title.subnet" : !t.title.startsWith("Subred ")) return null;
  const kv: Record<string, string> = {};
  t.rows.forEach((x, i) => { const k = keyed ? t.rowLabels![i].key.replace("calc.row.", "") : LEGACY_ROWS[x[0]]; if (k) kv[k] = x[x.length - 1]; });
  const total = Number(kv.addresses);
  if (!kv.network || !kv.first_usable || !kv.last_usable || !(total > 0)) return null;
  const title = keyed ? t.titleArgs?.prefix ?? "" : t.title.slice(7);
  return { title, network: kv.network, broadcast: kv.broadcast || undefined, first: kv.first_usable, last: kv.last_usable, total, usable: Number(kv.usable_hosts), usableRaw: kv.usable_hosts };
}

export function vlsmFacts(r: CalcResult): VlsmFacts | null {
  const t = r.tables[0];
  if (!t) return null;
  const keyed = !!t.titleKey && t.columns?.length === t.head.length;
  if (keyed ? t.titleKey !== "calc.title.vlsm" : !t.title.startsWith("VLSM sobre ")) return null;
  const parent = keyed ? t.titleArgs?.parent ?? "" : t.title.slice(11);
  const len = /\/(\d+)$/.exec(parent);
  const col = (key: string, legacy: string) => (keyed ? t.columns!.findIndex((c) => c.key === key) : t.head.indexOf(legacy));
  const ci = col("calc.col.prefix", "Prefijo"), ni = col("calc.col.name", "Nombre");
  if (!len || ci < 0 || ni < 0) return null;
  const freeText = r.notesStructured?.find((n) => n.key === "calc.note.vlsm_free")?.args?.free
    ?? (r.notes.find((n) => n.startsWith("Espacio libre: ")) ?? "").slice(15);
  const allocations = t.rows.map((x) => ({ name: x[ni] || x[ci], prefix: x[ci] }));
  return { parent, parentLen: Number(len[1]), allocations, free: freeText.split(/\s+/).filter(Boolean) };
}
