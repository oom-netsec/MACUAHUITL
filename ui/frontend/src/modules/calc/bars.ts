// Lectura de las tablas del núcleo para las barras de Subred y VLSM. Las etiquetas ("Red", "Primera usable"…) son
// las que imprime internal/calc en español; si no están, no hay barra y el resultado se ve igual en su tabla.
import type { CalcResult } from "./api";

export interface SubnetFacts { title: string; network: string; broadcast?: string; first: string; last: string; total: number; usable: number; usableRaw: string }
export interface VlsmFacts { parent: string; parentLen: number; allocations: { name: string; prefix: string }[]; free: string[] }

export function subnetFacts(r: CalcResult): SubnetFacts | null {
  const t = r.tables[0];
  if (!t?.title.startsWith("Subred ")) return null;
  const kv = Object.fromEntries(t.rows.map((x) => [x[0], x[1]]));
  const total = Number(kv["Direcciones"]);
  if (!kv["Red"] || !kv["Primera usable"] || !kv["Última usable"] || !(total > 0)) return null;
  return { title: t.title.slice(7), network: kv["Red"], broadcast: kv["Broadcast"] || undefined, first: kv["Primera usable"], last: kv["Última usable"], total, usable: Number(kv["Hosts usables"]), usableRaw: kv["Hosts usables"] };
}

export function vlsmFacts(r: CalcResult): VlsmFacts | null {
  const t = r.tables[0];
  if (!t?.title.startsWith("VLSM sobre ")) return null;
  const len = /\/(\d+)$/.exec(t.title);
  const ci = t.head.indexOf("Prefijo"), ni = t.head.indexOf("Nombre");
  if (!len || ci < 0 || ni < 0) return null;
  const free = (r.notes.find((n) => n.startsWith("Espacio libre: ")) ?? "").slice(15).split(/\s+/).filter(Boolean);
  const allocations = t.rows.map((x) => ({ name: x[ni] || x[ci], prefix: x[ci] }));
  return { parent: t.title.slice(11), parentLen: Number(len[1]), allocations, free };
}
