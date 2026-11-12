// El camino de Flota es un árbol (parent -1 es la raíz; ECMP lo ramifica). Aquí se aplana a cadenas raíz → hoja.
import type { PathHop } from "./api";

export function chains(hops: PathHop[]): PathHop[][] {
  const byId = new Map(hops.map((h) => [h.id, h]));
  const parents = new Set(hops.map((h) => h.parent));
  return hops.filter((h) => !parents.has(h.id)).map((leaf) => {
    const c: PathHop[] = [];
    for (let h: PathHop | undefined = leaf; h && c.length <= hops.length; h = byId.get(h.parent)) c.unshift(h);
    return c;
  });
}

// Cómo se llegó a un salto desde su padre: interfaz de salida, VLAN, siguiente salto y switches L2 por el medio.
export function linkLabel(h: PathHop) {
  const s = h.segment;
  return { iface: h.out_if || s?.interface || "", vlan: s?.vlan ?? "", via: h.via ?? "", l2: (s?.l2 ?? []).map((x) => `${x.device} ${x.port}`) };
}
