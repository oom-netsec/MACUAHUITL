// Clasificación de salidas tipo terminal. Las reglas y las paletas son las mismas
// JSON que usa Go (internal/termcolor), así la UI y mctl colorean igual.
import rules from "../../../../internal/termcolor/rules.json";
import palettes from "../../../../internal/termcolor/palettes.json";

export interface Span { start: number; end: number; cat: string }
export type Palette = (typeof palettes)[number];
export const PALETTES: Palette[] = palettes;
export const DEFAULT_PALETTE = "classic";
export const CATEGORIES = ["ok", "bad", "warn", "info", "addr", "iface", "prompt", "uprompt", "num", "dim", "kw", "str", "ospf", "eigrp", "bgp", "rip", "static", "conn", "cred", "acl", "svc", "ver"] as const;

// Tope por línea: una línea enorme (volcado binario) no debe costar regex.
export const MAX_LINE = 2000;
// Solo las últimas líneas se resaltan; el resto se pinta como texto plano.
export const MAX_HIGHLIGHT_LINES = 2000;

const RE = new RegExp(rules.map((r) => `(${r.re})`).join("|"), "gi");

function sevCat(s: string): string {
  const d = /-([0-7])-/.exec(s)?.[1];
  if (d === undefined) return "dim";
  return d <= "3" ? "bad" : d === "4" ? "warn" : d === "5" ? "info" : "dim";
}

export function classify(line: string): Span[] {
  if (line.length > MAX_LINE) return [];
  const out: Span[] = [];
  for (const m of line.matchAll(RE)) {
    if (m[0] === "") continue;
    const g = m.findIndex((x, i) => i > 0 && x !== undefined) - 1;
    let cat = rules[g].cat;
    if (cat === "mnem") cat = sevCat(m[0]);
    out.push({ start: m.index, end: m.index + m[0].length, cat });
  }
  return out;
}
