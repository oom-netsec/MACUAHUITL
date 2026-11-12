// Lógica del formulario genérico de plantillas: sin React, para probarla sola. La validación del cliente es solo ayuda; manda la del núcleo.
import { countInterfaces, decimalOk, interfaceOk, intOk, ipv4Ok, maskOk, vlanOk } from "../../lib/validate";
import type { SnippetField, SnippetTemplate } from "./api";

export const TECH_ORDER = ["l2", "l3", "gestion", "seguridad", "qos", "etherchannel"] as const;
export const MAX_PORTS = 48;

const norm = (s: string) => s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();

// Agrupa por tecnología en el orden del catálogo; una tecnología desconocida va al final. `name` ya viene traducido.
export function groupTemplates(list: SnippetTemplate[], q: string, nameOf: (t: SnippetTemplate) => string): [string, SnippetTemplate[]][] {
  const words = norm(q).split(/\s+/).filter(Boolean);
  const hit = (t: SnippetTemplate) => { const hay = norm(`${nameOf(t)} ${t.name} ${t.id}`); return words.every((w) => hay.includes(w)); };
  const m = new Map<string, SnippetTemplate[]>();
  for (const t of list.filter(hit)) m.set(t.tech, [...(m.get(t.tech) ?? []), t]);
  const rank = (k: string) => { const i = (TECH_ORDER as readonly string[]).indexOf(k); return i < 0 ? TECH_ORDER.length : i; };
  return [...m].sort(([a], [b]) => rank(a) - rank(b));
}

// Solo defaultValue prellena. Una `choice` obligatoria sin valor sugerido empieza en «— elige —» y no deja planear hasta que se elija.
export function initialValues(t: SnippetTemplate): Record<string, string> {
  return Object.fromEntries(t.fields.map((f) => [f.name, f.defaultValue ?? ""]));
}

export type Problem = { key: "snippets.err.int" | "snippets.err.decimal" | "snippets.err.ipv4" | "snippets.err.mask" | "snippets.err.iface" | "snippets.err.ifaces" | "snippets.err.ports" | "snippets.err.vlan" | "snippets.err.pattern" | "snippets.err.len" | "snippets.err.choice"; vars?: Record<string, string | number> };

// Problema de un valor no vacío, o null. Vacío nunca es problema aquí: lo obligatorio se mira aparte.
// Se juzga el valor recortado, igual que lo que viaja (valuesToSend); el secreto va tal cual.
export function problemOf(f: SnippetField, raw: string): Problem | null {
  const v = f.type === "secret" ? raw : raw.trim();
  if (v === "") return null;
  const min = f.min ?? 0, max = f.max ?? 0;
  const range = { min, max: max || "∞" };
  switch (f.type) {
    case "int": return intOk(v, min, max) ? null : { key: "snippets.err.int", vars: range };
    case "decimal": return decimalOk(v, min, max) ? null : { key: "snippets.err.decimal", vars: range };
    case "vlan_id": return vlanOk(v, min, max) ? null : { key: "snippets.err.vlan", vars: { min: Math.max(min, 1), max: max > 0 ? Math.min(max, 4094) : 4094 } };
    case "ipv4": return ipv4Ok(v) ? null : { key: "snippets.err.ipv4" };
    case "ipv4_mask": return maskOk(v) ? null : { key: "snippets.err.mask" };
    case "interface": return interfaceOk(v) ? null : { key: "snippets.err.iface" };
    case "interfaces": {
      const n = countInterfaces(v);
      if (n === null) return { key: "snippets.err.ifaces" };
      return n > MAX_PORTS ? { key: "snippets.err.ports", vars: { max: MAX_PORTS, n } } : null;
    }
    case "choice": return f.choices?.includes(v) ? null : { key: "snippets.err.choice" };
    case "text": {
      const hi = f.max || 200;
      if (v.length < min || v.length > hi) return { key: "snippets.err.len", vars: { min, max: hi } };
      if (f.pattern) { try { if (!new RegExp(f.pattern).test(v)) return { key: "snippets.err.pattern" }; } catch { /* patrón de Go que JS no entiende: lo juzga el núcleo */ } }
      return null;
    }
    default: return null;
  }
}

// Lo que viaja: todo el formulario por nombre. Texto recortado (el núcleo rechaza espacios en los demás tipos); el secreto va tal cual.
// Un bool sin marcar viaja vacío salvo que tenga defaultValue: no hay forma de decir "false" sin que el núcleo lo haya sugerido.
export function valuesToSend(t: SnippetTemplate, values: Record<string, string>): Record<string, string> {
  return Object.fromEntries(t.fields.map((f) => {
    const v = values[f.name] ?? "";
    if (f.type === "secret") return [f.name, v];
    if (f.type === "bool") return [f.name, v === "true" ? "true" : f.defaultValue ? "false" : ""];
    return [f.name, v.trim()];
  }));
}

// Los problemas del cliente o lo obligatorio que falta: el botón de planear se apaga.
export const formReady = (t: SnippetTemplate, values: Record<string, string>) =>
  t.fields.every((f) => {
    const v = valuesToSend(t, values)[f.name];
    return (!f.required || f.type === "bool" || v !== "") && problemOf(f, v) === null;
  });

export interface CoreError { code: string; desc: string }
// «rpc error: code = X desc = Y» como lo entrega el puente; cualquier otro texto no trae código.
export function parseCoreError(e: unknown): CoreError {
  const m = e instanceof Error ? e.message : String(e);
  const r = /^rpc error: code = (\w+) desc = ([\s\S]*)$/.exec(m);
  return r ? { code: r[1], desc: r[2] } : { code: "", desc: m };
}

// El núcleo junta los problemas con «; » y cada uno dice «Etiqueta (nombre): motivo». Se asigna cada pieza al campo que nombra.
// Lo que no nombre un campo conocido queda en `rest` para mostrarlo como aviso.
export function mapInvalid(desc: string, fields: SnippetField[]): { byField: Record<string, string>; rest: string[] } {
  const byField: Record<string, string> = {};
  const rest: string[] = [];
  // «assist: valores del snippet inválidos: » precede a la primera pieza y la separaría de su campo.
  for (const piece of desc.replace(/^assist: [^:]+: /, "").split(/;\s+/).map((p) => p.trim()).filter(Boolean)) {
    const f = fields.find((x) => piece.includes(`(${x.name})`)) ?? fields.find((x) => piece.includes(`"${x.name}"`));
    if (!f) { rest.push(piece); continue; }
    const after = piece.indexOf(`(${f.name}):`);
    const text = after >= 0 ? piece.slice(after + f.name.length + 3).trim() : piece;
    byField[f.name] = byField[f.name] ? `${byField[f.name]}; ${text}` : text;
  }
  return { byField, rest };
}
