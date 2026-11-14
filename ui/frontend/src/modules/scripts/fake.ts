// Doble del módulo para pruebas y para trabajar la vista sin núcleo. Guarda en memoria y respeta las reglas
// básicas del núcleo: la biblioteca no se edita ni se borra, "duplicar" copia como usuario, los favoritos valen en ambos.
import { vi } from "vitest";
import { FAVORITES_ID, MAX_PINNED } from "./api";
import type { Collection, CollectionsImportPreview, ImportDecision, ImportFormatField, ImportKind, ImportItem, ImportPreview, ScriptFilter, ScriptItem } from "./api";

const t0 = Date.UTC(2026, 10, 7, 12, 0, 0);

const script = (p: Partial<ScriptItem> & Pick<ScriptItem, "id" | "name" | "commands">): ScriptItem => ({
  tech: "l2", platform: "ios-xe", description: "", tags: [], origin: "usuario", createdMs: t0, updatedMs: t0, readOnly: false, favorite: false, pinned: false, collections: [], ...p,
});

export const sampleScripts: ScriptItem[] = [
  script({ id: "lib-l2-stp", name: "L2 · STP", origin: "biblioteca", readOnly: true, commands: ["show spanning-tree summary", "show spanning-tree root"] }),
  script({ id: "lib-cfg-vlan-acceso", name: "Config · VLAN y puerto de acceso", origin: "biblioteca", commands: ["configure terminal", "vlan 10", "end"], tags: ["vlan"] }),
  script({ id: "a".repeat(32), name: "Mi OSPF", tech: "l3", readOnly: true, commands: ["show ip ospf neighbor"], tags: ["ospf"] }),
];

// Archivo de ejemplo para el import: uno nuevo, uno igual y un conflicto de nombre.
export const sampleImport: ImportPreview = {
  token: "token-1",
  expiresMs: t0 + 600_000,
  warnings: ["archivo sin suma de verificación"],
  items: [
    { script: script({ id: "b".repeat(32), name: "Nuevo", commands: ["show clock"] }), state: "nuevo", conflictsWith: "" },
    { script: sampleScripts[2], state: "igual", conflictsWith: sampleScripts[2].id },
    { script: script({ id: "c".repeat(32), name: "Mi OSPF", commands: ["show ip route"] }), state: "conflicto_nombre", conflictsWith: sampleScripts[2].id },
  ],
};

// Archivo de colecciones de ejemplo: una nueva, una igual, un conflicto de nombre, favoritos por fusionar y un aviso por un «lib-*» ajeno.
const col = (p: Partial<Collection> & Pick<Collection, "id" | "name">): Collection => ({ description: "", order: 0, scriptIds: [], hiddenScriptIds: [], createdMs: t0, updatedMs: t0, ...p });
export const sampleCollectionsImport: CollectionsImportPreview = {
  token: "token-c1",
  expiresMs: t0 + 600_000,
  collections: [
    { collection: col({ id: "d".repeat(32), name: "Nueva", scriptIds: ["b".repeat(32), "lib-l2-stp"] }), state: "nueva", conflictsWith: "" },
    { collection: col({ id: "e".repeat(32), name: "Igual" }), state: "igual", conflictsWith: "e".repeat(32) },
    { collection: col({ id: "f".repeat(32), name: "Redes", scriptIds: ["a".repeat(32)] }), state: "conflicto_nombre", conflictsWith: "1".repeat(32) },
    { collection: col({ id: FAVORITES_ID, name: "Favoritos", scriptIds: ["lib-l2-stp"] }), state: "fusionar", conflictsWith: FAVORITES_ID },
  ],
  scripts: [{ script: script({ id: "b".repeat(32), name: "Nuevo", commands: ["show clock"] }), state: "nuevo", conflictsWith: "" }],
  warnings: ["colección \"Nueva\": el script lib-de-otra-version no está en la biblioteca local; se omitirá"],
};

export function fakeScripts(initial: ScriptItem[] = sampleScripts) {
  let all = initial.map((s) => ({ ...s }));
  let n = 0;
  // Colecciones y fijados: favorite, pinned y collections de cada script se calculan de aquí, como en el núcleo.
  let cols: Collection[] = [{ id: FAVORITES_ID, name: "Favoritos", description: "", order: 0, hiddenScriptIds: [], scriptIds: initial.filter((s) => s.favorite).map((s) => s.id), createdMs: t0, updatedMs: t0 }];
  let pins: string[] = initial.filter((s) => s.pinned).map((s) => s.id);
  const view = (s: ScriptItem): ScriptItem => ({ ...s, favorite: cols[0] && cols.find((c) => c.id === FAVORITES_ID)!.scriptIds.includes(s.id), pinned: pins.includes(s.id), collections: cols.filter((c) => c.scriptIds.includes(s.id)).map((c) => c.id) });
  const find = (id: string) => {
    const s = all.find((x) => x.id === id);
    if (!s) throw new Error(`no hay un script ${id}`);
    return s;
  };
  const findCol = (id: string) => {
    const c = cols.find((x) => x.id === id);
    if (!c) throw new Error(`no hay una colección ${id}`);
    return c;
  };
  const setCols = (next: Collection[]) => { cols = next.map((c, i) => ({ ...c, order: i })); };
  const sameSet = (a: string[], b: string[]) => a.length === b.length && new Set(b).size === b.length && b.every((x) => a.includes(x));
  const matches = (s: ScriptItem, f: ScriptFilter) => {
    const text = (f.text ?? "").toLowerCase();
    return (!f.tech || s.tech === f.tech) && (!f.platform || s.platform === f.platform || s.platform === "cualquiera") && (!f.tag || s.tags.includes(f.tag)) &&
      (!f.onlyFavorites || view(s).favorite) && (!text || [s.name, s.description, ...s.tags, ...s.commands].join("\n").toLowerCase().includes(text));
  };
  return {
    listScripts: vi.fn(async (f: ScriptFilter = {}) => all.filter((s) => matches(s, f)).sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase())).map(view)),
    getScript: vi.fn(async (id: string) => view(find(id))),
    saveScript: vi.fn(async (d: Parameters<import("./api").ScriptsAPI["saveScript"]>[0]) => {
      if (d.id?.startsWith("lib-")) throw new Error("los scripts de la biblioteca no se editan");
      if (all.some((s) => s.origin === "usuario" && s.id !== d.id && s.name.toLowerCase() === d.name.trim().toLowerCase())) throw new Error(`ya hay un script llamado "${d.name}"`);
      const old = d.id ? find(d.id) : undefined;
      const s = script({ ...d, id: d.id ?? String(++n).padStart(32, "0"), name: d.name.trim(), createdMs: old?.createdMs ?? t0, updatedMs: t0, favorite: old?.favorite ?? false,
        readOnly: d.commands.every((c) => /^\s*(!|show |ping |traceroute )/.test(c)) });
      all = old ? all.map((x) => (x.id === s.id ? s : x)) : [...all, s];
      return view(s);
    }),
    deleteScript: vi.fn(async (id: string) => {
      if (id.startsWith("lib-")) throw new Error("los scripts de la biblioteca no se borran");
      find(id);
      all = all.filter((s) => s.id !== id);
      cols = cols.map((c) => ({ ...c, scriptIds: c.scriptIds.filter((x) => x !== id) }));
      pins = pins.filter((x) => x !== id);
    }),
    setScriptFavorite: vi.fn(async (id: string, favorite: boolean) => {
      find(id);
      const fav = findCol(FAVORITES_ID);
      fav.scriptIds = favorite ? (fav.scriptIds.includes(id) ? fav.scriptIds : [...fav.scriptIds, id]) : fav.scriptIds.filter((x) => x !== id);
    }),
    duplicateScript: vi.fn(async (id: string) => {
      const src = find(id);
      const copy = { ...src, id: String(++n).padStart(32, "0"), name: `${src.name} (copia)`, origin: "usuario" as const };
      all = [...all, copy];
      return view(copy);
    }),
    exportScripts: vi.fn(async (ids: string[], _path: string, _overwrite: boolean) => { ids.forEach(find); return ids.length; }),
    previewScriptsImport: vi.fn(async (_path: string) => sampleImport),
    applyScriptsImport: vi.fn(async (_token: string, decisions: ImportDecision[]) => {
      const need = sampleImport.items.filter((i: ImportItem) => i.state.startsWith("conflicto"));
      if (need.some((i) => !decisions.some((d) => d.scriptId === i.script.id))) throw new Error("falta la decisión de un conflicto");
      const skipped = decisions.filter((d) => d.action === "omitir").length + 1; // el «igual» se omite solo
      return { created: 1, replaced: decisions.filter((d) => d.action === "reemplazar").length, renamed: decisions.filter((d) => d.action === "renombrar").length, skipped };
    }),
    listCollections: vi.fn(async () => cols.map((c) => ({ ...c, scriptIds: [...c.scriptIds] }))),
    getCollection: vi.fn(async (id: string) => ({ ...findCol(id), scriptIds: [...findCol(id).scriptIds] })),
    saveCollection: vi.fn(async (d: { id?: string; name: string; description?: string }) => {
      const name = d.name.trim();
      if (!name || name.length > 64) throw new Error("el nombre va de 1 a 64 caracteres");
      if (cols.some((c) => c.id !== d.id && c.name.toLowerCase() === name.toLowerCase())) throw new Error(`ya hay una colección llamada "${name}"`);
      if (d.id === FAVORITES_ID && name !== "Favoritos") throw new Error("la colección favoritos no se renombra");
      if (d.id) {
        const c = findCol(d.id);
        c.name = name;
        c.description = d.description ?? "";
        c.updatedMs = t0;
        return { ...c, scriptIds: [...c.scriptIds] };
      }
      const c: Collection = { id: `c${String(++n).padStart(31, "0")}`, name, description: d.description ?? "", order: cols.length, scriptIds: [], hiddenScriptIds: [], createdMs: t0, updatedMs: t0 };
      cols = [...cols, c];
      return { ...c };
    }),
    deleteCollection: vi.fn(async (id: string) => {
      if (id === FAVORITES_ID) throw new Error("la colección favoritos no se borra");
      findCol(id);
      setCols(cols.filter((c) => c.id !== id));
    }),
    reorderCollections: vi.fn(async (ids: string[]) => {
      if (!sameSet(cols.map((c) => c.id), ids)) throw new Error("el orden debe traer cada colección una sola vez");
      setCols(ids.map(findCol));
    }),
    setCollectionScripts: vi.fn(async (id: string, scriptIds: string[]) => {
      const c = findCol(id);
      if (new Set(scriptIds).size !== scriptIds.length) throw new Error("hay scripts repetidos");
      scriptIds.forEach(find);
      c.scriptIds = [...scriptIds];
      c.updatedMs = t0;
      return { ...c, scriptIds: [...c.scriptIds] };
    }),
    setScriptPinned: vi.fn(async (id: string, pinned: boolean) => {
      find(id);
      if (pinned && !pins.includes(id)) {
        if (pins.length >= MAX_PINNED) throw new Error(`rpc error: code = FailedPrecondition desc = ya hay ${MAX_PINNED} scripts fijados, el máximo; desfija uno antes`);
        pins = [...pins, id];
      } else if (!pinned) pins = pins.filter((x) => x !== id);
    }),
    listPinnedScripts: vi.fn(async () => pins.map((id) => view(find(id)))),
    reorderPinnedScripts: vi.fn(async (ids: string[]) => {
      if (!sameSet(pins, ids)) throw new Error("el orden debe traer cada script fijado una sola vez");
      pins = [...ids];
    }),
    exportCollections: vi.fn(async (ids: string[], _path: string, _overwrite: boolean) => {
      const sel = ids.map(findCol);
      return { collections: sel.length, scripts: new Set(sel.flatMap((c) => c.scriptIds).filter((x) => !x.startsWith("lib-"))).size };
    }),
    previewCollectionsImport: vi.fn(async (_path: string) => sampleCollectionsImport),
    importTemplate: vi.fn(async (kind: ImportKind) => JSON.stringify({ formato: `macuahuitl-${kind}`, version: 1, [kind]: [] }, null, 2)),
    importFormat: vi.fn(async (kind: ImportKind): Promise<ImportFormatField[]> => [
      { name: "formato", type: "texto", required: true, example: JSON.stringify(`macuahuitl-${kind}`), description: "Tipo de archivo" },
      { name: "version", type: "entero", required: true, example: "1", description: "Versión del formato" },
      { name: "sha256", type: "texto", required: false, example: JSON.stringify("0".repeat(64)), description: "Suma opcional" },
    ]),
    applyCollectionsImport: vi.fn(async (_token: string, scriptDecisions: ImportDecision[], collectionDecisions: ImportDecision[]) => {
      const need = sampleCollectionsImport.collections.filter((i) => i.state.startsWith("conflicto"));
      if (need.some((i) => !collectionDecisions.some((d) => d.scriptId === i.collection.id))) throw new Error("falta la decisión de un conflicto");
      if (collectionDecisions.some((d) => d.scriptId === FAVORITES_ID && d.action !== "omitir")) throw new Error("favoritos solo se fusiona u omite");
      const omit = collectionDecisions.filter((d) => d.action === "omitir").length;
      return {
        scriptsCreated: sampleCollectionsImport.scripts.filter((i) => i.state === "nuevo").length, scriptsReplaced: scriptDecisions.filter((d) => d.action === "reemplazar").length,
        scriptsRenamed: scriptDecisions.filter((d) => d.action === "renombrar").length, scriptsSkipped: scriptDecisions.filter((d) => d.action === "omitir").length,
        collectionsCreated: 1, collectionsReplaced: collectionDecisions.filter((d) => d.action === "reemplazar").length, collectionsRenamed: collectionDecisions.filter((d) => d.action === "renombrar").length,
        collectionsMerged: 1, collectionsSkipped: omit + 1, // la «igual» se omite sola
        warnings: sampleCollectionsImport.warnings,
      };
    }),
  };
}
