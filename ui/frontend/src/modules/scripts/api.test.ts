import { describe, expect, it, vi } from "vitest";
import { scriptsWails } from "./api";
import { FAVORITES_ID, MAX_PINNED } from "./api";
import { fakeScripts, sampleScripts } from "./fake";

describe("scripts api", () => {
  it("llama al puente con el nombre y los argumentos de cada método", async () => {
    const call = vi.fn(async (..._a: unknown[]) => undefined);
    const api = scriptsWails(call as never);
    await api.listScripts({ text: "ospf" });
    await api.listScripts();
    await api.getScript("lib-l2-stp");
    await api.saveScript({ name: "N", tech: "l2", platform: "ios-xe", description: "", commands: ["show clock"], tags: [] });
    await api.deleteScript("x");
    await api.setScriptFavorite("x", true);
    await api.duplicateScript("x");
    await api.exportScripts(["a", "b"], "/tmp/s.json", true);
    await api.previewScriptsImport("/tmp/s.json");
    await api.applyScriptsImport("tok", [{ scriptId: "a", action: "omitir" }]);
    const nombres = call.mock.calls.map((c) => c[0]);
    expect(nombres).toEqual(["ListScripts", "ListScripts", "GetScript", "SaveScript", "DeleteScript", "SetScriptFavorite", "DuplicateScript", "ExportScripts", "PreviewScriptsImport", "ApplyScriptsImport"]);
    expect(call.mock.calls[0][1]).toEqual({ tech: "", platform: "", tag: "", text: "ospf", onlyFavorites: false });
    expect(call.mock.calls[1][1]).toEqual({ tech: "", platform: "", tag: "", text: "", onlyFavorites: false });
    expect(call.mock.calls[3][1]).toMatchObject({ id: "", name: "N" });
    expect(call.mock.calls[7].slice(1)).toEqual([["a", "b"], "/tmp/s.json", true]);
    expect(call.mock.calls[9].slice(1)).toEqual(["tok", [{ scriptId: "a", action: "omitir" }]]);
  });

  it("el doble respeta las reglas del núcleo: la biblioteca no se edita y duplicar copia como usuario", async () => {
    const f = fakeScripts();
    expect((await f.listScripts()).length).toBe(sampleScripts.length);
    expect((await f.listScripts({ text: "OSPF NEIGHBOR" })).map((s) => s.name)).toEqual(["Mi OSPF"]);
    await expect(f.saveScript({ id: "lib-l2-stp", name: "x", tech: "l2", platform: "ios-xe", description: "", commands: ["show clock"], tags: [] })).rejects.toThrow();
    await expect(f.deleteScript("lib-l2-stp")).rejects.toThrow();
    const copia = await f.duplicateScript("lib-l2-stp");
    expect(copia.origin).toBe("usuario");
    expect(copia.name).toBe("L2 · STP (copia)");
    await f.setScriptFavorite("lib-l2-stp", true);
    expect((await f.listScripts({ onlyFavorites: true })).map((s) => s.id)).toEqual(["lib-l2-stp"]);
  });

  it("el doble de import exige una decisión por conflicto", async () => {
    const f = fakeScripts();
    const p = await f.previewScriptsImport("/tmp/s.json");
    const conflicto = p.items.find((i) => i.state === "conflicto_nombre")!;
    await expect(f.applyScriptsImport(p.token, [])).rejects.toThrow();
    const r = await f.applyScriptsImport(p.token, [{ scriptId: conflicto.script.id, action: "renombrar" }]);
    expect(r).toMatchObject({ created: 1, renamed: 1, replaced: 0 });
  });

  it("las colecciones llaman al puente con el nombre y los argumentos de cada método", async () => {
    const call = vi.fn(async (..._a: unknown[]) => undefined);
    const api = scriptsWails(call as never);
    await api.listCollections();
    await api.getCollection("c");
    await api.saveCollection({ name: "N" });
    await api.saveCollection({ id: "c", name: "M", description: "d" });
    await api.deleteCollection("c");
    await api.reorderCollections(["c", FAVORITES_ID]);
    await api.setCollectionScripts("c", ["a", "lib-b"]);
    await api.setScriptPinned("a", true);
    await api.listPinnedScripts();
    await api.reorderPinnedScripts(["a"]);
    await api.exportCollections(["c"], "/tmp/c.json", false);
    await api.previewCollectionsImport("/tmp/c.json");
    await api.applyCollectionsImport("tok", [{ scriptId: "a", action: "omitir" }], [{ scriptId: "c", action: "renombrar" }]);
    await api.importTemplate("colecciones");
    await api.importFormat("scripts");
    expect(call.mock.calls.map((c) => c[0])).toEqual(["ListCollections", "GetCollection", "SaveCollection", "SaveCollection", "DeleteCollection", "ReorderCollections", "SetCollectionScripts",
      "SetScriptPinned", "ListPinnedScripts", "ReorderPinnedScripts", "ExportCollections", "PreviewCollectionsImport", "ApplyCollectionsImport", "ImportTemplate", "ImportFormat"]);
    expect(call.mock.calls[13].slice(1)).toEqual(["colecciones"]);
    expect(call.mock.calls[14].slice(1)).toEqual(["scripts"]);
    expect(call.mock.calls[2].slice(1)).toEqual(["", "N", ""]);
    expect(call.mock.calls[3].slice(1)).toEqual(["c", "M", "d"]);
    expect(call.mock.calls[6].slice(1)).toEqual(["c", ["a", "lib-b"]]);
    expect(call.mock.calls[7].slice(1)).toEqual(["a", true]);
    expect(call.mock.calls[12].slice(1)).toEqual(["tok", [{ scriptId: "a", action: "omitir" }], [{ scriptId: "c", action: "renombrar" }]]);
  });

  it("el doble de colecciones respeta las reglas del núcleo: favoritos fijo, referencias sin copiar y borrar un script lo quita de todas", async () => {
    const f = fakeScripts();
    const a = sampleScripts[2].id;
    expect((await f.listCollections()).map((c) => c.id)).toEqual([FAVORITES_ID]);
    await expect(f.deleteCollection(FAVORITES_ID)).rejects.toThrow();
    await expect(f.saveCollection({ id: FAVORITES_ID, name: "Otro" })).rejects.toThrow();
    // setScriptFavorite es el atajo: agrega a «favoritos» y el script lo refleja
    await f.setScriptFavorite(a, true);
    expect((await f.getCollection(FAVORITES_ID)).scriptIds).toEqual([a]);
    expect((await f.getScript(a)).collections).toEqual([FAVORITES_ID]);
    const c = await f.saveCollection({ name: "Redes" });
    await expect(f.saveCollection({ name: "REDES" })).rejects.toThrow();
    const n0 = (await f.listScripts()).length;
    await f.setCollectionScripts(c.id, ["lib-l2-stp", a]);
    expect((await f.listScripts()).length).toBe(n0); // la biblioteca se referencia, no se copia
    expect((await f.getScript(a)).collections).toEqual([FAVORITES_ID, c.id]);
    await expect(f.setCollectionScripts(c.id, [a, a])).rejects.toThrow();
    await expect(f.setCollectionScripts(c.id, ["no-existe"])).rejects.toThrow();
    await f.deleteScript(a);
    expect((await f.getCollection(c.id)).scriptIds).toEqual(["lib-l2-stp"]);
    expect((await f.getCollection(FAVORITES_ID)).scriptIds).toEqual([]);
    await expect(f.reorderCollections([c.id])).rejects.toThrow();
    await f.reorderCollections([c.id, FAVORITES_ID]);
    expect((await f.listCollections()).map((x) => x.id)).toEqual([c.id, FAVORITES_ID]);
  });

  it("el doble de fijados topa en 5, guarda el orden y desfija al borrar", async () => {
    const f = fakeScripts();
    const ids: string[] = [];
    for (let i = 0; i < MAX_PINNED + 1; i++) ids.push((await f.saveScript({ name: `P${i}`, tech: "l2", platform: "ios", description: "", commands: ["show clock"], tags: [] })).id);
    for (const id of ids.slice(0, MAX_PINNED)) await f.setScriptPinned(id, true);
    await f.setScriptPinned(ids[0], true); // ya fijado: no cuenta
    await expect(f.setScriptPinned(ids[MAX_PINNED], true)).rejects.toThrow(/5/);
    await f.reorderPinnedScripts([...ids.slice(0, MAX_PINNED)].reverse());
    expect((await f.listPinnedScripts()).map((s) => s.id)).toEqual([...ids.slice(0, MAX_PINNED)].reverse());
    await expect(f.reorderPinnedScripts([ids[0]])).rejects.toThrow();
    await f.deleteScript(ids[1]);
    await f.setScriptPinned(ids[MAX_PINNED], true);
    expect((await f.listPinnedScripts()).length).toBe(MAX_PINNED);
    expect((await f.getScript(ids[MAX_PINNED])).pinned).toBe(true);
  });

  it("el doble de import de colecciones exige una decisión por conflicto y «favoritos» solo se fusiona u omite", async () => {
    const f = fakeScripts();
    const p = await f.previewCollectionsImport("/tmp/c.json");
    const conflicto = p.collections.find((i) => i.state === "conflicto_nombre")!;
    const fusion = p.collections.find((i) => i.state === "fusionar")!;
    expect(fusion.collection.id).toBe(FAVORITES_ID);
    expect(p.warnings.length).toBeGreaterThan(0);
    await expect(f.applyCollectionsImport(p.token, [], [])).rejects.toThrow();
    await expect(f.applyCollectionsImport(p.token, [], [{ scriptId: conflicto.collection.id, action: "renombrar" }, { scriptId: FAVORITES_ID, action: "reemplazar" }])).rejects.toThrow();
    const r = await f.applyCollectionsImport(p.token, [], [{ scriptId: conflicto.collection.id, action: "renombrar" }]);
    expect(r).toMatchObject({ collectionsCreated: 1, collectionsRenamed: 1, collectionsMerged: 1 });
  });

  it("el doble de plantilla y formato responde por tipo y marca el sha256 como opcional", async () => {
    const f = fakeScripts();
    expect(JSON.parse(await f.importTemplate("colecciones")).formato).toBe("macuahuitl-colecciones");
    const campos = await f.importFormat("scripts");
    expect(campos.find((c) => c.name === "sha256")?.required).toBe(false);
    expect(campos.find((c) => c.name === "formato")?.required).toBe(true);
    expect((await f.previewScriptsImport("/tmp/s.json")).warnings).toEqual(["archivo sin suma de verificación"]);
  });
});
