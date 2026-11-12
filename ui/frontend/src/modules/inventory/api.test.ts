import { describe, expect, it, vi } from "vitest";
import { inventoryWails } from "./api";
import { fakeInventory, sampleDevices } from "./fake";

describe("inventory api", () => {
  it("listDevices llama al puente con el filtro (vacío por omisión)", async () => {
    const call = vi.fn(async () => sampleDevices);
    const api = inventoryWails(call as never);
    await api.listDevices();
    await api.listDevices("core");
    expect(call).toHaveBeenNthCalledWith(1, "ListDevices", "");
    expect(call).toHaveBeenNthCalledWith(2, "ListDevices", "core");
  });
  it("el doble filtra como el núcleo y trae un equipo sin dirección y uno nunca visto", async () => {
    const f = fakeInventory();
    expect((await f.listDevices("sw-acc")).devices.map((d) => d.hostname)).toEqual(["SW-ACC1"]);
    const all = (await f.listDevices()).devices;
    expect(all.find((d) => d.address === "")?.sources).toEqual(["respaldos"]);
    expect(all.find((d) => d.lastSeenMs === 0)?.hostname).toBe("CAIDO");
  });
});

describe("libreta de hosts", () => {
  it("el contrato llama al puente con sus argumentos y rellena lo que falta", async () => {
    const call = vi.fn(async () => ({}));
    const api = inventoryWails(call as never);
    await api.listHosts();
    await api.listHosts({ query: "co", folder: "Lab", tag: "core" });
    await api.saveHost({ name: "N", address: "10.0.0.1", port: 0, platform: "", folder: "", tags: [], credentialId: "", notes: "" });
    await api.saveHost({ id: "x", name: "N", address: "10.0.0.1", port: 22, platform: "ios", folder: "", tags: ["a"], credentialId: "", notes: "" });
    await api.deleteHost("x");
    await api.exportHosts(["a"], "/tmp/h.json", true);
    await api.exportHosts([], "/tmp/h.txt", true, "csv");
    await api.previewHostsImport("/tmp/h.json");
    await api.previewHostsImport("/tmp/h.txt", "csv");
    await api.applyHostsImport("tok", [{ key: "10.0.0.1:22", action: "omitir" }]);
    await api.hostsImportTemplate("csv");
    await api.hostsImportFormat();
    const c = call.mock.calls as unknown as unknown[][];
    expect(c[0]).toEqual(["ListHosts", "", "", ""]);
    expect(c[1]).toEqual(["ListHosts", "co", "Lab", "core"]);
    expect(c[2][0]).toBe("SaveHost");
    expect(c[2][1]).toMatchObject({ id: "", credentialLabel: "", name: "N" });
    expect(c[3][1]).toMatchObject({ id: "x", tags: ["a"] });
    expect(c.slice(4)).toEqual([
      ["DeleteHost", "x"], ["ExportHosts", ["a"], "/tmp/h.json", true, ""], ["ExportHosts", [], "/tmp/h.txt", true, "csv"],
      ["PreviewHostsImport", "/tmp/h.json", ""], ["PreviewHostsImport", "/tmp/h.txt", "csv"],
      ["ApplyHostsImport", "tok", [{ key: "10.0.0.1:22", action: "omitir" }]], ["HostsImportTemplate", "csv"], ["HostsImportFormat"],
    ]);
  });
  it("el doble de hosts valida, no repite y filtra por carpeta y etiqueta", async () => {
    const f = fakeInventory();
    expect((await f.listHosts({ folder: "lab" })).map((h) => h.name)).toEqual(["LAB-AP", "LAB-CORE"]);
    expect((await f.listHosts({ tag: "core" })).map((h) => h.name)).toEqual(["LAB-CORE"]);
    expect((await f.listHosts({ query: "oficina" })).map((h) => h.name)).toEqual(["OFI-SW"]);
    const nuevo = { name: "NUEVO", address: "10.1.1.1", port: 0, platform: "ios" as const, folder: "", tags: [], credentialId: "", notes: "" };
    const { id } = await f.saveHost(nuevo);
    expect((await f.listHosts()).find((h) => h.id === id)?.port).toBe(22);
    await expect(f.saveHost({ ...nuevo, name: "nuevo" })).rejects.toThrow("ya hay un host");
    await expect(f.saveHost({ ...nuevo, name: "otro" })).rejects.toThrow("ya está en la libreta");
    await expect(f.saveHost({ ...nuevo, name: "x", address: "admin@10.1.1.2" })).rejects.toThrow("inválida");
    await f.saveHost({ ...nuevo, id, address: "10.1.1.3" }); // editarse a sí mismo no choca
    await f.deleteHost(id);
    await expect(f.deleteHost(id)).rejects.toThrow("no hay un host");
  });
  it("el import del doble exige una decisión por conflicto y no deja renombrar uno de dirección", async () => {
    const f = fakeInventory();
    const p = await f.previewHostsImport("/tmp/h.json");
    expect(p.items.map((i) => i.state)).toEqual(["nuevo", "igual", "conflicto", "conflicto"]);
    expect(p.items[3].credentialMissing).toBe(true);
    await expect(f.applyHostsImport(p.token, [])).rejects.toThrow("falta la decisión");
    await expect(f.applyHostsImport(p.token, [{ key: "10.9.0.1:22", action: "renombrar" }, { key: "ap2.lab:22", action: "omitir" }])).rejects.toThrow("solo se puede reemplazar");
    expect(p.errors.map((e) => e.line)).toEqual([14, 15]);
    expect(await f.applyHostsImport(p.token, [{ key: "10.9.0.1:22", action: "reemplazar" }, { key: "ap2.lab:22", action: "renombrar" }])).toEqual({ created: 1, replaced: 1, renamed: 1, skipped: 3, invalid: 2 });
  });
  it("la plantilla y la descripción del doble salen de la misma tabla de campos", async () => {
    const f = fakeInventory();
    const fmt = await f.hostsImportFormat();
    expect(fmt.fields.map((x) => x.name)).toEqual(["name", "address", "port", "platform", "folder", "tags", "credential_label", "notes"]);
    expect(fmt.fields.filter((x) => x.required).map((x) => x.name)).toEqual(["name", "address"]);
    const csv = await f.hostsImportTemplate("csv");
    expect(csv.content.startsWith("\ufeff")).toBe(true); // el CSV lleva BOM para Excel
    expect(csv.content.slice(1).split("\n")[0]).toBe(fmt.fields.map((x) => x.name).join(","));
    expect(csv.content.trim().split("\n")).toHaveLength(4);
    const json = JSON.parse((await f.hostsImportTemplate("json")).content);
    expect(json.sha256).toBeUndefined();
    expect(json.hosts).toHaveLength(3);
    expect(Object.keys(json.hosts[0])).toEqual(fmt.fields.map((x) => x.name));
  });
});
