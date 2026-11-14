import { describe, expect, it, vi } from "vitest";
import { packsWails } from "./api";
import { sampleDetail, samplePack, sampleThirdParty } from "./fake";

describe("packs api", () => {
  it("cada método llama al puente con sus argumentos", async () => {
    const call = vi.fn(async () => samplePack);
    const api = packsWails(call as never);
    await api.packInstall("/tmp/x.mpack", true, "abc");
    await api.packList();
    await api.packShow("oom/ios-xe");
    await api.packRemove("oom/ios-xe");
    expect(call.mock.calls).toEqual([["PackInstall", "/tmp/x.mpack", true, "abc"], ["PackList"], ["PackShow", "oom/ios-xe"], ["PackRemove", "oom/ios-xe"]]);
  });
  it("los métodos de 32b y 32c mandan sus argumentos en el orden del puente", async () => {
    const call = vi.fn(async () => ({}));
    const api = packsWails(call as never);
    await api.packInstallHiding("/tmp/x.mpack", true, ["a"], true, "abc");
    await api.packSetItems("oom/ios-xe", ["a"], ["b"]);
    await api.packInspect("/tmp/x.mpack", true);
    await api.packImportPreview("/tmp/p.mpack");
    await api.packImport("/tmp/p.mpack", "abc", [{ itemId: "s1", action: "omitir" }]);
    expect(call.mock.calls).toEqual([
      ["PackInstallHiding", "/tmp/x.mpack", true, ["a"], true, "abc"], ["PackSetItems", "oom/ios-xe", ["a"], ["b"]], ["PackInspect", "/tmp/x.mpack", true],
      ["PackImportPreview", "/tmp/p.mpack"], ["PackImport", "/tmp/p.mpack", "abc", [{ itemId: "s1", action: "omitir" }]],
    ]);
  });
  it("los ejemplos cumplen el contrato: oficial y de terceros, tapados y texto plano", () => {
    expect(samplePack.official).toBe(true);
    expect(sampleThirdParty).toMatchObject({ official: false, shadowed: ["ios-xe/acme-a"] });
    expect(sampleDetail.readme).toContain("<script>"); // llega tal cual: la vista no lo interpreta
  });
});
