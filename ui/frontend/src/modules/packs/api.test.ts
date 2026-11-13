import { describe, expect, it, vi } from "vitest";
import { packsWails } from "./api";
import { sampleDetail, samplePack, sampleThirdParty } from "./fake";

describe("packs api", () => {
  it("cada método llama al puente con sus argumentos", async () => {
    const call = vi.fn(async () => samplePack);
    const api = packsWails(call as never);
    await api.packInstall("/tmp/x.mpack", true);
    await api.packList();
    await api.packShow("oom/ios-xe");
    await api.packRemove("oom/ios-xe");
    expect(call.mock.calls).toEqual([["PackInstall", "/tmp/x.mpack", true], ["PackList"], ["PackShow", "oom/ios-xe"], ["PackRemove", "oom/ios-xe"]]);
  });
  it("los ejemplos cumplen el contrato: oficial y de terceros, tapados y texto plano", () => {
    expect(samplePack.official).toBe(true);
    expect(sampleThirdParty).toMatchObject({ official: false, shadowed: ["ios-xe/acme-a"] });
    expect(sampleDetail.readme).toContain("<script>"); // llega tal cual: la vista no lo interpreta
  });
});
