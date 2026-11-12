import { describe, expect, it, vi } from "vitest";
import { settingsWails } from "./api";
import { fakeSettings, sampleOutputsDefault } from "./fake";

describe("settings api", () => {
  it("getCorePrefs y setCorePrefs llaman al puente con los campos del contrato", async () => {
    const call = vi.fn(async () => ({}));
    const api = settingsWails(call as never);
    await api.getCorePrefs();
    expect(call).toHaveBeenCalledWith("GetCorePrefs");
    await api.setCorePrefs({ outputsDir: "/x", rotateMb: 10, rotateMin: 5, maxFiles: 7, format: "jsonl" });
    expect(call).toHaveBeenCalledWith("SetCorePrefs", { outputsDir: "/x", rotateMb: 10, rotateMin: 5, maxFiles: 7, format: "jsonl" });
  });
  it("el doble parte de fábrica, avisa al cambiar la carpeta y conserva lo guardado", async () => {
    const f = fakeSettings();
    expect(await f.getCorePrefs()).toMatchObject({ outputsDir: "", outputsDirEffective: sampleOutputsDefault, outputsDirDefault: sampleOutputsDefault, note: "" });
    const r = await f.setCorePrefs({ outputsDir: "/x", rotateMb: 10, rotateMin: 0, maxFiles: 0, format: "crudo" });
    expect(r).toMatchObject({ outputsDirEffective: "/x", rotateMb: 10, format: "crudo" });
    expect(r.note).toMatch(/no se mueven/);
    expect((await f.setCorePrefs({ ...r, rotateMb: 20 })).note).toBe("");
    expect(await f.getCorePrefs()).toMatchObject({ outputsDir: "/x", rotateMb: 20 });
  });
});
