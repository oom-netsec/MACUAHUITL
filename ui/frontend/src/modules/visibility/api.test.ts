import { describe, expect, it, vi } from "vitest";
import { visibilityWails } from "./api";
import { fakeVisibility } from "./fake";
import { sampleSyslogDrops } from "../tools/fake";

// El runtime real de Wails deja un temporizador que toca `window` después de cerrar jsdom (error suelto en CI).
vi.mock("@wailsio/runtime", () => ({ Events: { On: () => () => {} } }));

describe("visibility api: topes y archivo de traps y flows", () => {
  it("trapsStart y flowsStart mandan las opciones al puente y {} si no hay (el puente exige el último argumento)", async () => {
    const call = vi.fn(async () => "run-1");
    const api = visibilityWails(call as never);
    const opts = { ratePerSource: 50, rotateMb: 5, nameTemplate: "x_{fecha}", maxFiles: 3, format: "jsonl" as const };
    await api.trapsStart("127.0.0.1:1162", false, false, "", "SHA", "AES");
    await api.trapsStart("127.0.0.1:1162", false, true, "", "SHA", "AES", opts);
    await api.flowsStart("127.0.0.1:2055", false, false, 10);
    await api.flowsStart("127.0.0.1:2055", false, true, 10, opts);
    expect(call).toHaveBeenNthCalledWith(1, "TrapsStart", "127.0.0.1:1162", false, false, "", "SHA", "AES", {});
    expect(call).toHaveBeenNthCalledWith(2, "TrapsStart", "127.0.0.1:1162", false, true, "", "SHA", "AES", opts);
    expect(call).toHaveBeenNthCalledWith(3, "FlowsStart", "127.0.0.1:2055", false, false, 10, {});
    expect(call).toHaveBeenNthCalledWith(4, "FlowsStart", "127.0.0.1:2055", false, true, 10, opts);
  });
  it("el doble entrega eventos de descartes y de archivo nuevo", () => {
    const f = fakeVisibility();
    const got: unknown[] = [];
    f.onVis("traps", (e) => got.push(e));
    f.onVis("flows", (e) => got.push(e));
    f.emitVis("traps", { runId: "t1", drops: sampleSyslogDrops });
    f.emitVis("flows", { runId: "f1", rotatedPath: "/o/flows/a.jsonl", outputPath: "/o/flows" });
    expect(got).toEqual([{ runId: "t1", drops: sampleSyslogDrops }, { runId: "f1", rotatedPath: "/o/flows/a.jsonl", outputPath: "/o/flows" }]);
  });
});
