import { describe, expect, it, vi } from "vitest";
import { toolsWails } from "./api";
import { fakeTools, sampleSyslogDrops } from "./fake";

// El runtime real de Wails deja un temporizador que toca `window` después de cerrar jsdom (error suelto en CI).
vi.mock("@wailsio/runtime", () => ({ Events: { On: () => () => {} } }));

describe("tools api: syslog", () => {
  it("syslogStart manda las opciones al puente y {} si no hay (el puente exige el quinto argumento)", async () => {
    const call = vi.fn(async () => "run-1");
    const api = toolsWails(call as never);
    await api.syslogStart("127.0.0.1:5514", "udp", false, false);
    const opts = { ratePerSource: 50, rotateMb: 5, nameTemplate: "x_{fecha}", maxFiles: 3, format: "jsonl" as const };
    await api.syslogStart("127.0.0.1:5514", "tcp", false, true, opts);
    expect(call).toHaveBeenNthCalledWith(1, "SyslogStart", "127.0.0.1:5514", "udp", false, false, {});
    expect(call).toHaveBeenNthCalledWith(2, "SyslogStart", "127.0.0.1:5514", "tcp", false, true, opts);
  });
  it("el doble entrega eventos de descartes y de archivo nuevo", () => {
    const f = fakeTools();
    const got: unknown[] = [];
    f.onSyslog((e) => got.push(e));
    f.emitSyslog({ runId: "s1", drops: sampleSyslogDrops });
    f.emitSyslog({ runId: "s1", rotatedPath: "/o/syslog/a.log" });
    expect(got).toEqual([{ runId: "s1", drops: sampleSyslogDrops }, { runId: "s1", rotatedPath: "/o/syslog/a.log" }]);
  });
});
