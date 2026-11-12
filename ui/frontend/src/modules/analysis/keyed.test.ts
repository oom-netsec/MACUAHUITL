import { describe, expect, it } from "vitest";
import { analysisWails } from "./api";

// Fase 30c: los métodos *Report traen el informe, su texto y las claves de los textos del json.
describe("analysisWails con claves", () => {
  it("analysisRunReport separa el json, el texto y las claves", async () => {
    const calls: unknown[][] = [];
    const api = analysisWails(async <T,>(method: string, ...args: unknown[]) => {
      calls.push([method, ...args]);
      return { json: '{"findings":[]}', text: "t", keys: { "findings.0.detail": { key: "analyze.detail.lines", args: { n: "2" } } } } as T;
    });
    const r = await api.analysisRunReport!("j", 2, "SW1");
    expect(calls[0]).toEqual(["AnalysisRunReport", "j", 2, "SW1"]);
    expect(r.report).toEqual({ findings: [] });
    expect(r.text).toBe("t");
    expect(r.keys!["findings.0.detail"].key).toBe("analyze.detail.lines");
  });
});
