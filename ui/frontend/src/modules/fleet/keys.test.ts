import { describe, expect, it } from "vitest";
import { fleetWails } from "./api";

// Fase 30c: fleetWails entrega las claves de los textos junto al resultado; sin claves, el resultado de siempre.
describe("fleetWails con claves", () => {
  const keys = { "rows.0.detail": { key: "fleet.detail.reboot" } };
  const api = (dto: object) => fleetWails(async <T,>() => dto as T);

  it("trae keys en cada resultado", async () => {
    const dto = { json: '{"rows":[],"devices":1,"checked":{},"warnings":[]}', text: "t", keys };
    expect((await api(dto).fleetSummary()).keys).toEqual(keys);
    expect((await api({ json: '{"query":"x","mode":"name","hits":[],"devices":0,"warnings":[]}', text: "", keys }).fleetFind("x")).keys).toEqual(keys);
    expect((await api({ ...dto, svg: "<svg/>" }).fleetPath("a", "b")).result.keys).toEqual(keys);
    expect((await api({ ...dto, csv: "", markdown: "" }).fleetInventory()).result.keys).toEqual(keys);
  });

  it("sin claves no agrega el campo", async () => {
    const r = await api({ json: '{"rows":[],"devices":0,"checked":{},"warnings":[]}', text: "" }).fleetSummary();
    expect("keys" in r).toBe(false);
  });
});
