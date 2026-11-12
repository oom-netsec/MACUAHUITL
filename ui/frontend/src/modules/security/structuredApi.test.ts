import { expect, it, vi } from "vitest";
import { securityWails, type RadiusExchangeData, type RadiusRequest, type TacacsRequest } from "./api";
import { fakeSecurity } from "./fake";

// Fase 30b: los métodos con informe estructurado llaman al puente por su nombre y el doble los tiene vacíos.
it("secRadiusReport, secTacacsReport y secPkiDecodeReport llaman a sus métodos del puente", async () => {
  const call = vi.fn(async () => ({}));
  const api = securityWails(call as never);
  const r = { host: "10.0.0.1" } as RadiusRequest, t = { host: "10.0.0.1" } as TacacsRequest;
  await api.secRadiusReport!(r);
  await api.secTacacsReport!(t);
  await api.secPkiDecodeReport!("PEM");
  expect(call.mock.calls).toEqual([["SecRadiusReport", r], ["SecTacacsReport", t], ["SecPkiDecodeReport", "PEM"]]);
});

it("el doble devuelve informes vacíos y con la forma", async () => {
  const f = fakeSecurity();
  expect(await f.secRadiusReport()).toEqual({ text: "", server: "", exchanges: [], findings: [] });
  expect(await f.secPkiDecodeReport()).toEqual({ text: "", certificates: [] });
});

// Fase 30c-A: secIkeReport llama a su método del puente y el doble trae la forma vacía; mschap2Verified es opcional.
it("secIkeReport llama a SecIkeReport y el doble devuelve el informe vacío", async () => {
  const call = vi.fn(async () => ({}));
  await securityWails(call as never).secIkeReport!("debug");
  expect(call.mock.calls).toEqual([["SecIkeReport", "debug"]]);
  expect(await fakeSecurity().secIkeReport()).toEqual({ text: "", json: "", phase1: "no_data", phase2: "no_data", findings: [], proposals: [], note: "" });
  const ex: RadiusExchangeData[] = [{ kind: "access-request", rttMs: 1, attempts: 1, attrs: [], mschap2Verified: true }, { kind: "accounting-start", rttMs: 1, attempts: 1, attrs: [] }];
  expect(ex[0].mschap2Verified).toBe(true);
  expect(ex[1].mschap2Verified).toBeUndefined();
});
