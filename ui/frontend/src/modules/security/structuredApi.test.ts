import { expect, it, vi } from "vitest";
import { securityWails, type RadiusRequest, type TacacsRequest } from "./api";
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
