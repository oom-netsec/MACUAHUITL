import { describe, expect, it, vi } from "vitest";
import { metricsWails } from "./api";
import { samplePorts, sampleMetrics } from "./fake";

describe("metrics api", () => {
  it("jobMetrics llama al puente con los topes por omisión", async () => {
    const call = vi.fn(async () => sampleMetrics);
    await metricsWails(call as never).jobMetrics({ job: "abc", device: "SW1" });
    expect(call).toHaveBeenCalledWith("JobMetrics", { job: "abc", device: "SW1", maxPoints: 0, maxInterfaces: 0, interfaces: [] });
  });
  it("el ejemplo cumple la forma del contrato: reinicio sin diferencias y fuente 5min", () => {
    const p = sampleMetrics.devices[0].interfaces[0].points;
    expect(p[2]).toMatchObject({ reboot: true, deltaOk: false, source: "5min" });
    expect(p[1]).toMatchObject({ deltaOk: true, source: "counters", crc: 4 });
  });
  it("portStatus llama al puente con los valores por omisión", async () => {
    const call = vi.fn(async () => samplePorts);
    await metricsWails(call as never).portStatus({ device: "10.0.0.1", credentialId: "c1" });
    expect(call).toHaveBeenCalledWith("PortStatus", { job: "", device: "10.0.0.1", port: 0, credentialId: "c1", acceptedHostKeys: [], legacySsh: false });
  });
  it("el ejemplo de puertos trae los cuatro estados, un canal y la numeración módulo/stack/puerto", () => {
    expect(new Set(samplePorts.ports.map((p) => p.status))).toEqual(new Set(["connected", "notconnect", "disabled", "err-disabled"]));
    expect(samplePorts.ports[11]).toMatchObject({ name: "Gi1/0/12", module: 1, stack: 0, number: 12 });
    expect(samplePorts.channels[0].members.map((m) => m.port)).toEqual(["Gi1/0/1", "Gi1/0/2"]);
  });
});
