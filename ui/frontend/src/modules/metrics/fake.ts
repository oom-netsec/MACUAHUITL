// Doble del módulo para pruebas y para trabajar las gráficas sin núcleo.
import { vi } from "vitest";
import type { DeviceMetrics, JobMetrics, PortInfo, PortStatus } from "./api";

const t0 = Date.UTC(2026, 10, 6, 10, 0, 0);
const GB = 1 << 30;

// Un equipo con tres rondas, dos pools de memoria y dos interfaces; el reinicio cae en la ronda 3.
export const sampleDevice: DeviceMetrics = {
  address: "10.0.0.1", hostname: "SW1", rounds: 3, interfaceTotal: 2, truncated: false, warnings: [],
  cpu: [
    { round: 1, atMs: t0, fiveSec: 5, oneMin: 4, fiveMin: 3 },
    { round: 2, atMs: t0 + 300_000, fiveSec: 10, oneMin: 8, fiveMin: 6 },
    { round: 3, atMs: t0 + 600_000, fiveSec: 20, oneMin: 15, fiveMin: 9 },
  ],
  memory: [
    { pool: "Processor", points: [1, 2, 3].map((r) => ({ round: r, atMs: t0 + (r - 1) * 300_000, used: GB / 4 + r * 1_000_000, free: GB - GB / 4 - r * 1_000_000, total: GB })) },
    { pool: "I/O", points: [1, 2, 3].map((r) => ({ round: r, atMs: t0 + (r - 1) * 300_000, used: 5_000_000, free: 11_000_000, total: 16_000_000 })) },
  ],
  interfaces: [
    {
      name: "Gi1/0/1", description: "to-DIST1", bwKbit: 1_000_000, peakUtilPct: 62.5,
      points: [
        { round: 1, atMs: t0 + 5_000, inBps: 2000, outBps: 5000, source: "5min", inUtilPct: 0.0002, outUtilPct: 0.0005, deltaOk: false, inErrors: 0, outErrors: 0, crc: 0, resets: 0, inDrops: 0, outDrops: 0, reboot: false },
        { round: 2, atMs: t0 + 305_000, inBps: 1_000_000, outBps: 625_000_000, source: "counters", inUtilPct: 0.1, outUtilPct: 62.5, deltaOk: true, inErrors: 4, outErrors: 0, crc: 4, resets: 0, inDrops: 0, outDrops: 12, reboot: false },
        { round: 3, atMs: t0 + 605_000, inBps: 9, outBps: 8, source: "5min", inUtilPct: 0, outUtilPct: 0, deltaOk: false, inErrors: 0, outErrors: 0, crc: 0, resets: 0, inDrops: 0, outDrops: 0, reboot: true },
      ],
    },
    { name: "Gi1/0/2", description: "", bwKbit: 100_000, peakUtilPct: 0, points: [] },
  ],
  reboots: [{ round: 3, bootMs: t0 + 540_000 }],
};

export const sampleMetrics: JobMetrics = { devices: [sampleDevice], warnings: [] };

// Un switch de 24 puertos con dos uplinks en canal, un puerto caído por err-disable y uno apagado.
const port = (n: number, over: Partial<PortInfo> = {}): PortInfo => ({
  name: `Gi1/0/${n}`, kind: "Gi", module: 1, stack: 0, number: n, description: "", status: "notconnect", vlan: "1", duplex: "auto", speed: "auto",
  duplexMode: "auto", speedMbps: 0, autoNegotiated: true, type: "10/100/1000BaseTX", trunk: false, trunkNative: "", channel: "", channelFlags: "", ...over,
});
export const samplePorts: PortStatus = {
  source: "job", address: "10.0.0.1", hostname: "SW1", atMs: t0, warnings: [],
  ports: [
    port(1, { description: "to-DIST1", status: "connected", vlan: "trunk", duplex: "a-full", speed: "a-1000", duplexMode: "full", speedMbps: 1000, trunk: true, trunkNative: "1", channel: "Po1", channelFlags: "P" }),
    port(2, { description: "to-DIST1", status: "connected", vlan: "trunk", duplex: "a-full", speed: "a-1000", duplexMode: "full", speedMbps: 1000, trunk: true, trunkNative: "1", channel: "Po1", channelFlags: "P" }),
    port(3, { description: "sala de juntas", status: "connected", vlan: "10", duplex: "a-full", speed: "a-100", duplexMode: "full", speedMbps: 100 }),
    port(4),
    port(5, { description: "apagado", status: "disabled" }),
    port(6, { description: "loop detectado", status: "err-disabled", vlan: "20" }),
    ...Array.from({ length: 18 }, (_, i) => port(i + 7)),
    { ...port(1), name: "Gi1/1/1", stack: 1, type: "1000BaseSX SFP", duplex: "full", speed: "1000", duplexMode: "full", speedMbps: 1000, autoNegotiated: false },
  ],
  channels: [{ name: "Po1", state: "SU", protocol: "LACP", members: [{ port: "Gi1/0/1", flags: "P" }, { port: "Gi1/0/2", flags: "P" }] }],
};

export function fakeMetrics() {
  return {
    jobMetrics: vi.fn(async () => sampleMetrics),
    portStatus: vi.fn(async () => samplePorts),
  };
}
