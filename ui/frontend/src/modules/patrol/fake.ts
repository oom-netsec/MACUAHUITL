// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { CoreEvent, PlaybookInfo } from "./api";
import type { DeviceMetrics, InterfaceSeries, JobMetrics } from "../metrics/api";

const MiB = 1024 * 1024;
const GBPS = 1_000_000_000;

// Datos de ejemplo con la forma de core.jobMetrics: 3 equipos, 6 rondas cada 15 min, 4 interfaces; pico de CPU en
// la ronda 4 del primer equipo y CRC creciente en Gi1/0/2 del mismo. Sirve a las pruebas y a la vista previa.
export function sampleMetrics(start = Date.now() - 90 * 60_000): JobMetrics {
  const at = (r: number) => start + (r - 1) * 15 * 60_000;
  const rounds = [1, 2, 3, 4, 5, 6];
  const devs: [string, string, number][] = [["sw-core-1", "10.0.0.1", 0], ["sw-dist-2", "10.0.0.2", 1], ["sw-acc-3", "10.0.0.3", 2]];
  // Contadores acumulados por ronda; el núcleo entrega la diferencia contra la ronda anterior.
  const cum = (k: number) => ({
    "Te1/1/1": { crc: rounds.map(() => 0), errs: rounds.map(() => 0), outDrops: rounds.map((r) => (r > 3 ? (r - 3) * 14 : 0)), resets: rounds.map(() => 1) },
    "Gi1/0/2": { crc: k === 0 ? [0, 2, 9, 30, 68, 148] : rounds.map(() => 0), errs: k === 0 ? [0, 2, 9, 31, 70, 150] : rounds.map(() => 0), outDrops: rounds.map(() => 0), resets: rounds.map(() => 0) },
  } as Record<string, { crc: number[]; errs: number[]; outDrops: number[]; resets: number[] }>);
  const devices: DeviceMetrics[] = devs.map(([hostname, address, k]) => {
    const c = cum(k);
    const wave = (r: number) => 0.4 + 0.25 * Math.sin(r + k);
    const iface = (name: string, bw: number, inR: number, outR: number, fixed = false): InterfaceSeries => ({
      name, description: "", bwKbit: bw / 1000, peakUtilPct: 0,
      points: rounds.map((r) => {
        const w = fixed ? 1 : wave(r), x = c[name], d = (v?: number[]) => (v && r > 1 ? v[r - 1] - v[r - 2] : 0);
        const inBps = Math.round(inR * w), outBps = Math.round(outR * w);
        return { round: r, atMs: at(r) + 5000, inBps, outBps, source: r === 1 ? "5min" : "counters", inUtilPct: (inBps / bw) * 100, outUtilPct: (outBps / bw) * 100,
          deltaOk: r > 1, inErrors: d(x?.errs), outErrors: 0, crc: d(x?.crc), resets: d(x?.resets), inDrops: 0, outDrops: d(x?.outDrops), reboot: false };
      }),
    });
    return {
      address, hostname, rounds: 6, interfaceTotal: 4, reboots: [], truncated: false, warnings: [],
      cpu: rounds.map((r) => {
        const spike = k === 0 && r === 4, cpu1 = spike ? 88 : 18 + k * 9 + (r % 3) * 3;
        return { round: r, atMs: at(r), fiveSec: spike ? 97 : cpu1 + 4, oneMin: cpu1, fiveMin: spike ? 55 : cpu1 - 2 };
      }),
      memory: [
        { pool: "Processor", points: rounds.map((r) => { const used = (1800 + k * 200 + r * 6) * MiB; return { round: r, atMs: at(r), used, free: 4096 * MiB - used, total: 4096 * MiB }; }) },
        { pool: "I/O", points: rounds.map((r) => ({ round: r, atMs: at(r), used: 210 * MiB, free: 302 * MiB, total: 512 * MiB })) },
      ],
      interfaces: [iface("Te1/1/1", 10 * GBPS, 4.2e9, 3.1e9), iface("Gi1/0/2", GBPS, 310e6, 120e6), iface("Gi1/0/14", GBPS, 38e6, 61e6), iface("Gi1/0/24", GBPS, 0.4e6, 0.2e6, true)],
    };
  });
  return { devices, warnings: [] };
}

// Catálogo de ejemplo con la forma de ListPlaybooks (nombres "Área · Tema").
export const samplePlaybooks: PlaybookInfo[] = [
  { id: "ios-xe/l3-ospf", platform: "ios-xe", name: "L3 · OSPF", commands: ["show clock", "show ip ospf neighbor", "show ip ospf interface brief", "show ip ospf database"], params: [], pack: "" },
  { id: "ios-xe/l2-stp", platform: "ios-xe", name: "L2 · STP", commands: ["show clock", "show spanning-tree summary", "show spanning-tree detail", "show spanning-tree blockedports"], params: [], pack: "" },
  { id: "ios-xe/tac-baseline", platform: "ios-xe", name: "TAC · Línea base", commands: ["show version", "show running-config", "show logging"], params: [], pack: "" },
  { id: "ios-xe/tac-usuario-sin-red", platform: "ios-xe", name: "TAC · Usuario sin red", commands: ["show interfaces status", "show mac address-table", "show ip dhcp snooping binding"], params: [], pack: "" },
  { id: "ios-xe/l2-vlan-troncales", platform: "ios-xe", name: "L2 · VLAN y troncales", commands: ["show vlan brief", "show interfaces trunk", "show vtp status"], params: [], pack: "" },
];

export function fakePatrol() {
  const events = new Set<(e: CoreEvent) => void>();
  return {
    getRun: vi.fn(async () => [] as { target: string; state: string; detail: string }[]),
    onEvent: (cb: (e: CoreEvent) => void) => (events.add(cb), () => events.delete(cb)),
    createJob: vi.fn(async () => "j1"),
    loginTest: vi.fn(async () => []),
    armJob: vi.fn(async () => ({ windowEndsAt: "2026-11-04T10:00:00Z", missingInhibitors: [] })),
    cancelJob: vi.fn(async () => {}),
    listJobs: vi.fn(async () => []),
    subscribe: vi.fn(async () => {}),
    listPlaybooks: vi.fn(async () => samplePlaybooks),
    emitEvent: (e: CoreEvent) => events.forEach((cb) => cb(e)),
  };
}
