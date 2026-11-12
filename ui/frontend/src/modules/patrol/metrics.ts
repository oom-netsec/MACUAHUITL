// Funciones puras para armar las series de Patrol: fromJob pasa JobMetrics del núcleo (core.jobMetrics,
// docs/plans/contratos-front.md §1) a una muestra por equipo y ronda, que es lo que dibujan las gráficas.
import type { JobMetrics } from "../metrics/api";

export interface PatrolMetrics { rounds: { round: number; at: string }[]; devices: DeviceMetrics[]; warnings: string[] }
export interface DeviceMetrics {
  deviceId: string; name: string; address: string; warnings: string[]; reboots: number[]; // id: la dirección (dos equipos pueden llamarse igual); reboots: rondas
  ifaceShown: number; ifaceTotal: number; // el núcleo manda las de mayor pico: «mostrando N de M»
  samples: {
    round: number; at: string;
    cpu?: { fiveSec: number; oneMin: number; fiveMin: number };
    memory?: { pool: string; usedBytes: number; freeBytes: number }[];
    interfaces?: {
      name: string; bandwidthBps: number; inBps?: number; outBps?: number; avg5min: boolean; // sin tasa: ausente; avg5min: tasa del equipo, no de contadores
      // Diferencia contra la ronda anterior; ausente cuando no vale (primera ronda, reinicio, contador que bajó).
      inErrors?: number; outErrors?: number; crc?: number; inDrops?: number; outDrops?: number; resets?: number;
    }[];
  }[];
}

export function fromJob(j: JobMetrics): PatrolMetrics {
  const at = new Map<number, number>();
  const seen = (round: number, ms: number) => { if (!at.get(round)) at.set(round, ms); }; // la primera hora conocida de la ronda
  const devices = j.devices.map((d): DeviceMetrics => {
    const by = new Map<number, DeviceMetrics["samples"][number]>();
    const get = (round: number, ms: number) => {
      seen(round, ms);
      let s = by.get(round);
      if (!s) by.set(round, (s = { round, at: "" }));
      return s;
    };
    d.cpu.forEach((c) => { get(c.round, c.atMs).cpu = { fiveSec: c.fiveSec, oneMin: c.oneMin, fiveMin: c.fiveMin }; });
    d.memory.forEach((m) => m.points.forEach((p) => { const s = get(p.round, p.atMs); (s.memory ??= []).push({ pool: m.pool, usedBytes: p.used, freeBytes: p.free }); }));
    d.interfaces.forEach((i) => i.points.forEach((p) => {
      const ok = p.deltaOk;
      if (!p.source && !ok) return; // ronda sin tasa ni diferencias válidas de esta interfaz
      (get(p.round, p.atMs).interfaces ??= []).push({
        name: i.name, bandwidthBps: i.bwKbit * 1000, avg5min: p.source === "5min",
        ...(p.source ? { inBps: p.inBps, outBps: p.outBps } : {}),
        ...(ok ? { inErrors: p.inErrors, outErrors: p.outErrors, crc: p.crc, inDrops: p.inDrops, outDrops: p.outDrops, resets: p.resets } : {}),
      });
    }));
    return { deviceId: d.address || d.hostname, name: d.hostname || d.address, address: d.address, ifaceShown: d.interfaces.length, ifaceTotal: d.interfaceTotal, warnings: d.warnings, reboots: d.reboots.map((r) => r.round), samples: [...by.values()].sort((a, b) => a.round - b.round) };
  });
  const iso = (ms: number) => (ms ? new Date(ms).toISOString() : "");
  const rounds = [...at].sort((a, b) => a[0] - b[0]).map(([round, ms]) => ({ round, at: iso(ms) }));
  devices.forEach((d) => d.samples.forEach((s) => { s.at = iso(at.get(s.round) ?? 0); }));
  return { rounds, devices, warnings: j.warnings };
}

export type Sample = DeviceMetrics["samples"][number];
export type Iface = NonNullable<Sample["interfaces"]>[number];

export const roundTimes = (m: PatrolMetrics) => m.rounds.map((r) => Math.floor(Date.parse(r.at) / 1000));

// Un valor por ronda del trabajo; null si el equipo no tiene muestra o el comando no se recolectó.
export const perRound = (d: DeviceMetrics, m: PatrolMetrics, pick: (s: Sample) => number | undefined): (number | null)[] =>
  m.rounds.map((r) => {
    const s = d.samples.find((x) => x.round === r.round);
    return (s && pick(s)) ?? null;
  });

export const ifaceValue = (name: string, pick: (i: Iface) => number | undefined) => (s: Sample) => {
  const i = s.interfaces?.find((x) => x.name === name);
  return i ? pick(i) : undefined;
};

export const ifaceNames = (d: DeviceMetrics): string[] => {
  const seen = new Set<string>();
  d.samples.forEach((s) => s.interfaces?.forEach((i) => seen.add(i.name)));
  return [...seen];
};

const peakOf = (d: DeviceMetrics, name: string) =>
  Math.max(0, ...d.samples.map((s) => ifaceValue(name, (i) => Math.max(i.inBps ?? 0, i.outBps ?? 0))(s) ?? 0));

export const topInterfaces = (d: DeviceMetrics, n = 5): string[] =>
  ifaceNames(d).map((name) => [name, peakOf(d, name)] as const).sort((a, b) => b[1] - a[1]).slice(0, n).map(([name]) => name);

// Interfaces cuyo contador creció entre rondas (diferencias válidas), de mayor a menor crecimiento total.
export const growing = (d: DeviceMetrics, m: PatrolMetrics, pick: (i: Iface) => number | undefined): string[] =>
  ifaceNames(d)
    .map((name) => [name, perRound(d, m, ifaceValue(name, pick)).reduce<number>((a, x) => a + (x ?? 0), 0)] as const)
    .filter(([, total]) => total > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([name]) => name);

export function cpuPeak(d: DeviceMetrics): { value: number; round: number } | null {
  let best: { value: number; round: number } | null = null;
  for (const s of d.samples) if (s.cpu && (!best || s.cpu.fiveSec > best.value)) best = { value: s.cpu.fiveSec, round: s.round };
  return best;
}
