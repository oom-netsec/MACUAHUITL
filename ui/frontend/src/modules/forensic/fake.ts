// Doble de Forense para pruebas.
import { vi } from "vitest";
import type { CrashReport, DebugReport, FlappingReport, LeaksReport, MsgEntry, PatternsReport } from "./api";

export const sampleMsg = (over: Partial<MsgEntry> = {}): MsgEntry =>
  ({ id: "%SYS-2-MALLOCFAIL", severity: 2, meaning: "Sin memoria.", cause: "Fuga.", action: "Revisa procesos.", verify: ["show memory statistics"], source: "documentación pública de Cisco (sin validar en laboratorio)", ...over });

export function fakeForensic() {
  return {
    forensicMsg: vi.fn(async () => [] as MsgEntry[]),
    forensicCrashinfo: vi.fn(async () => ({ kind: "desconocido", binary: false, bytes: 0, messages: [] }) as CrashReport),
    forensicPatterns: vi.fn(async () => ({ source: "texto pegado", entries: 0, with_time: 0, patterns: [], burst_count: 5, burst_window: "1m0s", stats: { lines: 0, parsed: 0, with_time: 0, skipped: 0 } }) as PatternsReport),
    forensicFlapping: vi.fn(async () => ({ source: "texto pegado", flaps: [], interfaces: 0, transitions: 0, count: 3, window: "1m0s", counter_jumps: [] }) as FlappingReport),
    forensicLeaks: vi.fn(async () => ({ job: "", leaks: [], processes: 0, min_rounds: 3, min_growth: 1048576 }) as LeaksReport),
    forensicDebugs: vi.fn(async () => ({ lines: 0, blank: 0, hidden: 0, noise: [], groups_total: 0, groups: [], anomalies: [] }) as DebugReport),
  };
}
