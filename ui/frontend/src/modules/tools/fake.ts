// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { PcapReportData, SyslogDrops, SyslogEvent, ToolsAPI } from "./api";

/** Descartes de ejemplo: un origen inunda y la cola llegó a llenarse. */
export const sampleSyslogDrops: SyslogDrops = {
  total: 1200, porOrigen: 1100, global: 80, colaLlena: 20, sinceMs: 1793959200000,
  top: [{ source: "10.0.0.9", count: 1100 }, { source: "otros", count: 100 }],
};

export function fakeTools() {
  const syslog = new Set<(e: SyslogEvent) => void>();
  return {
    toolsPcap: vi.fn(async () => ""),
    toolsPcapReport: vi.fn(async () => ({ text: "", summary: { file: "", packets: 0, bytes: 0, durationMs: 0, start: "" }, conversations: [], topTalkers: [], protocols: [], neighbors: [],
      tcp: { handshakes: 0, rttMinMs: 0, rttAvgMs: 0, rttMaxMs: 0, retransmissions: 0, zeroWindow: 0, failedHandshakesTotal: 0, failedHandshakes: [], resets: [] },
      dns: { queries: 0, responses: 0, errors: [], slow: [], unanswered: [] }, tls: [], icmp: { unreachable: [], ttlExceeded: [] }, arpConflicts: [], fragments: 0, warnings: [], sections: [] }) as PcapReportData),
    toolsDns: vi.fn(async () => ""),
    toolsTls: vi.fn(async () => ""),
    syslogStart: vi.fn<ToolsAPI["syslogStart"]>(async () => "s1"),
    onSyslog: (cb: (e: SyslogEvent) => void) => (syslog.add(cb), () => syslog.delete(cb)),
    emitSyslog: (e: SyslogEvent) => syslog.forEach((cb) => cb(e)),
  };
}
