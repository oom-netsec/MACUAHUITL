// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { DiagEvent, NetInterface, SweepPoint } from "./api";

export function fakeDiag() {
  const diag = new Set<(e: DiagEvent) => void>();
  const emit = (e: DiagEvent) => diag.forEach((cb) => cb(e));
  return {
    // Con barrido (vista previa): emite los puntos y el resumen sin esperar a un núcleo.
    diagRun: vi.fn(async (_t?: string, _a?: string[], o?: Record<string, string>) => {
      if (o?.sweep_start) setTimeout(() => {
        const pts: SweepPoint[] = [1200, 1300, 1400, 1472, 1500].map((size) => ({ size, sent: 1, received: size > 1472 ? 0 : 1, result: size > 1472 ? "frag" : "ok" }));
        pts.forEach((sweepPoint) => emit({ runId: "r1", sweepPoint }));
        emit({ runId: "r1", done: true, exitCode: 0, pingSummary: { sent: 5, received: 4, lossPct: 20, minMs: 1.1, avgMs: 1.6, maxMs: 2.4, mdevMs: 0.5 } });
      }, 0);
      return "r1";
    }),
    diagCancel: vi.fn(async () => {}),
    diagStop: vi.fn(async (_id: string) => {}),
    listInterfaces: vi.fn(async () => [] as NetInterface[]),
    onDiag: (cb: (e: DiagEvent) => void) => (diag.add(cb), () => diag.delete(cb)),
    emitDiag: emit,
  };
}
