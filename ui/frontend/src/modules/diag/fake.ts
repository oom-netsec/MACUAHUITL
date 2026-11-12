// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { DiagEvent, NetInterface } from "./api";

export function fakeDiag() {
  const diag = new Set<(e: DiagEvent) => void>();
  return {
    diagRun: vi.fn(async () => "r1"),
    diagCancel: vi.fn(async () => {}),
    listInterfaces: vi.fn(async () => [] as NetInterface[]),
    onDiag: (cb: (e: DiagEvent) => void) => (diag.add(cb), () => diag.delete(cb)),
    emitDiag: (e: DiagEvent) => diag.forEach((cb) => cb(e)),
  };
}
