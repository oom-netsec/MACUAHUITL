// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { DriftReport } from "./api";

export function fakeDrift() {
  return {
    driftRun: vi.fn(async () => ({ dir: "", from: 0, to: 0, devices: [], warnings: [] }) as DriftReport),
  };
}
