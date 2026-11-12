// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { CleanResult } from "./api";

export function fakeCleaner() {
  return {
    cleanerRun: vi.fn(async () => ({ report: { changes: [], orphans: [] }, text: "", output: "" }) as CleanResult),
  };
}
