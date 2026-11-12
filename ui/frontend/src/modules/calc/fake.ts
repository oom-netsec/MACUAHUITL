// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { CalcResult } from "./api";

export function fakeCalc() {
  return {
    calc: vi.fn(async () => ({ text: "", tables: [], notes: [] }) as CalcResult),
  };
}
