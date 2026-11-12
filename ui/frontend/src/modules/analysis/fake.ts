// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { AnalysisReport, DiffReport, TimelineReport } from "./api";

export function fakeAnalysis() {
  return {
    analysisRun: vi.fn(async () => ({ dir: "", devices: [], rounds: [], findings: [], warnings: [], missing: [] }) as AnalysisReport),
    analysisDiff: vi.fn(async () => ({ dir: "", from: 1, to: 2, devices: [], warnings: [] }) as DiffReport),
    analysisTimeline: vi.fn(async () => ({ dir: "", events: [], warnings: [] }) as TimelineReport),
  };
}
