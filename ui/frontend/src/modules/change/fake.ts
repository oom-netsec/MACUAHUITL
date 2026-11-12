// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { ChangeSummary } from "./api";

export function fakeChange() {
  return {
    changeCreate: vi.fn(async () => "ch1"),
    changeCapture: vi.fn(async () => ({ jobId: "j1", armed: true, detail: "" })),
    listChanges: vi.fn(async () => [] as ChangeSummary[]),
    changeReport: vi.fn(async () => ({ json: "{}", text: "" })),
    upgradeCheck: vi.fn(async () => ({ json: "{}", text: "" })),
    complianceCheck: vi.fn(async () => ({ json: "{}", text: "" })),
    topoBuild: vi.fn(async () => ({ text: "", json: "{}", svg: "<svg/>" })),
  };
}
