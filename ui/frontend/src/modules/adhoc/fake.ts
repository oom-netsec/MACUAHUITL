// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { AdhocResult } from "./api";

export function fakeAdhoc() {
  return {
    adhocStart: vi.fn(async () => ({ jobId: "j1", armed: true, detail: "" })),
    adhocResult: vi.fn(async () => ({ state: "completed", done: true, report: { commands: [], devices: 0, rows: [] }, text: "", csv: "", markdown: "" }) as AdhocResult),
  };
}
