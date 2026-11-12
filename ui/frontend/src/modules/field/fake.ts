// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { ServeEvent } from "./api";

export function fakeField() {
  const serve = new Set<(e: ServeEvent) => void>();
  return {
    serveStart: vi.fn(async () => "s1"),
    onServe: (cb: (e: ServeEvent) => void) => (serve.add(cb), () => serve.delete(cb)),
    fieldHash: vi.fn(async () => ({ text: "", ok: true })),
    emitServe: (e: ServeEvent) => serve.forEach((cb) => cb(e)),
  };
}
