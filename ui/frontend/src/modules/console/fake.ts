// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { ConsoleEvent } from "./api";

export function fakeConsole() {
  const evs = new Set<(e: ConsoleEvent) => void>();
  return {
    fieldPorts: vi.fn(async () => [] as string[]),
    consoleOpen: vi.fn(async () => "c1"),
    consoleSend: vi.fn(async () => {}),
    consoleBreak: vi.fn(async () => {}),
    consoleClose: vi.fn(async () => {}),
    onConsole: (cb: (e: ConsoleEvent) => void) => (evs.add(cb), () => evs.delete(cb)),
    emitConsole: (e: ConsoleEvent) => evs.forEach((cb) => cb(e)),
  };
}
