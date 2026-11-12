// Doble de la Terminal para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { TerminalEvent } from "./api";

export function fakeTerminal() {
  const evs = new Set<(e: TerminalEvent) => void>();
  let seq = 0;
  return {
    terminalOpen: vi.fn(async () => `t${++seq}`),
    terminalSend: vi.fn(async () => {}),
    terminalResize: vi.fn(async () => {}),
    terminalClose: vi.fn(async () => {}),
    onTerminal: (cb: (e: TerminalEvent) => void) => (evs.add(cb), () => { evs.delete(cb); }),
    emitTerminal: (e: TerminalEvent) => evs.forEach((cb) => cb(e)),
  };
}
