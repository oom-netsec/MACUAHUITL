// Doble del módulo para pruebas: registra llamadas.
import { vi } from "vitest";

export function fakeHash() {
  return { fieldHash: vi.fn(async () => ({ text: "", ok: true })) };
}
