// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";

export function fakeAudit() {
  return {
    auditVerify: vi.fn(async () => ({ intact: true, firstBroken: 0, head: "abc" })),
  };
}
