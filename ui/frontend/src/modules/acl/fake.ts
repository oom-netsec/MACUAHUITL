// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { AclFinding, AclRule } from "./api";

export function fakeAcl() {
  return {
    aclImport: vi.fn(async () => ({ name: "X", rules: [] as AclRule[] })),
    aclAnalyze: vi.fn(async () => [] as AclFinding[]),
    aclGenerate: vi.fn(async () => ""),
  };
}
