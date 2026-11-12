// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";

export function fakeSecurity() {
  return {
    secRadius: vi.fn(async () => ""),
    secTacacs: vi.fn(async () => ""),
    secIkeDecode: vi.fn(async () => ""),
    secPkiDecode: vi.fn(async () => ""),
    secPkiCsr: vi.fn(async () => ({ pem: "", key: "", text: "" })),
    secPkiCaInit: vi.fn(async () => ({ pem: "", key: "", text: "" })),
    secPkiCaSign: vi.fn(async () => ({ pem: "", key: "", text: "" })),
    secPkiExport: vi.fn(async () => ""),
  };
}
