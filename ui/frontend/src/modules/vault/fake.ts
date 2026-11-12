// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { VaultBackupPreview } from "./api";

// Respaldo de ejemplo: una nueva, una igual, un conflicto y una reservada.
export const sampleVaultBackup: VaultBackupPreview = {
  token: "tok-vault-1",
  expiresMs: 1_700_000_600_000,
  items: [
    { id: "a1", label: "Core DC", username: "netops", state: "nueva" },
    { id: "a2", label: "Sucursales", username: "tac", state: "igual" },
    { id: "a3", label: "Laboratorio", username: "lab", state: "conflicto_etiqueta" },
    { id: "a4", label: "macuahuitl:llave-de-respaldos", username: "hmac", state: "reservada" },
  ],
};

export function fakeVault() {
  return {
    vaultStatus: vi.fn(async () => ({ state: "unlocked" as const, armedJobs: [] })),
    vaultCreate: vi.fn(async () => {}),
    vaultUnlock: vi.fn(async () => {}),
    vaultLock: vi.fn(async () => {}),
    listCredentials: vi.fn(async () => []),
    putCredential: vi.fn(async () => "c1"),
    deleteCredential: vi.fn(async () => {}),
    exportVaultBackup: vi.fn(async () => ({ count: 3, noPermissions: false })),
    removeEmptyFile: vi.fn(async () => {}),
    previewVaultBackupImport: vi.fn(async () => sampleVaultBackup),
    applyVaultBackupImport: vi.fn(async () => ({ created: 1, replaced: 0, renamed: 1, skipped: 1, same: 1 })),
  };
}
