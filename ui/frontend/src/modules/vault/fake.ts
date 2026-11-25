// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { Credential, VaultBackupPreview, VaultImportKeyInput } from "./api";

const coreErr = (reason: string, metadata: Record<string, string> = {}) => Object.assign(new Error(reason), { cause: { code: "InvalidArgument", reason, metadata } });

// Respaldo de ejemplo: una nueva, un conflicto y una reservada.
export const sampleVaultBackup: VaultBackupPreview = {
  token: "tok-vault-1",
  expiresMs: 1_700_000_600_000,
  items: [
    { id: "a1", label: "Core DC", username: "netops", state: "nueva" },
    { id: "a3", label: "Laboratorio", username: "lab", state: "conflicto_etiqueta", targetId: "v7" },
    { id: "a4", label: "macuahuitl:llave-de-respaldos", username: "hmac", state: "reservada" },
  ],
};

export function fakeVault() {
  const imported: Credential[] = [];
  return {
    vaultStatus: vi.fn(async () => ({ state: "unlocked" as const, armedJobs: [] })),
    vaultCreate: vi.fn(async () => {}),
    vaultUnlock: vi.fn(async () => {}),
    vaultLock: vi.fn(async () => {}),
    listCredentials: vi.fn(async () => [...imported]),
    putCredential: vi.fn(async () => "c1"),
    deleteCredential: vi.fn(async () => {}),
    createKeyCredential: vi.fn(async () => ({ id: "k1", publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfake macuahuitl" })),
    vaultImportKey: vi.fn(async (i: VaultImportKeyInput) => {
      const text = i.privateKey ?? "";
      if (text.includes("ENCRYPTED") && !i.passphrase) throw coreErr("vault.err.key_passphrase_required");
      if (text.includes("ENCRYPTED") && i.passphrase !== "correcta") throw coreErr("vault.err.key_passphrase_wrong");
      if (text.includes("DSA-KEY")) throw coreErr("vault.err.key_import_unsupported", { type: "ssh-dss", format: "pem-legacy" });
      if (text.includes("PKCS8-ENC")) throw coreErr("vault.err.key_import_unsupported", { type: "other", format: "pkcs8-encrypted" });
      if (text.includes("TOOLONG")) throw coreErr("vault.err.field_too_long", { max: "64 KiB" });
      if (text.includes("INVALID")) throw coreErr("vault.err.key_import_invalid", { format: "other" });
      const credential: Credential = { id: "i" + (imported.length + 1), label: i.label || i.username, username: i.username, kind: "key", origin: "imported", hasEnable: false, hasSshKey: true };
      imported.push(credential);
      const weak = text.includes("RSA-2048");
      return { id: credential.id, publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIimp macuahuitl", fingerprint: "SHA256:abcDEF123fake", algorithm: weak ? "ssh-rsa" : "ssh-ed25519", bits: weak ? 2048 : 256, weak };
    }),
    credentialPublicKey: vi.fn(async () => "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfake macuahuitl"),
    regenerateKeyCredential: vi.fn(async (_id: string, _confirm: boolean) => ({ publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInew macuahuitl", previousOrigin: "generated" as const })),
    exportVaultBackup: vi.fn(async () => ({ count: 3, noPermissions: false, sshKeysIncluded: 0 })),
    removeEmptyFile: vi.fn(async () => {}),
    previewVaultBackupImport: vi.fn(async () => sampleVaultBackup),
    applyVaultBackupImport: vi.fn(async () => ({ created: 1, replaced: 0, renamed: 1, skipped: 1, same: 0 })),
  };
}
