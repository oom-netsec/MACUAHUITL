// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
export type VaultState = "absent" | "locked" | "unlocked";
export interface VaultStatus { state: VaultState; armedJobs: string[] | null }
export interface Credential { id: string; label: string; username: string; hasEnable: boolean; hasSshKey: boolean }


// Respaldo cifrado (fase 29d): archivo de bóveda con frase propia; el import va en dos pasos con un token de 10 minutos.
export type VaultBackupState = "nueva" | "igual" | "conflicto_etiqueta" | "reservada"; // «reservada» (del sistema) se omite sola
export type VaultBackupAction = "renombrar" | "reemplazar" | "omitir";
export interface VaultBackupItem { id: string; label: string; username: string; state: VaultBackupState } // id: el de la credencial dentro del respaldo
export interface VaultBackupPreview { token: string; expiresMs: number; items: VaultBackupItem[] }
export interface VaultBackupDecision { id: string; action: VaultBackupAction }
export interface VaultBackupExport { count: number; noPermissions: boolean } // noPermissions: el sistema de archivos (p. ej. vfat) no admitió 0600; el archivo va cifrado igual
export interface VaultBackupResult { created: number; replaced: number; renamed: number; skipped: number; same: number }

export interface VaultAPI {
  vaultStatus(): Promise<VaultStatus>;
  vaultCreate(master: string): Promise<void>;
  vaultUnlock(master: string): Promise<void>;
  vaultLock(): Promise<void>;
  listCredentials(): Promise<Credential[]>;
  putCredential(label: string, username: string, password: string, enable: string): Promise<string>;
  deleteCredential(id: string): Promise<void>;
  // Devuelve cuántas credenciales guardó. La frase tiene 12 caracteres o más y es distinta de la maestra; confirm es la confirmación explícita.
  exportVaultBackup(path: string, passphrase: string, overwrite: boolean, confirm: boolean): Promise<VaultBackupExport>;
  // Borra el archivo vacío que dejó pickSavePath si el export falló: solo un archivo regular de 0 bytes en esa ruta exacta.
  removeEmptyFile(path: string): Promise<void>;
  previewVaultBackupImport(path: string, passphrase: string): Promise<VaultBackupPreview>;
  applyVaultBackupImport(token: string, decisions: VaultBackupDecision[]): Promise<VaultBackupResult>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const vaultWails = (call: Call): VaultAPI => ({
  vaultStatus: () => call("VaultStatus"),
  vaultCreate: (m) => call("VaultCreate", m),
  vaultUnlock: (m) => call("VaultUnlock", m),
  vaultLock: () => call("VaultLock"),
  listCredentials: () => call("ListCredentials"),
  putCredential: (l, u, p, e) => call("PutCredential", l, u, p, e),
  deleteCredential: (id) => call("DeleteCredential", id),
  exportVaultBackup: (p, f, o, c) => call("ExportVaultBackup", p, f, o, c),
  removeEmptyFile: (p) => call("RemoveEmptyFile", p),
  previewVaultBackupImport: (p, f) => call("PreviewVaultBackupImport", p, f),
  applyVaultBackupImport: (t, d) => call("ApplyVaultBackupImport", t, d),
});
