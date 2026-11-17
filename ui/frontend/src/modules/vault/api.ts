// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
export type VaultState = "absent" | "locked" | "unlocked";
export interface VaultStatus { state: VaultState; armedJobs: string[] | null }
export interface Credential { id: string; label: string; username: string; kind?: "password" | "key"; origin?: "generated" | "imported"; hasEnable: boolean; hasSshKey: boolean }

// Las credenciales de llave solo valen para hosts linux/windows abiertos por host_id: los selectores de credencial sueltos no las ofrecen.
export const passwordCreds = (l: Credential[]): Credential[] => l.filter((c) => c.kind !== "key");

// Respaldo cifrado (fase 29d): archivo de bóveda con frase propia; el import va en dos pasos con un token de 10 minutos.
export type VaultBackupState = "nueva" | "igual" | "conflicto_etiqueta" | "reservada"; // «reservada» (del sistema) se omite sola
export type VaultBackupAction = "renombrar" | "reemplazar" | "omitir";
export interface VaultBackupItem { id: string; label: string; username: string; state: VaultBackupState } // id: el de la credencial dentro del respaldo
export interface VaultBackupPreview { token: string; expiresMs: number; items: VaultBackupItem[] }
export interface VaultBackupDecision { id: string; action: VaultBackupAction }
export interface VaultBackupExport { count: number; noPermissions: boolean; sshKeysIncluded: number } // noPermissions: el sistema de archivos (p. ej. vfat) no admitió 0600; el archivo va cifrado igual
export interface VaultBackupResult { created: number; replaced: number; renamed: number; skipped: number; same: number }

// Fase 47: importar una privada existente. Con archivo va path (el puente lee los bytes) y privateKey no; con texto pegado, al revés.
export interface VaultImportKeyInput { label: string; username: string; privateKey?: string; path?: string; passphrase?: string }
export interface VaultImportKeyResult { id: string; publicKey: string; fingerprint: string; algorithm: string; bits: number; weak: boolean } // weak: RSA de menos de 3072 bits; es un aviso

export interface VaultAPI {
  vaultStatus(): Promise<VaultStatus>;
  vaultCreate(master: string): Promise<void>;
  vaultUnlock(master: string): Promise<void>;
  vaultLock(): Promise<void>;
  listCredentials(): Promise<Credential[]>;
  putCredential(label: string, username: string, password: string, enable: string): Promise<string>;
  deleteCredential(id: string): Promise<void>;
  // Fase 44: ed25519 generada en el núcleo; la privada nunca sale. publicKey es una línea de authorized_keys. 
  createKeyCredential(label: string, username: string): Promise<{ id: string; publicKey: string }>;
  vaultImportKey(input: VaultImportKeyInput): Promise<VaultImportKeyResult>;
  credentialPublicKey(id: string): Promise<string>;
  // Otra llave para la misma credencial (conserva el id) y su pública nueva. confirm es obligatorio: la pública vieja deja de servir en cada
  // authorized_keys, así que va en true solo tras preguntar. Solo credenciales de tipo llave.
  regenerateKeyCredential(id: string, confirm: boolean): Promise<{ publicKey: string; previousOrigin: "generated" | "imported" | "" }>;
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
  createKeyCredential: (l, u) => call("CreateKeyCredential", l, u),
  vaultImportKey: (i) => call("ImportKeyCredential", i),
  credentialPublicKey: (id) => call("CredentialPublicKey", id),
  regenerateKeyCredential: (id, confirm) => call("RegenerateKeyCredential", id, confirm),
  exportVaultBackup: (p, f, o, c) => call("ExportVaultBackup", p, f, o, c),
  removeEmptyFile: (p) => call("RemoveEmptyFile", p),
  previewVaultBackupImport: (p, f) => call("PreviewVaultBackupImport", p, f),
  applyVaultBackupImport: (t, d) => call("ApplyVaultBackupImport", t, d),
});
