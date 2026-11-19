// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
export interface HashAPI {
  fieldHash(path: string, md5: string, sha512: string): Promise<{ text: string; ok: boolean }>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const hashWails = (call: Call): HashAPI => ({
  fieldHash: (p, m, s) => call("FieldHash", p, m, s),
});
