// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
// Deriva (Fase 16a): JSON de internal/drift. op "+" entró, "-" salió; path es la sección.
export interface DriftChange { op: "+" | "-"; path: string; line: string }
export interface DriftDevice { device: string; from: number; to: number; added: number; removed: number; changes: DriftChange[]; ignored: string[] }
export interface DriftReport { dir: string; from: number; to: number; devices: DriftDevice[]; warnings: string[]; masked?: boolean }

/** Clave del catálogo de un texto del json y sus argumentos (fase 30c), por ruta JSON: "rows.2.detail". */
export interface DriftTextKey { key: string; args?: Record<string, string> }
export type DriftTextKeys = Record<string, DriftTextKey>;

export interface DriftAPI {
  driftRun(job: string, round: number, device: string): Promise<DriftReport>;
  // Fase 30c: con el texto del informe y las claves de los textos del json.
  driftRunReport?(job: string, round: number, device: string): Promise<{ report: DriftReport; text: string; keys?: DriftTextKeys }>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const driftWails = (call: Call): DriftAPI => ({
  driftRun: async (j, r, d) => JSON.parse(await call<string>("DriftRun", j, r, d)),
  driftRunReport: async (j, r, d) => { const x = await call<{ json: string; text: string; keys?: DriftTextKeys }>("DriftRunReport", j, r, d); return { report: JSON.parse(x.json), text: x.text, keys: x.keys }; },
});
