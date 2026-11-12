// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
// Limpiador (Fase 16a): JSON de internal/cleaner (sin la salida, que viaja aparte).
export interface CleanChange { rule: string; line: number; text: string }
export interface CleanOrphan { line: number; text: string; why: string }
export interface CleanReport { changes: CleanChange[]; orphans: CleanOrphan[] }
/** Clave del catálogo de un texto del json y sus argumentos (fase 30c), por ruta JSON: "rows.2.detail". */
export interface CleanerTextKey { key: string; args?: Record<string, string> }
export type CleanerTextKeys = Record<string, CleanerTextKey>;
export interface CleanResult { report: CleanReport; text: string; output: string; keys?: CleanerTextKeys }

export interface CleanerAPI {
  cleanerRun(text: string, sort: boolean): Promise<CleanResult>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const cleanerWails = (call: Call): CleanerAPI => ({
  cleanerRun: async (t, s) => { const r = await call<{ json: string; text: string; output: string; keys?: CleanerTextKeys }>("CleanerRun", t, s); return { report: JSON.parse(r.json), text: r.text, output: r.output, keys: r.keys }; },
});
