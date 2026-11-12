// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
// Ejecutor ad-hoc (Fase 16a): lote de solo lectura; JSON de internal/adhoc.
export interface AdhocRow { device: string; address: string; command: string; ok: boolean; output: string; note?: string }
export interface AdhocReport { commands: string[]; devices: number; rows: AdhocRow[] | null }
export interface AdhocStart { jobId: string; armed: boolean; detail: string }
export interface AdhocResult { state: string; done: boolean; report: AdhocReport | null; text: string; csv: string; markdown: string; error?: string }
interface AdhocDTO { state: string; done: boolean; json: string; text: string; csv: string; markdown: string; error?: string }

export interface AdhocAPI {
  adhocStart(targets: { address: string; port: number }[], credentialId: string, commands: string, accept: string[]): Promise<AdhocStart>;
  adhocResult(jobId: string): Promise<AdhocResult>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const adhocWails = (call: Call): AdhocAPI => ({
  adhocStart: (t, c, cmds, a) => call("AdhocStart", t, c, cmds, a),
  adhocResult: async (id) => { const r = await call<AdhocDTO>("AdhocResult", id); return { state: r.state, done: r.done, report: r.json ? JSON.parse(r.json) : null, text: r.text, csv: r.csv, markdown: r.markdown, error: r.error || undefined }; },
});
