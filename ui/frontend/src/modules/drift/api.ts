// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
// Deriva (Fase 16a): JSON de internal/drift. op "+" entró, "-" salió; path es la sección.
export interface DriftChange { op: "+" | "-"; path: string; line: string }
export interface DriftDevice { device: string; from: number; to: number; added: number; removed: number; changes: DriftChange[]; ignored: string[] }
export interface DriftReport { dir: string; from: number; to: number; devices: DriftDevice[]; warnings: string[]; masked?: boolean }

export interface DriftAPI {
  driftRun(job: string, round: number, device: string): Promise<DriftReport>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const driftWails = (call: Call): DriftAPI => ({
  driftRun: async (j, r, d) => JSON.parse(await call<string>("DriftRun", j, r, d)),
});
