// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
// Análisis (Fase 9): JSON de internal/analyze tal cual lo entrega el núcleo.
export type Severity = "critica" | "alta" | "media" | "baja" | "info";
export interface AnalysisWarning { device?: string; round?: number; command?: string; msg: string }
export interface Finding { rule: string; title: string; severity: Severity; device: string; round: number; at: string; command: string; evidence: string[]; detail: string; explanation: string; action: string }
export interface AnalysisReport { dir: string; devices: string[] | null; rounds: number[] | null; findings: Finding[]; warnings: AnalysisWarning[]; missing: string[] }
export interface DeviceDiff {
  device: string;
  counters: { interface: string; counter: string; from: number; to: number; delta: number }[];
  neighbors: { protocol: string; id: string; change: string; from: string; to: string }[];
  prefixes: { neighbor: string; from: number; to: number }[];
  uptime?: { from: string; to: string; reset: boolean };
  text: { command: string; lines: string[]; note?: string }[];
}
export interface DiffReport { dir: string; from: number; to: number; devices: DeviceDiff[]; warnings: AnalysisWarning[] }
export interface TimelineEvent { at: string; source: string; device?: string; severity?: Severity; text: string; note?: string; kb?: string }
export interface TimelineReport { dir: string; around?: string; window?: string; events: TimelineEvent[]; warnings: AnalysisWarning[] }

export interface AnalysisAPI {
  analysisRun(job: string, round: number, device: string): Promise<AnalysisReport>;
  analysisDiff(job: string, from: number, to: number, device: string): Promise<DiffReport>;
  analysisTimeline(job: string, around: string, windowSeconds: number, device: string, pcap: string): Promise<TimelineReport>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const analysisWails = (call: Call): AnalysisAPI => ({
  analysisRun: async (j, r, d) => JSON.parse(await call<string>("AnalysisRun", j, r, d)),
  analysisDiff: async (j, f, t, d) => JSON.parse(await call<string>("AnalysisDiff", j, f, t, d)),
  analysisTimeline: async (j, a, w, d, p) => JSON.parse(await call<string>("AnalysisTimeline", j, a, w, d, p)),
});
