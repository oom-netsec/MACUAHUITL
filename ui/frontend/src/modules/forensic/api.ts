// Contrato del módulo Forense (Fase 17) con el puente (ui/bridge/forensic.go). Todo es de solo lectura.

export interface MsgEntry { id: string; severity: number; meaning: string; cause: string; action: string; verify: string[]; source: string }

export interface CrashReport {
  kind: "crashinfo" | "core" | "desconocido";
  binary: boolean; bytes: number; truncated?: boolean;
  reason?: string; pc?: string; process?: string; pid?: number; traceback?: string[];
  host?: string; model?: string; version?: string; uptime?: string;
  cpu?: { five_sec: number; one_min: number; five_min: number };
  memory?: { total: number; free: number; free_pct: number };
  mnemonics?: string[]; hint?: string; warnings?: string[];
  messages: MsgEntry[];
}

// De dónde salen los mensajes: exactamente una fuente (lo exige el núcleo).
export interface LogSource { text?: string; path?: string; capture?: boolean; job?: string; device?: string; max_kib?: number }

export interface LogPattern {
  pattern: string; mnemonic?: string; severity: number; count: number; first?: string; last?: string;
  hosts?: string[]; host_count: number; example: string; peak: number; episodes: number; burst: boolean; unstable: boolean;
}
export interface PatternsReport {
  source: string; entries: number; with_time: number; patterns: LogPattern[]; overflow?: number;
  kb?: Record<string, MsgEntry>; // fichas por mnemónico, una vez
  burst_count: number; burst_window: string; warnings?: string[]; stats: { lines: number; parsed: number; with_time: number; skipped: number; truncated?: boolean };
}

export interface FlapRow {
  host?: string; interface: string; layer: "link" | "lineproto"; total: number; peak: number; episodes: number;
  first?: string; last?: string; sequence: string; no_time?: boolean; mnemonic?: string;
}
export interface CounterJump { host: string; interface: string; counter: string; from_round: number; to_round: number; from: number; to: number; delta: number; per_hour?: number }
export interface FlappingReport {
  kb?: Record<string, MsgEntry>;
  source: string; flaps: FlapRow[]; interfaces: number; transitions: number; count: number; window: string;
  counter_jumps: CounterJump[]; warnings?: string[];
}

export interface DebugGroup { pattern: string; count: number; example: string }
export interface DebugAnomaly { line: number; text: string; reason: string; family: string; family_count: number }
export interface DebugReport {
  lines: number; blank: number; hidden: number; noise: string[]; groups_total: number; groups: DebugGroup[]; anomalies: DebugAnomaly[]; truncated?: boolean; warnings?: string[];
}

export interface LeakRow { host: string; process: string; pid: number; rounds: number; from_round: number; to_round: number; series: number[]; growth: number; per_hour?: number }
export interface LeaksReport { job: string; leaks: LeakRow[]; processes: number; min_rounds: number; min_growth: number; warnings?: string[] }

export interface ForensicAPI {
  forensicMsg(query: string): Promise<MsgEntry[]>;
  forensicCrashinfo(text: string, path: string): Promise<CrashReport>;
  forensicPatterns(src: LogSource, burst: number, window: number): Promise<PatternsReport>;
  forensicFlapping(src: LogSource, count: number, window: number, minDelta: number): Promise<FlappingReport>;
  forensicLeaks(job: string, device: string, minRounds: number, minGrowthKiB: number): Promise<LeaksReport>;
  forensicDebugs(text: string, path: string, noise: string[], familyMin: number, rareMax: number, top: number): Promise<DebugReport>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

const full = (s: LogSource) => ({ text: "", path: "", capture: false, job: "", device: "", max_kib: 0, ...s });

export const forensicWails = (call: Call): ForensicAPI => ({
  forensicMsg: async (q) => JSON.parse(await call<string>("ForensicMsg", q)),
  forensicCrashinfo: async (t, p) => JSON.parse(await call<string>("ForensicCrashinfo", t, p)),
  forensicPatterns: async (s, b, w) => JSON.parse(await call<string>("ForensicPatterns", full(s), b, w)),
  forensicFlapping: async (s, c, w, d) => JSON.parse(await call<string>("ForensicFlapping", full(s), c, w, d)),
  forensicLeaks: async (j, d, r, k) => JSON.parse(await call<string>("ForensicLeaks", j, d, r, k)),
  forensicDebugs: async (t, p, n, f, r, top) => JSON.parse(await call<string>("ForensicDebugs", t, p, n, f, r, top)),
});
