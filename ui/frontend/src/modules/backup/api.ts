// Contrato del módulo Respaldos con el puente (ui/bridge/backup.go). Solo lectura: un trabajo de Patrol. Restaurar (fase 16c) planea con el
// puente del modo asistido (ui/bridge/assist.go) y ejecuta con el contrato de Puertos.
import type { AssistPlan } from "../ports/api";

export interface BackupEntry { id: string; device: string; kind: "running" | "startup"; at: string; bytes: number; sha256?: string; masked: boolean; job?: string; round?: number }
export interface BackupList { backups: BackupEntry[]; masked: boolean }
export interface BackupStartRequest {
  targets: { address: string; port: number }[]; credentialId: string; startup: boolean; keep: number;
  // 0 = una sola vez; con intervalo, rounds veces.
  intervalSeconds: number; rounds: number; secrets: boolean; accept: string[];
}
export interface BackupStart { jobId: string; armed: boolean; detail: string }
export interface BackupCollect { state: string; done: boolean; error?: string; saved: string[]; skipped: number; pruned: number; warnings: string[] }
export interface BackupChange { op: "+" | "-"; path: string; line: string }
export interface BackupDiff { from: BackupEntry; to: BackupEntry; added: number; removed: number; changes: BackupChange[]; ignored: string[]; masked: boolean }

export interface RestoreRequest {
  target: { name: string; address: string; port?: number; credentialId: string };
  backupId: string;
  managementInterface?: string; // la interfaz por la que estás conectado; no se toca
  maxLines?: number; // 0 o ausente = 200
  allowPartial?: boolean;
  writeMemory?: boolean;
  acceptedHostKeyFingerprints?: string[];
}
export interface RestoreRefusal { path?: string; line?: string; why?: string }
// planId vacío = el plan se rechazó (reason) y refused lista lo que hay que hacer a mano; con planId, refused es lo que el plan parcial deja fuera.
export interface RestoreResult { planId?: string; plan?: AssistPlan; refused?: RestoreRefusal[]; reason?: string }

export interface BackupAPI {
  assistPlanRestore(r: RestoreRequest): Promise<RestoreResult>;
  backupStart(r: BackupStartRequest): Promise<BackupStart>;
  backupCollect(jobId: string): Promise<BackupCollect>;
  backupList(device: string): Promise<BackupList>;
  backupGet(id: string): Promise<{ meta: BackupEntry; text: string }>;
  backupDiff(from: string, to: string): Promise<BackupDiff>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const backupWails = (call: Call): BackupAPI => ({
  assistPlanRestore: async (r) => JSON.parse(await call<string>("AssistPlanRestore", JSON.stringify(r))),
  backupStart: (r) => call("BackupStart", r.targets, r.credentialId, r.startup, r.keep, r.intervalSeconds, r.rounds, r.secrets, r.accept),
  backupCollect: async (j) => {
    const r = await call<{ state: string; done: boolean; error: string; json: string }>("BackupCollect", j);
    const rep = r.json ? JSON.parse(r.json) : {};
    return { state: r.state, done: r.done, error: r.error || undefined, saved: rep.saved ?? [], skipped: rep.skipped ?? 0, pruned: rep.pruned ?? 0, warnings: rep.warnings ?? [] };
  },
  backupList: async (d) => { const r = JSON.parse(await call<string>("BackupList", d)); return { backups: r.backups ?? [], masked: !!r.masked }; },
  backupGet: async (id) => { const r = await call<{ meta: string; text: string }>("BackupGet", id); return { meta: JSON.parse(r.meta), text: r.text }; },
  backupDiff: async (a, b) => JSON.parse(await call<string>("BackupDiff", a, b)),
});
