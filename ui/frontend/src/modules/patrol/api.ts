// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
import { Events } from "@wailsio/runtime";

export interface LoginResult { target: string; passed: boolean; failedStep: string; detail: string; platform: string; fingerprint: string }
export interface ArmResult { windowEndsAt: string; missingInhibitors: string[] | null }
// Fase del historial de un trabajo; kind es el nombre del enum (JOB_PHASE_KIND_*).
export interface JobPhase { at: string; kind: string; round?: number; detail?: string }
// Los campos opcionales vienen del núcleo; un núcleo anterior no los manda.
export interface Job {
  id: string; name: string; state: string;
  armedAt?: string; windowEndsAt?: string; nextRoundAt?: string;
  round?: number; rounds?: number; devicesTotal?: number; devicesOk?: number; devicesFailed?: number;
  outputDir?: string; phases?: JobPhase[];
}
// Evento de core:event: JSON de SubscribeResponse (protojson, camelCase).
export interface CoreEvent {
  jobId: string;
  at?: string;
  deviceStateChanged?: { deviceId: string; state: string; detail?: string };
  commandProgress?: { deviceId: string; command: string; index?: number; total?: number; bytesReceived?: string };
  heartbeat?: Record<string, never>;
  jobStateChanged?: { state: string };
  warning?: { code: string; message?: string };
  phaseAdded?: JobPhase;
}
export interface JobSpec {
  name: string;
  targets: { address: string; port?: number; deviceId?: string }[];
  defaultCredentialId: string;
  customCommands: string;
  playbookIds: string[];
  outputDir: string;
  split: "SPLIT_STRATEGY_PER_ROUND" | "SPLIT_STRATEGY_CONSOLIDATED";
  zip: "ZIP_POLICY_AT_END" | "ZIP_POLICY_PER_ROUND" | "ZIP_POLICY_NONE";
  deleteLooseFiles: boolean;
  disableMasking: boolean;
  acceptChangedHostKeys: boolean;
  windowHours: number;
  schedule: { intervalSeconds?: number; rounds?: number; cron?: string };
}
export interface RunDevice { target: string; state: string; detail: string }
// Un playbook del catálogo: id "ios-xe/stp", nombre "L2 · STP" (área antes del «·») y los comandos que corre.
export interface PlaybookInfo { id: string; platform: string; name: string; commands: string[] }

export interface PatrolAPI {
  getRun(jobId: string, round: number): Promise<RunDevice[]>;
  onEvent(cb: (e: CoreEvent) => void): () => void;
  createJob(spec: JobSpec): Promise<string>;
  loginTest(jobId: string): Promise<LoginResult[]>;
  armJob(jobId: string, accept: string[], exclude: string[]): Promise<ArmResult>;
  cancelJob(jobId: string): Promise<void>;
  listJobs(): Promise<Job[]>;
  subscribe(jobIds: string[]): Promise<void>;
  // Catálogo de playbooks del núcleo (PatrolService.ListPlaybooks); el id es el que acepta JobSpec.playbookIds.
  listPlaybooks(): Promise<PlaybookInfo[]>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const patrolWails = (call: Call): PatrolAPI => ({
  getRun: (id, r) => call("GetRun", id, r),
  onEvent: (cb) => Events.On("core:event", (e) => cb(e.data as CoreEvent)),
  createJob: (s) => call("CreateJob", JSON.stringify(s)),
  loginTest: (id) => call("LoginTest", id),
  armJob: (id, a, x) => call("ArmJob", id, a, x),
  cancelJob: (id) => call("CancelJob", id),
  listJobs: () => call("ListJobs"),
  subscribe: (ids) => call("Subscribe", ids),
  // protojson omite las listas vacías: {} sin playbooks, y un playbook sin commands.
  listPlaybooks: async () => ((JSON.parse(await call<string>("ListPlaybooks")) as { playbooks?: Partial<PlaybookInfo>[] }).playbooks ?? [])
    .filter((p): p is Partial<PlaybookInfo> & { id: string } => !!p.id) // sin id no se puede pedir: el núcleo lo rechazaría
    .map((p) => ({ id: p.id, platform: p.platform ?? "", name: p.name ?? p.id, commands: p.commands ?? [] })),
});
