// Contrato del módulo Puertos con el puente (ui/bridge/assist.go). Los cuerpos viajan como JSON de protojson.
import { Events } from "@wailsio/runtime";

export interface PortsRequest {
  target: { name: string; address: string; port?: number; credentialId: string };
  interfaces: string[];
  vlan?: number;
  voice?: number;
  description?: string;
  shutdown?: boolean;
  writeMemory?: boolean;
  acceptedHostKeyFingerprints?: string[];
}
export interface PlanExpect { command: string; line: string; present?: boolean; prefix?: boolean }
// Un aviso del plan como clave del catálogo del núcleo (assist.note.*) con sus argumentos; mismo orden que notes (fase 30c).
export interface AssistNote { key: string; args?: Record<string, string> }
export interface DevicePlan { device: string; pre: string[]; apply: string[]; rollback: string[]; post: string[]; expect?: PlanExpect[] | null; notes?: string[] | null; notesStructured?: AssistNote[] | null }
export interface AssistPlan { function: string; writeMemory?: boolean; devices: DevicePlan[] }
export interface PortsPlanResult { planId: string; plan: AssistPlan }
// protojson omite device y lines vacíos (el paso close no trae ninguno).
export interface AssistStep { id: string; kind: string; device?: string; lines?: string[] }
// Evento de assist:event; seq y los campos vacíos pueden faltar (protojson omite los ceros).
// changed: equipos que la ejecución cambió y siguen cambiados al emitirse el evento (vacío o ausente = ninguno).
export interface AssistEvent { runId: string; seq?: number; kind: "state" | "pending" | "output" | "fail"; state?: string; step?: AssistStep; device?: string; text?: string; changed?: string[] }
// Una ejecución que el núcleo recuerda (ListRuns); sirve para volver a una que sigue viva.
export interface AssistRunInfo { runId: string; state?: string; pending?: AssistStep; failReason?: string; changed?: string[]; active?: boolean; waiting?: boolean; canRollback?: boolean; devices?: string[] }
// Una reversa guardada de una ejecución que dejó equipos cambiados (ListPendingRollbacks). Las líneas ya vienen sin secretos.
export interface PendingRollback { runId: string; kind: string; devices: { device: string; rollbackLines: string[] }[]; endedUnix: number; ageSeconds: number; writeMemory: boolean; unreadable: boolean }

// protojson omite listas vacías y ceros, y manda los int64 (endedUnix, ageSeconds) como cadena.
export function parsePendingRollbacks(json: string): PendingRollback[] {
  type Raw = { runId: string; kind?: string; devices?: { device: string; rollbackLines?: string[] }[]; endedUnix?: string | number; ageSeconds?: string | number; writeMemory?: boolean; unreadable?: boolean };
  return ((JSON.parse(json).rollbacks ?? []) as Raw[]).map((r) => ({
    runId: r.runId, kind: r.kind ?? "", devices: (r.devices ?? []).map((d) => ({ device: d.device, rollbackLines: d.rollbackLines ?? [] })),
    endedUnix: Number(r.endedUnix ?? 0), ageSeconds: Number(r.ageSeconds ?? 0), writeMemory: !!r.writeMemory, unreadable: !!r.unreadable,
  }));
}
export interface AssistDone { runId: string; error?: string }

// Un puerto como lo dibuja la vista de frente; sale de PortInfo (core.portStatus, docs/plans/contratos-front.md §2) con toFront.
export interface FrontPort {
  name: string; module: number; slot: number; port: number; // Gi1/0/14 -> 1, 0, 14
  status: "connected" | "notconnect" | "disabled" | "err-disabled" | "monitoring";
  vlan: string; mode: "access" | "trunk" | "routed" | "channel"; channel?: string;
  speed: string; duplex: string; type: string; description: string;
  poeWatts?: number;
}

export interface PortsAPI {
  assistPlanPorts(r: PortsRequest): Promise<PortsPlanResult>;
  // assisted debe ser true en cada ejecución: no existe un ajuste que lo recuerde.
  assistStart(planId: string, assisted: boolean): Promise<string>;
  // Abre el stream de eventos de la ejecución (desde el primero). Se llama después de guardar el id que devolvió assistStart.
  assistWatch(runId: string): Promise<void>;
  // Ejecuciones que siguen vivas, para volver a ellas al abrir el módulo.
  assistListRuns(): Promise<AssistRunInfo[]>;
  assistConfirm(runId: string, stepId: string): Promise<void>;
  assistAbort(runId: string): Promise<void>;
  assistRollback(runId: string): Promise<void>;
  assistListPendingRollbacks(): Promise<PendingRollback[]>;
  // Devuelve el id de la ejecución nueva (luego assistWatch). acceptAge: el ingeniero aceptó una reversa de más de 24 h.
  assistStartPendingRollback(runId: string, acceptAge: boolean, assisted: boolean): Promise<string>;
  assistDiscardPendingRollback(runId: string): Promise<void>;
  onAssist(cb: (e: AssistEvent) => void): () => void;
  onAssistDone(cb: (e: AssistDone) => void): () => void;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const portsWails = (call: Call): PortsAPI => ({
  assistPlanPorts: async (r) => JSON.parse(await call<string>("AssistPlanPorts", JSON.stringify(r))),
  assistStart: (p, a) => call("AssistStart", p, a),
  assistWatch: (r) => call("AssistWatch", r),
  assistListRuns: async () => (JSON.parse(await call<string>("AssistListRuns")).runs ?? []) as AssistRunInfo[],
  assistConfirm: (r, s) => call("AssistConfirm", r, s),
  assistAbort: (r) => call("AssistAbort", r),
  assistRollback: (r) => call("AssistRollback", r),
  assistListPendingRollbacks: async () => parsePendingRollbacks(await call<string>("AssistListPendingRollbacks")),
  assistStartPendingRollback: (r, a, s) => call("AssistStartPendingRollback", r, a, s),
  assistDiscardPendingRollback: (r) => call("AssistDiscardPendingRollback", r),
  onAssist: (cb) => Events.On("assist:event", (e) => {
    const d = e.data as { runId: string; event: Omit<AssistEvent, "runId"> };
    cb({ ...d.event, runId: d.runId });
  }),
  onAssistDone: (cb) => Events.On("assist:done", (e) => cb(e.data as AssistDone)),
});
