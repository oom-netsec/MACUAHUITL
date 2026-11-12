// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
// Flota (Fase 15): última evidencia de cada equipo en outputs/. Cada fila trae su hora (at).
export interface FleetHit { kind: string; device: string; port?: string; vlan?: string; mac?: string; ip?: string; name?: string; source: string; at: string }
export interface FindResult { query: string; mode: string; hits: FleetHit[] | null; devices: number; warnings: string[] | null }
export interface TraceHop { device: string; port: string; vlan?: string; neighbor?: string; neighbor_port?: string; note?: string; source: string; at: string }
export interface TraceResult { query: string; mac?: string; ip?: string; hops: TraceHop[] | null; end: string; access?: TraceHop; warnings: string[] | null }
export interface PathSegment { interface: string; mode?: string; vlan?: string; l2?: TraceHop[]; l2_end?: string }
export interface PathHop { id: number; parent: number; device: string; via?: string; out_if?: string; ecmp?: boolean; route?: string; segment?: PathSegment; final?: PathSegment; status: "ok" | "arrived" | "cut"; reason?: string; source?: string; at: string }
export interface PathResult { src: string; dst: string; hops: PathHop[] | null; arrived: boolean; warnings: string[] | null }
export interface IfProblem { kind: string; value?: number; evidence: string }
export interface IfIssue { device: string; port: string; severity: "critica" | "alta" | "media" | "baja"; problems: IfProblem[]; source: string; at: string }
export interface HealthResult { issues: IfIssue[] | null; devices: number; warnings: string[] | null }
export interface SummaryRow { device: string; check: string; value: string; detail?: string; source: string; at: string }
export interface SummaryResult { rows: SummaryRow[] | null; checked: Record<string, number>; devices: number; warnings: string[] | null }
export interface FlashRow { device: string; fs: string; total: number; free: number; used_pct: number; fits?: boolean; at: string }
export interface DramRow { device: string; total: number; pool_free?: number; pool_used_pct?: number; at: string }
export interface CapacityResult { need?: number; flash: FlashRow[] | null; dram: DramRow[] | null; devices: number; warnings: string[] | null }
export interface InvRow { device: string; kind: string; name?: string; descr?: string; pid?: string; vid?: string; serial?: string; model?: string; version?: string; source: string; at: string }
export interface InventoryResult { rows: InvRow[] | null; devices: number; warnings: string[] | null }
/** Clave del catálogo de un texto del json y sus argumentos (fase 30c), por ruta JSON: "rows.2.detail". */
export interface FleetTextKey { key: string; args?: Record<string, string> }
export type FleetTextKeys = Record<string, FleetTextKey>;
interface FleetDTO { json: string; text: string; svg?: string; csv?: string; markdown?: string; keys?: FleetTextKeys }

export interface FleetAPI {
  fleetFind(q: string): Promise<FindResult>;
  fleetTrace(q: string): Promise<TraceResult>;
  fleetPath(src: string, dst: string): Promise<{ result: PathResult; svg: string }>;
  fleetHealth(): Promise<HealthResult>;
  fleetSummary(): Promise<SummaryResult>;
  fleetCapacity(need: string): Promise<CapacityResult>;
  fleetInventory(): Promise<{ result: InventoryResult; csv: string; markdown: string }>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const fleetWails = (call: Call): FleetAPI => ({
  fleetFind: async (q) => JSON.parse((await call<FleetDTO>("FleetFind", q)).json),
  fleetTrace: async (q) => JSON.parse((await call<FleetDTO>("FleetTrace", q)).json),
  fleetPath: async (s, d) => { const r = await call<FleetDTO>("FleetPath", s, d); return { result: JSON.parse(r.json), svg: r.svg ?? "" }; },
  fleetHealth: async () => JSON.parse((await call<FleetDTO>("FleetHealth")).json),
  fleetSummary: async () => JSON.parse((await call<FleetDTO>("FleetSummary")).json),
  fleetCapacity: async (n) => JSON.parse((await call<FleetDTO>("FleetCapacity", n)).json),
  fleetInventory: async () => { const r = await call<FleetDTO>("FleetInventory"); return { result: JSON.parse(r.json), csv: r.csv ?? "", markdown: r.markdown ?? "" }; },
});
