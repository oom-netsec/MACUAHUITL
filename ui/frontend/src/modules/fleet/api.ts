// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
// Flota (Fase 15): última evidencia de cada equipo en outputs/. Cada fila trae su hora (at).
/** Clave del catálogo de un texto del json y sus argumentos (fase 30c), por ruta JSON: "rows.2.detail". */
export interface FleetTextKey { key: string; args?: Record<string, string> }
export type FleetTextKeys = Record<string, FleetTextKey>;
/** Todo resultado trae las claves de sus textos del catálogo (fase 30c) cuando el núcleo las manda. */
export interface Keyed { keys?: FleetTextKeys }
export interface FleetHit { kind: string; device: string; port?: string; vlan?: string; mac?: string; ip?: string; name?: string; source: string; at: string }
export interface FindResult extends Keyed { query: string; mode: string; hits: FleetHit[] | null; devices: number; warnings: string[] | null }
export interface TraceHop { device: string; port: string; vlan?: string; neighbor?: string; neighbor_port?: string; note?: string; source: string; at: string }
export interface TraceResult extends Keyed { query: string; mac?: string; ip?: string; hops: TraceHop[] | null; end: string; access?: TraceHop; warnings: string[] | null }
export interface PathSegment { interface: string; mode?: string; vlan?: string; l2?: TraceHop[]; l2_end?: string }
export interface PathHop { id: number; parent: number; device: string; via?: string; out_if?: string; ecmp?: boolean; route?: string; segment?: PathSegment; final?: PathSegment; status: "ok" | "arrived" | "cut"; reason?: string; source?: string; at: string }
export interface PathResult extends Keyed { src: string; dst: string; hops: PathHop[] | null; arrived: boolean; warnings: string[] | null }
export interface IfProblem { kind: string; value?: number; evidence: string }
export interface IfIssue { device: string; port: string; severity: "critica" | "alta" | "media" | "baja"; problems: IfProblem[]; source: string; at: string }
export interface HealthResult extends Keyed { issues: IfIssue[] | null; devices: number; warnings: string[] | null }
export interface SummaryRow { device: string; check: string; value: string; detail?: string; source: string; at: string }
export interface SummaryResult extends Keyed { rows: SummaryRow[] | null; checked: Record<string, number>; devices: number; warnings: string[] | null }
export interface FlashRow { device: string; fs: string; total: number; free: number; used_pct: number; fits?: boolean; at: string }
export interface DramRow { device: string; total: number; pool_free?: number; pool_used_pct?: number; at: string }
export interface CapacityResult extends Keyed { need?: number; flash: FlashRow[] | null; dram: DramRow[] | null; devices: number; warnings: string[] | null }
export interface InvRow { device: string; kind: string; name?: string; descr?: string; pid?: string; vid?: string; serial?: string; model?: string; version?: string; source: string; at: string }
export interface InventoryResult extends Keyed { rows: InvRow[] | null; devices: number; warnings: string[] | null }
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

/** El json del núcleo con las claves de sus textos. */
const parsed = <T,>(r: FleetDTO): T => (r.keys ? { ...JSON.parse(r.json), keys: r.keys } : JSON.parse(r.json));

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const fleetWails = (call: Call): FleetAPI => ({
  fleetFind: async (q) => parsed(await call<FleetDTO>("FleetFind", q)),
  fleetTrace: async (q) => parsed(await call<FleetDTO>("FleetTrace", q)),
  fleetPath: async (s, d) => { const r = await call<FleetDTO>("FleetPath", s, d); return { result: parsed(r), svg: r.svg ?? "" }; },
  fleetHealth: async () => parsed(await call<FleetDTO>("FleetHealth")),
  fleetSummary: async () => parsed(await call<FleetDTO>("FleetSummary")),
  fleetCapacity: async (n) => parsed(await call<FleetDTO>("FleetCapacity", n)),
  fleetInventory: async () => { const r = await call<FleetDTO>("FleetInventory"); return { result: parsed(r), csv: r.csv ?? "", markdown: r.markdown ?? "" }; },
});
