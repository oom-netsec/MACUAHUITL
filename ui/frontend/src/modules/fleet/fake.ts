// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { CapacityResult, FindResult, HealthResult, InventoryResult, PathResult, SummaryResult, TraceResult } from "./api";

export function fakeFleet() {
  return {
    fleetFind: vi.fn(async () => ({ query: "", mode: "name", hits: [], devices: 0, warnings: [] }) as FindResult),
    fleetTrace: vi.fn(async () => ({ query: "", hops: [], end: "not-found", warnings: [] }) as TraceResult),
    fleetPath: vi.fn(async () => ({ result: { src: "", dst: "", hops: [], arrived: false, warnings: [] } as PathResult, svg: "" })),
    fleetHealth: vi.fn(async () => ({ issues: [], devices: 0, warnings: [] }) as HealthResult),
    fleetSummary: vi.fn(async () => ({ rows: [], checked: {}, devices: 0, warnings: [] }) as SummaryResult),
    fleetCapacity: vi.fn(async () => ({ flash: [], dram: [], devices: 0, warnings: [] }) as CapacityResult),
    fleetInventory: vi.fn(async () => ({ result: { rows: [], devices: 0, warnings: [] } as InventoryResult, csv: "", markdown: "" })),
  };
}
