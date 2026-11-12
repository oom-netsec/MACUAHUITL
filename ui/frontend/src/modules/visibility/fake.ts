// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { VisEvent, VisKind, VisibilityAPI } from "./api";

export function fakeVisibility() {
  const vis = new Set<[VisKind, (e: VisEvent) => void]>();
  return {
    snmpGet: vi.fn(async () => ""),
    snmpWalk: vi.fn(async () => ""),
    snmpPollStart: vi.fn(async () => "v1"),
    trapsStart: vi.fn<VisibilityAPI["trapsStart"]>(async () => "v1"),
    flowsStart: vi.fn<VisibilityAPI["flowsStart"]>(async () => "v1"),
    gnmiGet: vi.fn(async () => ""),
    gnmiSubscribeStart: vi.fn(async () => "v1"),
    onVis: (kind: VisKind, cb: (e: VisEvent) => void) => {
      const entry: [VisKind, (e: VisEvent) => void] = [kind, cb];
      vis.add(entry);
      return () => { vis.delete(entry); };
    },
    emitVis: (kind: VisKind, e: VisEvent) => vis.forEach(([k, cb]) => k === kind && cb(e)),
  };
}
