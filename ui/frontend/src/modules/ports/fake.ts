// Doble del puente de Puertos para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { AssistDone, AssistEvent, AssistRunInfo, FrontPort, PortsPlanResult } from "./api";

export const samplePlan: PortsPlanResult = {
  planId: "p1",
  plan: {
    function: "ports",
    devices: [{
      device: "SW1",
      pre: ["show running-config interface GigabitEthernet1/0/1", "show interfaces GigabitEthernet1/0/1 status"],
      apply: ["interface GigabitEthernet1/0/1", "switchport access vlan 20"],
      rollback: ["interface GigabitEthernet1/0/1", "switchport access vlan 10"],
      post: ["show running-config interface GigabitEthernet1/0/1"],
      expect: [{ command: "show running-config interface GigabitEthernet1/0/1", line: "switchport access vlan 20", present: true }],
    }],
  },
};

// Switch de 24 puertos de acceso más 4 de subida, con un puerto de cada estado.
export function samplePorts(): FrontPort[] {
  const off: Record<number, FrontPort["status"]> = { 3: "notconnect", 7: "notconnect", 18: "notconnect", 9: "disabled", 11: "err-disabled", 12: "monitoring" };
  const access = Array.from({ length: 24 }, (_, i): FrontPort => {
    const n = i + 1;
    const status = off[n] ?? "connected";
    return {
      name: `Gi1/0/${n}`, module: 1, slot: 0, port: n, status, mode: "access",
      vlan: n === 9 || n >= 17 ? "30" : n <= 8 ? "10" : "20",
      speed: status === "connected" ? "a-1000" : "auto", duplex: status === "connected" ? "a-full" : "auto", type: "10/100/1000BaseTX",
      description: n === 14 ? "AP-piso2" : "", poeWatts: status === "connected" && n % 5 === 0 ? 6.4 : undefined,
    };
  });
  const uplinks = Array.from({ length: 4 }, (_, i): FrontPort => ({
    name: `Te1/1/${i + 1}`, module: 1, slot: 1, port: i + 1, status: "connected", mode: i === 3 ? "routed" : "trunk", vlan: i === 3 ? "routed" : "trunk",
    speed: "a-10G", duplex: "full", type: "SFP-10GBase-SR", description: i === 0 ? "Uplink a core" : "",
  }));
  return [...access, ...uplinks];
}

export function fakePorts() {
  const evs = new Set<(e: AssistEvent) => void>();
  const done = new Set<(e: AssistDone) => void>();
  const history: AssistEvent[] = []; // como el núcleo: assistWatch repite desde el primer evento
  return {
    assistPlanPorts: vi.fn(async () => samplePlan),
    assistStart: vi.fn(async () => "r1"),
    assistWatch: vi.fn(async (runId: string) => { history.filter((e) => e.runId === runId).forEach((e) => evs.forEach((cb) => cb(e))); }),
    assistListRuns: vi.fn(async () => [] as AssistRunInfo[]),
    assistConfirm: vi.fn(async () => {}),
    assistAbort: vi.fn(async () => {}),
    assistRollback: vi.fn(async () => {}),
    onAssist: (cb: (e: AssistEvent) => void) => (evs.add(cb), () => { evs.delete(cb); }),
    onAssistDone: (cb: (e: AssistDone) => void) => (done.add(cb), () => { done.delete(cb); }),
    emitAssist: (e: AssistEvent) => { history.push(e); evs.forEach((cb) => cb(e)); },
    emitAssistDone: (e: AssistDone) => done.forEach((cb) => cb(e)),
  };
}
