// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
import { Events } from "@wailsio/runtime";

export interface NetInterface { name: string; up: boolean; loopback: boolean; addresses: string[]; hardwareAddr: string }
// contrato provisional, #200: pingSummary y sweepPoint (el puente Go los define después del proto).
export interface PingSummary { sent: number; received: number; lossPct: number; minMs: number; avgMs: number; maxMs: number; mdevMs: number }
export interface SweepPoint { size: number; sent: number; received: number; result: "ok" | "loss" | "frag" }
export interface DiagEvent { runId: string; line?: string; done?: boolean; exitCode?: number; outputPath?: string; error?: string; canceled?: boolean; pingSummary?: PingSummary; sweepPoint?: SweepPoint }

export interface DiagAPI {
  diagRun(tool: string, targets: string[], options: Record<string, string>): Promise<string>;
  diagCancel(runId: string): Promise<void>;
  // contrato provisional, #200: termina el ping con resumen (RPC StopRun); NotFound si ya había terminado.
  diagStop(runId: string): Promise<void>;
  listInterfaces(): Promise<NetInterface[]>;
  onDiag(cb: (e: DiagEvent) => void): () => void;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const diagWails = (call: Call): DiagAPI => ({
  diagRun: (t, a, o) => call("DiagRun", t, a, o),
  diagCancel: (id) => call("DiagCancel", id),
  diagStop: (id) => call("DiagStop", id), // contrato provisional, #200
  listInterfaces: () => call("ListInterfaces"),
  onDiag: (cb) => {
    const a = Events.On("diag:line", (e) => cb(e.data as DiagEvent));
    const b = Events.On("diag:done", (e) => cb({ ...(e.data as DiagEvent), done: true }));
    return () => { a(); b(); };
  },
});
