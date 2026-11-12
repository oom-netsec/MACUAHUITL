// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
import { Events } from "@wailsio/runtime";

export interface NetInterface { name: string; up: boolean; loopback: boolean; addresses: string[]; hardwareAddr: string }
export interface DiagEvent { runId: string; line?: string; done?: boolean; exitCode?: number; outputPath?: string; error?: string }

export interface DiagAPI {
  diagRun(tool: string, targets: string[], options: Record<string, string>): Promise<string>;
  diagCancel(runId: string): Promise<void>;
  listInterfaces(): Promise<NetInterface[]>;
  onDiag(cb: (e: DiagEvent) => void): () => void;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const diagWails = (call: Call): DiagAPI => ({
  diagRun: (t, a, o) => call("DiagRun", t, a, o),
  diagCancel: (id) => call("DiagCancel", id),
  listInterfaces: () => call("ListInterfaces"),
  onDiag: (cb) => {
    const a = Events.On("diag:line", (e) => cb(e.data as DiagEvent));
    const b = Events.On("diag:done", (e) => cb({ ...(e.data as DiagEvent), done: true }));
    return () => { a(); b(); };
  },
});
