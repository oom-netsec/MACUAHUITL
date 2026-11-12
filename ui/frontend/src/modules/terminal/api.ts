// Contrato del módulo Terminal con el puente (ui/bridge/terminal.go). Eventos: terminal:opened,
// terminal:data y terminal:done, todos con el runId de la pestaña.
import { Events } from "@wailsio/runtime";

export interface TerminalOpenRequest { name: string; address: string; port: number; credentialId: string; accept: string[]; rows: number; cols: number }
export interface TerminalEvent { runId: string; opened?: string; recording?: string; data?: string; error?: string; done?: boolean }

export interface TerminalAPI {
  // Devuelve el id de la sesión; el núcleo rechaza una llave de host nueva con su huella en el error.
  terminalOpen(r: TerminalOpenRequest): Promise<string>;
  terminalSend(runId: string, data: string): Promise<void>;
  // Avisa el tamaño de la terminal en filas y columnas (el puente ya lo manda al núcleo como resize).
  terminalResize(runId: string, rows: number, cols: number): Promise<void>;
  // Cierra la sesión: el núcleo cierra SSH, revoca el guard y lo audita.
  terminalClose(runId: string): Promise<void>;
  onTerminal(cb: (e: TerminalEvent) => void): () => void;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const terminalWails = (call: Call): TerminalAPI => ({
  terminalOpen: (r) => call("TerminalOpen", r),
  terminalSend: (id, d) => call("TerminalSend", id, d),
  terminalResize: (id, rows, cols) => call("TerminalResize", id, rows, cols),
  terminalClose: (id) => call("TerminalClose", id),
  onTerminal: (cb) => {
    const a = Events.On("terminal:opened", (e) => cb(e.data as TerminalEvent));
    const b = Events.On("terminal:data", (e) => cb(e.data as TerminalEvent));
    const c = Events.On("terminal:done", (e) => cb({ ...(e.data as TerminalEvent), done: true }));
    return () => { a(); b(); c(); };
  },
});
