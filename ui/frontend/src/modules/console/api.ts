// Contrato de la consola serie con el puente (ui/bridge, servicio field) y su implementación de Wails.
import { Events } from "@wailsio/runtime";

export interface ConsoleParams { port: string; baud: number; dataBits: number; parity: string; stopBits: number; flow: string }
export interface ConsoleEvent { runId: string; opened?: string; outputPath?: string; data?: string; done?: boolean; error?: string }

export interface ConsoleAPI {
  fieldPorts(): Promise<string[]>;
  consoleOpen(p: ConsoleParams): Promise<string>;
  consoleSend(runId: string, data: string): Promise<void>;
  consoleBreak(runId: string): Promise<void>;
  consoleClose(runId: string): Promise<void>;
  onConsole(cb: (e: ConsoleEvent) => void): () => void;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const consoleWails = (call: Call): ConsoleAPI => ({
  fieldPorts: () => call("FieldPorts"),
  consoleOpen: (p) => call("ConsoleOpen", p),
  consoleSend: (id, d) => call("ConsoleSend", id, d),
  consoleBreak: (id) => call("ConsoleBreak", id),
  consoleClose: (id) => call("ConsoleClose", id),
  onConsole: (cb) => {
    const a = Events.On("console:opened", (e) => cb(e.data as ConsoleEvent));
    const b = Events.On("console:data", (e) => cb(e.data as ConsoleEvent));
    const c = Events.On("console:done", (e) => cb({ ...(e.data as ConsoleEvent), done: true }));
    return () => { a(); b(); c(); };
  },
});
