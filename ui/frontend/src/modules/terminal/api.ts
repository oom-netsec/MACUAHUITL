// Contrato del módulo Terminal con el puente (ui/bridge/terminal.go). Eventos: terminal:opened,
// terminal:data, terminal:auth y terminal:done, todos con el runId de la pestaña.
import { Events } from "@wailsio/runtime";
import type { AcceptedKey } from "../../lib/hostkeys";

// expectedStartupCommand: la orden de inicio que la UI le mostró a la persona (vacía = el host no debe tener); si no es la guardada el núcleo no conecta.
// Con hostId el núcleo usa dirección, puerto, credencial y orden de inicio del host guardado; la UI no manda address, port ni credentialId.
export interface TerminalOpenRequest { name: string; hostId?: string; address?: string; port?: number; credentialId?: string; username?: string; expectedStartupCommand?: string; accept: string[]; acceptedKeys?: AcceptedKey[]; rows: number; cols: number; protocol?: "telnet" }
// Pregunta de autenticación del equipo (terminal:auth): name, instruction y una pregunta por campo; echo=false es secreto.
export interface AuthQuestion { text: string; echo: boolean }
export interface AuthPrompt { seq: number; name: string; instruction: string; prompts: AuthQuestion[] }
export interface TerminalEvent extends Partial<AuthPrompt> { runId: string; opened?: string; protocol?: "ssh" | "telnet"; recording?: string; data?: string; error?: string; errorInfo?: { code?: string; reason?: string; metadata?: Record<string, string> }; done?: boolean }

export interface TerminalAPI {
  // Devuelve el id de la sesión; el núcleo rechaza una llave de host nueva con su huella en el error.
  terminalOpen(r: TerminalOpenRequest): Promise<string>;
  terminalSend(runId: string, data: string): Promise<void>;
  // Avisa el tamaño de la terminal en filas y columnas (el puente ya lo manda al núcleo como resize).
  terminalResize(runId: string, rows: number, cols: number): Promise<void>;
  // Responde una ronda de preguntas (una respuesta por pregunta, mismo seq). Son secretos: quien llama no las guarda.
  terminalAnswer(runId: string, seq: number, answers: string[]): Promise<void>;
  // Cierra la sesión: el núcleo cierra SSH, revoca el guard y lo audita.
  terminalClose(runId: string): Promise<void>;
  onTerminal(cb: (e: TerminalEvent) => void): () => void;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const terminalWails = (call: Call): TerminalAPI => ({
  terminalOpen: (r) => call("TerminalOpen", r),
  terminalSend: (id, d) => call("TerminalSend", id, d),
  terminalResize: (id, rows, cols) => call("TerminalResize", id, rows, cols),
  terminalAnswer: (id, seq, a) => call("TerminalAnswer", id, seq, a),
  terminalClose: (id) => call("TerminalClose", id),
  onTerminal: (cb) => {
    const a = Events.On("terminal:opened", (e) => cb(e.data as TerminalEvent));
    const b = Events.On("terminal:data", (e) => cb(e.data as TerminalEvent));
    const c = Events.On("terminal:done", (e) => cb({ ...(e.data as TerminalEvent), done: true }));
    const d = Events.On("terminal:auth", (e) => cb(e.data as TerminalEvent));
    return () => { a(); b(); c(); d(); };
  },
});
