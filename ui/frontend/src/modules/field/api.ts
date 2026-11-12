// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
import { Events } from "@wailsio/runtime";

export interface ServeRequest { protocol: string; addr: string; files: string[]; allowAny: boolean; seconds: number }
export interface ServeEvent { runId: string; listening?: string; hint?: string; transfer?: string; done?: boolean; error?: string }

export interface FieldAPI {
  serveStart(r: ServeRequest): Promise<string>;
  onServe(cb: (e: ServeEvent) => void): () => void;
  fieldHash(path: string, md5: string, sha512: string): Promise<{ text: string; ok: boolean }>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const fieldWails = (call: Call): FieldAPI => ({
  serveStart: (r) => call("ServeStart", r),
  onServe: (cb) => {
    const a = Events.On("serve:msg", (e) => cb(e.data as ServeEvent));
    const b = Events.On("serve:done", (e) => cb({ ...(e.data as ServeEvent), done: true }));
    return () => { a(); b(); };
  },
  fieldHash: (p, m, s) => call("FieldHash", p, m, s),
});
