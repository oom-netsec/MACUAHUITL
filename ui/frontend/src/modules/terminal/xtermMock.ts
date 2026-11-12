// Dobles de xterm.js para pruebas: jsdom no tiene canvas ni medidas de layout. Se usan con
// vi.mock("@xterm/xterm", ...) y compañía; FakeTerm.all guarda cada emulador creado, en orden.
import { vi } from "vitest";

export class FakeTerm {
  static all: FakeTerm[] = [];
  rows = 24; cols = 80; modes = { mouseTrackingMode: "none" }; // "any" = una app remota (tmux, vim) controla el mouse
  options: Record<string, unknown>; textarea = document.createElement("textarea");
  write = vi.fn(); paste = vi.fn(); focus = vi.fn(); blur = vi.fn(); dispose = vi.fn(); loadAddon = vi.fn(); open = vi.fn(); getSelection = vi.fn(() => ""); clearSelection = vi.fn();
  private data: (d: string) => void = () => {};
  keyHandler: (e: KeyboardEvent) => boolean = () => true;
  constructor(o: Record<string, unknown> = {}) { this.options = { ...o }; FakeTerm.all.push(this); }
  onData(f: (d: string) => void) { this.data = f; }
  onResize() {}
  attachCustomKeyEventHandler(f: (e: KeyboardEvent) => boolean) { this.keyHandler = f; }
  type(d: string) { this.data(d); } // lo que teclearía el usuario
}
export class FakeFit { fit = vi.fn(); }
export class FakeSearch {
  static all: FakeSearch[] = [];
  findNext = vi.fn(); findPrevious = vi.fn(); clearDecorations = vi.fn();
  private res: (r: { resultIndex: number; resultCount: number }) => void = () => {};
  constructor() { FakeSearch.all.push(this); }
  onDidChangeResults(f: (r: { resultIndex: number; resultCount: number }) => void) { this.res = f; }
  report(resultIndex: number, resultCount: number) { this.res({ resultIndex, resultCount }); }
}
// WebGL: `fail` simula un equipo sin WebGL (el constructor revienta); `lose()` simula perder el contexto ya dibujando.
export class FakeWebgl {
  static all: FakeWebgl[] = [];
  static fail = false;
  lost: (() => void) | null = null;
  dispose = vi.fn();
  constructor() { if (FakeWebgl.fail) throw new Error("WebGL2 no disponible"); FakeWebgl.all.push(this); }
  onContextLoss(f: () => void) { this.lost = f; return { dispose() {} }; }
}
