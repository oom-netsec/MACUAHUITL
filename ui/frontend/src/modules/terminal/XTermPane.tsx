import { useEffect, useRef, useState } from "react";
import { Terminal, type ITheme } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { WebglAddon } from "@xterm/addon-webgl";
import "@xterm/xterm/css/xterm.css";
import { FONT, FONT_PROBE, MARK, TERM_OPTIONS } from "./termTheme";
import { useT } from "../../lib/i18n";

export interface FindReq { q: string; dir: 1 | -1; n: number }
interface Props {
  runId: string; screenReader?: boolean; onCopy: (text: string) => void; onPaste: () => Promise<string>; active: boolean; shown?: boolean; label?: string; done: boolean; theme: ITheme; search?: FindReq;
  bind: (runId: string, write: ((d: string) => void) | null) => void; // la vista manda aquí lo que llega del equipo
  onInput: (d: string) => void; // teclas en crudo hacia el equipo
  onSize: (rows: number, cols: number) => void;
  onResults: (index: number, count: number) => void;
  onLeave: () => void; // Ctrl+Mayús+K: el foco sale de la terminal
}

// Una pestaña de SSH: emulador xterm.js que habla en crudo con el equipo (Tab, flechas, Ctrl-teclas, --More--, pantallas completas).
export default function XTermPane(p: Props) {
  const t = useT();
  const host = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal | null>(null);
  const find = useRef<SearchAddon | null>(null);
  const fit = useRef<() => void>(() => {});
  const props = useRef(p);
  props.current = p;
  const label = p.label ?? t("ssh.output");
  const shown = p.shown ?? p.active; // en pantalla dividida se ven dos paneles, pero solo uno tiene el foco de pestaña
  const [noGL, setNoGL] = useState(false);

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const x = new Terminal({ ...TERM_OPTIONS, screenReaderMode: !!props.current.screenReader, theme: props.current.theme });
    const fa = new FitAddon();
    const sa = new SearchAddon();
    x.loadAddon(fa);
    x.loadAddon(sa);
    x.open(el);
    x.textarea?.setAttribute("aria-label", label);
    term.current = x; find.current = sa;
    let sent = ""; let timer: ReturnType<typeof setTimeout> | undefined;
    // Arrastrar la ventana dispara muchos ajustes: al núcleo llega solo el último, ~100 ms después.
    const notify = () => { clearTimeout(timer); timer = setTimeout(() => { const s = `${x.rows}x${x.cols}`; if (s !== sent) { sent = s; props.current.onSize(x.rows, x.cols); } }, 100); };
    fit.current = () => { if (el.clientWidth > 0 && el.clientHeight > 0) { fa.fit(); notify(); } };
    fit.current();
    x.onData((d) => props.current.onInput(d));
    x.onResize(notify);
    sa.onDidChangeResults((r) => props.current.onResults(r.resultIndex, r.resultCount));
    const pasteClip = () => { void props.current.onPaste().then((txt) => { if (txt) x.paste(txt); }).catch(() => {}); };
    // Copiar/pegar como en las terminales de Linux; Ctrl+C sigue siendo ^C hacia el equipo.
    x.attachCustomKeyEventHandler((e) => {
      if (e.type !== "keydown" || !e.ctrlKey || !e.shiftKey) return true;
      const k = e.key.toLowerCase();
      if (k === "c") { e.preventDefault(); const s = x.getSelection(); if (s) props.current.onCopy(s); return false; }
      // WebKitGTK no manda evento paste para este atajo: se lee el portapapeles y xterm lo pega (con paste entre corchetes si el equipo lo pidió).
      if (k === "v") { e.preventDefault(); pasteClip(); return false; }
      if (k === "k") { e.preventDefault(); x.blur(); props.current.onLeave(); return false; }
      return true;
    });
    // Clic derecho: con selección la copia y la limpia; sin selección pega (mismo camino que Ctrl+Mayús+V).
    const onContext = (e: MouseEvent) => {
      if (x.modes.mouseTrackingMode !== "none" && !e.shiftKey) return; // tmux, htop o vim con mouse: el clic derecho es de la app remota (con Mayús sigue siendo del emulador)
      e.preventDefault();
      const s = x.getSelection();
      if (s) { props.current.onCopy(s); x.clearSelection(); } else pasteClip();
    };
    el.addEventListener("contextmenu", onContext);
    props.current.bind(props.current.runId, (d) => x.write(d));
    const ro = new ResizeObserver(() => fit.current());
    ro.observe(el);
    // Con la fuente cargada la celda mide distinto: xterm solo vuelve a medir si cambia la familia, por eso el truco del espacio.
    let gone = false;
    void document.fonts?.load(FONT_PROBE).then(() => { if (!gone) { x.options.fontFamily = `${FONT} `; fit.current(); } }).catch(() => {});
    return () => { gone = true; el.removeEventListener("contextmenu", onContext); clearTimeout(timer); props.current.bind(props.current.runId, null); ro.disconnect(); x.dispose(); term.current = null; find.current = null; };
  }, []);

  useEffect(() => { if (term.current) term.current.options.theme = p.theme; }, [p.theme]);
  useEffect(() => { if (term.current) { term.current.options.disableStdin = p.done; term.current.options.cursorBlink = !p.done; } }, [p.done]);
  useEffect(() => { if (term.current) term.current.options.screenReaderMode = !!p.screenReader; }, [p.screenReader]);
  useEffect(() => { term.current?.textarea?.setAttribute("aria-label", label); }, [label]);
  // Se dibuja con WebGL: el renderizador DOM de xterm necesita estilos en línea y la CSP de la app (estricta) los rechaza,
  // con lo que la terminal saldría sin fuente fija, columnas ni color. El contexto vive solo mientras el panel se ve
  // (WebKit limita los contextos vivos y suelta el más viejo); al volver a mostrarse se reintenta. Sin WebGL, se avisa.
  useEffect(() => {
    const x = term.current;
    if (!shown || !x) return;
    let gl: WebglAddon | null = null;
    try {
      const g = (gl = new WebglAddon());
      g.onContextLoss(() => { g.dispose(); gl = null; setNoGL(true); });
      x.loadAddon(g); // sin WebGL2, activate() lanza aquí
      setNoGL(false);
    } catch { gl?.dispose(); gl = null; setNoGL(true); }
    return () => gl?.dispose();
  }, [shown]);
  useEffect(() => {
    if (!shown) return;
    const id = requestAnimationFrame(() => { fit.current(); if (props.current.active) term.current?.focus(); }); // visible de nuevo: medir y, si es la activa, tomar el foco
    return () => cancelAnimationFrame(id);
  }, [shown, p.active]);
  useEffect(() => {
    const s = p.search;
    if (!shown || !s || !find.current) return;
    if (!s.q) { find.current.clearDecorations(); return; }
    (s.dir > 0 ? find.current.findNext : find.current.findPrevious).call(find.current, s.q, { decorations: MARK });
  }, [shown, p.search]);

  return (
    <>
      {noGL && <p className="ssh-nogl" role="alert">{t("ssh.noWebgl")}</p>}
      <div ref={host} className="ssh-xterm" role="group" aria-label={label} />
    </>
  );
}
