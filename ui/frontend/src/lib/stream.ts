import { useEffect, useRef } from "react";

// Compartido por Consola serie y Campo (servidor TFTP/HTTP): eventos de una ejecución y limpieza de terminal.
// Consola sencilla (sin emulador de terminal): quita secuencias ANSI y aplica retrocesos.
// shortcut: sin xterm.js no hay pantallas completas ni Tab; agregarlo empaquetado si se necesita.
// max: tope del texto acumulado (al pasarlo se queda con el 75 % final).
export function cleanTerminal(prev: string, chunk: string, max = 200000): string {
  const s = chunk
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "")
    .replace(/\x1b./g, "")
    .replace(/[\x00-\x07\x0b-\x1f\x7f]/g, "");
  let out = prev;
  for (const ch of s) out = ch === "\b" ? out.slice(0, -1) : out + ch;
  return out.length > max ? out.slice(-Math.floor(max * 0.75)) : out;
}

// Une los eventos a su ejecución; los que llegan antes de conocer el ID se guardan.
export function useStream<E extends { runId: string }>(subscribe: (cb: (e: E) => void) => () => void, apply: (e: E) => void) {
  const runRef = useRef("");
  const pending = useRef<E[]>([]);
  const starting = useRef(false);
  const applyRef = useRef(apply);
  applyRef.current = apply;
  useEffect(
    () =>
      subscribe((e) => {
        if (starting.current) pending.current.push(e);
        else if (e.runId === runRef.current) applyRef.current(e);
      }),
    [subscribe],
  );
  const start = async (f: () => Promise<string>) => {
    pending.current = [];
    starting.current = true;
    try {
      const id = await f();
      runRef.current = id;
      starting.current = false;
      const early = pending.current.filter((e) => e.runId === id);
      pending.current = [];
      early.forEach((e) => applyRef.current(e));
      return id;
    } finally {
      starting.current = false;
    }
  };
  // Al salir del módulo (Campo o Consola serie) se desmonta: se cierra la sesión en vez de
  // dejar el puerto tomado o el servidor escuchando sin botón para detenerlo.
  const stopRef = useRef<(id: string) => Promise<void>>(async () => {});
  useEffect(() => () => {
    if (runRef.current) stopRef.current(runRef.current).catch(() => {});
  }, []);
  return { start, clear: () => { runRef.current = ""; }, onUnmount: (f: (id: string) => Promise<void>) => { stopRef.current = f; } };
}
