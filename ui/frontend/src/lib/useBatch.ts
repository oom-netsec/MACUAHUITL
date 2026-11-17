import { useCallback, useEffect, useRef } from "react";

export const MAX_LIVE = 5000; // filas que se conservan en pantalla; los archivos guardan todo
export const FLUSH_MS = 100;

/** Junta los eventos y los entrega a `apply` una vez cada `ms`: bajo inundación no hay un render por evento. Si pasan de 2x `keep`, descarta los más viejos (cuenta todos en `count`). */
export function useBatch<T>(apply: (batch: T[], count: number) => void, keep = MAX_LIVE, ms = FLUSH_MS) {
  const b = useRef<{ q: T[]; n: number; timer?: number }>({ q: [], n: 0 });
  const applyRef = useRef(apply);
  applyRef.current = apply;
  const reset = useCallback(() => { window.clearTimeout(b.current.timer); b.current = { q: [], n: 0 }; }, []);
  const flush = useCallback(() => {
    const cur = b.current;
    window.clearTimeout(cur.timer);
    cur.timer = undefined;
    if (!cur.n) return;
    const { q, n } = cur;
    cur.q = []; cur.n = 0;
    applyRef.current(q, n);
  }, []);
  const push = useCallback((x: T) => {
    const cur = b.current;
    cur.q.push(x);
    cur.n++;
    if (cur.q.length > 2 * keep) cur.q.splice(0, cur.q.length - keep);
    cur.timer ??= window.setTimeout(flush, ms);
  }, [flush, keep, ms]);
  useEffect(() => () => window.clearTimeout(b.current.timer), []);
  return { push, flush, reset };
}
