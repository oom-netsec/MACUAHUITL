import { useCallback, useEffect, useRef, useState } from "react";
import { errorText } from "../components/Field";

/** Una acción asíncrona con su carga y su error (texto con el formato de errorText, "" si no hay). Si fn rechaza, `run` resuelve a undefined. Con dos `run` que se pisan solo el último fija el estado; tras desmontar no hay setState. */
export function useAction<A extends unknown[], R>(fn: (...args: A) => Promise<R>) {
  const [state, setState] = useState({ busy: false, error: "" });
  const last = useRef(0);
  const alive = useRef(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const settle = (id: number, s: { busy: boolean; error: string }) => { if (alive.current && id === last.current) setState(s); };
  const run = useCallback(async (...args: A): Promise<R | undefined> => {
    const id = ++last.current;
    settle(id, { busy: true, error: "" });
    try {
      const r = await fnRef.current(...args);
      settle(id, { busy: false, error: "" });
      return r;
    } catch (e) {
      settle(id, { busy: false, error: errorText(e) });
      return undefined;
    }
  }, []);
  const clearError = useCallback(() => setState((s) => (s.error ? { ...s, error: "" } : s)), []);
  return { run, busy: state.busy, error: state.error, clearError };
}
