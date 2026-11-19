// Una ejecución de diagnóstico en vivo: arranque, líneas por lotes, resumen, resultado, Detener y Cancelar.
// DiagView la usa una vez; la vista combinada de ping y traceroute, una por herramienta (cada una con su runId).
import { useEffect, useRef, useState } from "react";
import { useBusy } from "../../app/activity";
import { useBatch } from "../../lib/useBatch";
import { showHidden, stripAnsi } from "../../lib/safeText";
import type { CoreAPI, DiagEvent, PingSummary, SweepPoint } from "../../lib/core";
import { errorText } from "../../components/Field";
import { useT } from "../../lib/i18n";
import { outputsErrorText } from "../../lib/outputsError";
import { errInfo } from "../../lib/coreError";
import type { ResolvedTarget } from "./api";

export type DiagResult = { ok: boolean; text: string; code?: number; path?: string; canceled?: boolean };
export type DiagSpec = {
  tool: string; targets: string[]; options: Record<string, string>;
  stoppable?: boolean; // ping continuo o con duración: se detiene con resumen
  fam?: "4" | "6" | "?"; interval?: number;
};

export function useDiagRun(core: CoreAPI) {
  const t = useT();
  const [runId, setRunId] = useState("");
  const [lines, setLines] = useState<string[]>([]);
  const [result, setResult] = useState<DiagResult | null>(null);
  const [summary, setSummary] = useState<PingSummary | null>(null);
  const [sweep, setSweep] = useState<SweepPoint[]>([]);
  const [resolved, setResolved] = useState<ResolvedTarget | null>(null);
  const [stoppable, setStoppable] = useState(false);
  const [fam, setFam] = useState<"4" | "6" | "?">("4"); // familia del ping en curso; «?» = Auto con un nombre de host
  const [interval, setInterval_] = useState(1); // segundos entre paquetes: escala el eje de la gráfica
  const [t0, setT0] = useState(0); // inicio en segundos Unix: eje de tiempo de las gráficas
  const [err, setErr] = useState("");
  // Eventos que llegan antes de conocer el ID de la ejecución (un fallo inmediato, la primera línea).
  // Solo se guardan mientras arranca: con varias vistas montadas, una inactiva no acumula lo ajeno.
  const pending = useRef<DiagEvent[]>([]);
  const starting = useRef(false);
  const [launching, setLaunching] = useState(false); // igual que starting pero visible: apaga el botón mientras arranca
  const runRef = useRef("");
  useBusy(!!runId);

  // Las líneas pasan a pantalla una vez cada FLUSH_MS; al terminar se vacía el lote antes de mostrar el resultado.
  const batch = useBatch<string>((b) => setLines((l) => { const all = l.concat(b); return all.length > 5000 ? all.slice(-4000) : all; }));
  const apply = (e: DiagEvent) => {
    if (e.resolved) setResolved(e.resolved);
    if (e.pingSummary) setSummary(e.pingSummary);
    if (e.sweepPoint) setSweep((l) => [...l.filter((p) => p.size !== e.sweepPoint!.size), e.sweepPoint!]);
    if (e.done) {
      batch.flush();
      setStoppable(false);
      setResult(e.canceled ? { ok: false, canceled: true, text: t("diag.canceled") } : e.error
        ? { ok: false, text: t("diag.error", { msg: errorText(new Error(e.error)) }) }
        : { ok: true, text: t("diag.done", { code: e.exitCode ?? 0, path: e.outputPath ?? "" }), code: e.exitCode ?? 0, path: e.outputPath });
      runRef.current = "";
      setRunId("");
    } else if (e.line !== undefined) {
      batch.push(showHidden(stripAnsi(e.line).replace(/\r$/, ""))); // sin ESC; lo demás oculto (bidi, controles) se ve como código
    }
  };
  const applyRef = useRef(apply); // el suscriptor se crea una vez: sin esto se quedaría con el t del primer render
  applyRef.current = apply;
  useEffect(
    () =>
      core.onDiag((e: DiagEvent) => {
        if (starting.current) {
          pending.current.push(e);
          return;
        }
        if (e.runId === runRef.current) applyRef.current(e);
      }),
    [core],
  );

  // `build` corre ya con el arranque tomado (doble clic o clic más Ctrl+Enter: un solo arranque); si devuelve texto, es un error y no arranca.
  const start = async (build: () => Promise<DiagSpec | string> | DiagSpec | string) => {
    if (starting.current) return;
    starting.current = true; setLaunching(true); // antes del await: si no, el segundo disparo pasa
    const spec = await build();
    if (typeof spec === "string") { starting.current = false; setLaunching(false); return setErr(spec); }
    batch.reset(); setErr(""); setLines([]); setResult(null); setSummary(null); setSweep([]); setResolved(null); setT0(Math.floor(Date.now() / 1000));
    setStoppable(!!spec.stoppable); if (spec.fam) setFam(spec.fam); if (spec.interval) setInterval_(spec.interval);
    pending.current = [];
    runRef.current = "";
    try {
      const id = await core.diagRun(spec.tool, spec.targets, spec.options);
      runRef.current = id;
      setRunId(id);
      starting.current = false;
      const early = pending.current.filter((e) => e.runId === id);
      pending.current = [];
      early.forEach((e) => applyRef.current(e));
    } catch (e) {
      starting.current = false;
      setStoppable(false);
      const i = errInfo(e);
      setErr(i?.reason === "diag.err.opt_windows" ? t("diag.err.opt_windows", { key: i.metadata.key ?? "" }) : outputsErrorText(e, t));
    } finally {
      setLaunching(false);
    }
  };
  // NotFound: el ping ya había terminado, no hay nada que detener.
  const stop = () => core.diagStop(runId).catch((e) => { if (!/NotFound/.test(`${errInfo(e)?.code ?? ""} ${String(e)}`)) setErr(errorText(e)); });
  const cancel = () => core.diagCancel(runId).catch((e) => setErr(errorText(e)));
  const started = !!runId || lines.length > 0 || !!result || !!err;

  return { runId, lines, setLines, result, summary, sweep, resolved, stoppable, fam, interval, t0, err, launching, started, start, stop, cancel };
}
