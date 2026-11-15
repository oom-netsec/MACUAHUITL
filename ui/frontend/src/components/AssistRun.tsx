// Lo que comparten las vistas del modo de cambio asistido (ADR 0007): mostrar el plan con su reversa, activar el modo por ejecución,
// seguir la ejecución paso a paso y volver a una que quedó viva. Una vista solo arma el formulario y pide el plan.
import { useContext, useEffect, useRef, useState } from "react";
import type { CoreAPI } from "../lib/core";
import type { AssistEvent, AssistRunInfo, AssistStep, PortsPlanResult } from "../modules/ports/api";
import { Check, Notice, errorText } from "./Field";
import { Badge } from "./Page";
import { Icon } from "./Icon";
import { Hl, Terminal } from "./Terminal";
import { PendingRollbacks } from "./PendingRollbacks";
import { useT } from "../lib/i18n";
import { vocab } from "../lib/vocab";
import type { Key } from "../lib/i18n/es";
import { ModuleIdContext } from "../app/activity";
import { assistOwner, assistOwnerKey } from "../app/useShellStatus";
import { showHidden } from "../lib/safeText";

export type AssistRunCore = Pick<CoreAPI, "assistStart" | "assistWatch" | "assistListRuns" | "assistConfirm" | "assistAbort" | "assistRollback" | "onAssist" | "onAssistDone" | "assistListPendingRollbacks" | "assistStartPendingRollback" | "assistDiscardPendingRollback">;

interface RunState {
  id: string;
  active: boolean; // desde que arranca hasta que el núcleo cierra el stream
  state: string;
  pending: AssistStep | null;
  failReason: string;
  stopped: boolean; // la ejecución se detuvo y espera: reversa o abortar
  changed: string[]; // equipos cambiados que siguen cambiados
  log: string[];
  offline?: boolean; // se cortó el stream y no se pudo reenganchar solo: la ejecución sigue viva en el núcleo, «Volver a enganchar»
  notes?: Record<string, string[]>; // avisos del plan por equipo: el plan se gasta al iniciar y los avisos se repiten en sus pasos
  unsaved?: string[]; // llegó el paso close: los equipos cambiados quedan solo en running-config (sin write memory)
}

const finalText: Record<string, Key> = {
  done: "assist.final.done",
  aborted: "assist.final.aborted",
  "rolled-back": "assist.final.rolled-back",
  failed: "assist.final.failed",
  abandoned: "assist.final.abandoned",
};

// changedText avisa de los equipos que la ejecución cambió y no se revirtieron.
function changedText(changed: string[], t: ReturnType<typeof useT>): string {
  return changed.length === 0 ? "" : t("assist.changed", { n: changed.length, x: changed.join(", ") });
}

// protojson omite device y lines vacíos: el paso se guarda ya completo para que nada lea undefined.
const stepOf = (s: AssistStep): AssistStep => ({ ...s, device: s.device ?? "", lines: s.lines ?? [] });

// Reenganches seguidos, sin eventos nuevos, que se intentan tras cortes del stream antes de cerrar la vista con el error.
const MAX_REATTACH = 3;

// fromInfo arma el estado de la vista para una ejecución que seguía viva al abrir el módulo.
function fromInfo(i: AssistRunInfo): RunState {
  return { id: i.runId, active: true, state: i.state ?? "running", pending: i.pending ? stepOf(i.pending) : null, failReason: i.failReason ?? "",
    stopped: i.state === "failed" && !!i.waiting, changed: i.changed ?? [], log: [] };
}

// splitTarget separa "host[:puerto]"; las direcciones IPv6 quedan sin puerto.
export function splitTarget(s: string): { address: string; port?: number } {
  const m = /^([^:]+):(\d{1,5})$/.exec(s);
  return m ? { address: m[1], port: Number(m[2]) } : { address: s };
}

// target arma el destino de una petición de plan desde lo que escribió el ingeniero.
export function targetOf(equipo: string, credentialId: string) {
  const t = splitTarget(equipo.trim());
  return { name: equipo.trim(), address: t.address, ...(t.port ? { port: t.port } : {}), credentialId };
}

// Líneas de configuración con su marca (+ aplicar, ↺ reversa) y resaltado de palabras clave.
export function CodeLines({ lines, mark }: { lines: string[]; mark?: string }) {
  return <pre className="code">{lines.map((l, i) => <div key={i}>{mark && <span className="mark" aria-hidden="true">{mark} </span>}<Hl text={showHidden(l)} /></div>)}</pre>;
}

export function PlanView({ r }: { r: PortsPlanResult }) {
  const t = useT();
  return (
    <div className="plan">
      {r.plan.devices.map((d) => (
        <section key={d.device} className="panel flush plan-device" aria-label={t("assist.planFor", { device: d.device })}>
          <header className="panel-head">
            <h3>{t("assist.planFor", { device: d.device })}</h3>
            <Badge tone="warn">{t("assist.lineCount", { n: d.apply.length })}</Badge>
          </header>
          {(d.notes ?? []).length > 0 && (
            <div className="panel-body plan-notes">
              <Notice kind="warn"><strong>{t("assist.notes")}</strong><ul className="notes">{(d.notes ?? []).map((n, i) => <li key={i}>{n}</li>)}</ul></Notice>
            </div>
          )}
          <div className="plan-grid">
            <section aria-label={t("assist.apply")} className="plan-block apply"><h4>{t("assist.apply")}</h4><CodeLines lines={d.apply} mark="+" /></section>
            <section aria-label={t("assist.rollback")} className="plan-block rollback"><h4>{t("assist.rollback.title")}</h4><CodeLines lines={d.rollback} mark="↺" /></section>
          </div>
          <details className="plan-more"><summary>{t("assist.prePost")}</summary><CodeLines lines={[...d.pre, "—", ...d.post]} /></details>
          <details className="plan-more" open><summary>{t("assist.expect")}</summary>
            <ul>{(d.expect ?? []).map((e, i) => <li key={i}><Badge tone={e.present ? "ok" : "bad"}>{t(e.present ? "assist.expect.present" : "assist.expect.absent")}</Badge><code>{e.line.replaceAll("\u001f", " > ")}</code></li>)}</ul>
          </details>
        </section>
      ))}
      {r.plan.writeMemory && <p className="meta">{t("assist.writeMem.end")}</p>}
    </div>
  );
}

// Paso que espera decisión. "Aplicar" no recibe el foco y se habilita tras un momento: nunca se confirma por inercia.
export const CONFIRM_DELAY_MS = 1500;
function PendingStep({ step, changed, notes, ready, reapply, onConfirm, onRevert, onAbort }: { step: AssistStep; changed: string[]; notes: string[]; ready: boolean; reapply: boolean; onConfirm: () => void; onRevert: () => void; onAbort: () => void }) {
  const t = useT();
  const head = useRef<HTMLHeadingElement>(null);
  useEffect(() => { head.current?.focus(); }, [step.id]); // el paso nuevo anuncia su título; el foco no cae en «Aplicar»
  const lines = step.lines ?? []; // protojson omite la lista vacía (el paso close no trae líneas)
  const device = step.device ?? "";
  const n = lines.length;
  // "close": sin write memory el motor espera al final; el cambio queda solo en running-config o se revierte en todos los equipos.
  const close = step.kind === "close";
  const label = step.kind === "rollback" ? t("assist.confirm.rollback", { device, id: step.id })
    : step.kind === "save" ? t("assist.confirm.save", { device, id: step.id })
    : close ? t("assist.confirm.close")
    : t("assist.confirm.apply", { n, device, id: step.id });
  return (
    <section className="panel flush pending-step" aria-label={t("assist.pending", { id: step.id })}>
      <header className="panel-head">
        <h4 ref={head} tabIndex={-1}>{t(step.kind === "rollback" ? "assist.step.rollback" : step.kind === "save" ? "assist.step.save" : close ? "assist.step.close" : "assist.step.apply", { device })}</h4>
        <Badge tone="warn">{t("assist.waiting")}</Badge>
      </header>
      <div className="panel-body">
        {notes.length > 0 && <Notice kind="warn"><strong>{t("assist.notes")}</strong><ul className="notes">{notes.map((n, i) => <li key={i}>{n}</li>)}</ul></Notice>}
        {close ? <><p>{t("assist.close.desc")}</p>{changed.length > 0 && <p className="meta">{t("assist.close.changed", { x: changed.join(", ") })}</p>}</> : <>
          <p className="meta">{t("assist.lines")}</p>
          <CodeLines lines={lines} mark={step.kind === "rollback" ? "↺" : "+"} />
        </>}
        <div className="actions">
          <button className="primary" disabled={!ready} onClick={onConfirm}>{label}</button>
          {(step.kind === "apply" || step.kind === "save" || close) && <button onClick={onRevert}>{t(reapply ? "assist.reapply" : close ? "assist.revert.all" : "assist.revert")}</button>}
          <button className="quiet" onClick={onAbort}>{t("assist.abort")}</button>
        </div>
      </div>
    </section>
  );
}

// AssistBanner es el aviso rojo permanente mientras hay una ejecución viva.
export function AssistBanner({ active }: { active: boolean }) {
  const t = useT();
  if (!active) return null;
  return (
    <div role="alert" className="assist-banner">
      <Icon name="alert" />{t("assist.banner")}
    </div>
  );
}

// AssistExecution muestra el plan (si hay), pide activar el modo para esta ejecución y sigue la ejecución. onActive avisa si hay una viva
// (para apagar el botón de planear); onStarted, que el plan ya se usó (se usa una sola vez); onError, un fallo del núcleo.
export function AssistExecution({ core, plan, start, onStarted, onActive, onError }: {
  core: AssistRunCore;
  plan: PortsPlanResult | null;
  start?: (assisted: boolean) => Promise<string>; // otra forma de arrancar (reversa pendiente); por omisión assistStart del plan
  onStarted: () => void;
  onActive: (active: boolean) => void;
  onError: (msg: string) => void;
}) {
  const t = useT();
  const moduleId = useContext(ModuleIdContext);
  const [armed, setArmed] = useState(false); // por ejecución: nunca se recuerda
  const [run, setRun] = useState<RunState | null>(null);
  const hasStart = !!start;
  const runId = useRef("");
  const lastSeq = useRef(0); // el núcleo repite el historial: un seq ya visto no se aplica dos veces
  // Reenganches tras un corte del stream: se cuentan seguidos hasta que llega un evento nuevo de verdad (seq mayor que el máximo visto en
  // la ejecución, que no vuelve a 0 al reenganchar). Un evento que rompe el stream en cada repetición no deja la vista reenganchando sin fin.
  const maxSeq = useRef(0);
  const retries = useRef(0);
  const starting = useRef(false); // doble clic en «Iniciar»: un solo assistStart
  const [ready, setReady] = useState(false); // «Aplicar» habilitado; el aviso vive aquí, siempre montado, para que los lectores lo lean
  const head = useRef<HTMLHeadingElement>(null);
  const hadPending = useRef(false);

  useEffect(() => setArmed(false), [plan]);
  useEffect(() => { onActive(!!run?.active); }, [run?.active, onActive]);
  const pid = run?.pending?.id;
  useEffect(() => {
    setReady(false);
    if (!pid) return;
    const id = window.setTimeout(() => setReady(true), CONFIRM_DELAY_MS);
    return () => window.clearTimeout(id);
  }, [pid]);
  // Al quedar sin paso (confirmado, abortado) el paso se desmonta con el foco dentro: pasa al encabezado de la ejecución.
  useEffect(() => {
    if (pid) hadPending.current = true;
    else if (hadPending.current) { hadPending.current = false; if (document.activeElement === document.body) head.current?.focus(); }
  }, [pid]);
  const onErrorRef = useRef(onError); // el suscriptor de eventos vive todo el montaje: usa siempre el onError vigente
  onErrorRef.current = onError;

  useEffect(() => {
    const off1 = core.onAssist((e: AssistEvent) => {
      if (e.runId !== runId.current) return;
      // El primer evento (seq 0) llega sin seq (protojson omite el 0) y se aplica siempre: con un solo módulo enganchado por
      // ejecución solo se repetiría al reenganchar, y es el estado inicial, que no cambia nada al repetirse.
      if (e.seq) { if (e.seq <= lastSeq.current) return; lastSeq.current = e.seq; }
      if ((e.seq ?? 0) > maxSeq.current) { maxSeq.current = e.seq!; retries.current = 0; }
      setRun((r) => {
        if (!r) return r;
        const n = { ...r, changed: e.changed ?? [] }; // cada evento trae los equipos cambiados al emitirse
        if (e.kind === "state") {
          n.state = e.state ?? n.state;
          n.pending = null;
          n.stopped = false;
        } else if (e.kind === "pending" && e.step) {
          if (e.step.kind === "close") n.unsaved = e.changed ?? [];
          n.pending = stepOf(e.step);
          n.stopped = false;
        } else if (e.kind === "fail") {
          n.failReason = e.text ?? "";
          n.stopped = true;
          n.state = "failed";
        } else if (e.kind === "output") {
          const line = `${e.device ?? ""}: ${(e.text ?? "").trimEnd()}`;
          n.log = n.log.length > 5000 ? [...n.log.slice(-4000), line] : [...n.log, line]; // tope: el núcleo repite el historial al reenganchar
        }
        return n;
      });
    });
    const off2 = core.onAssistDone(async (e) => {
      if (e.runId !== runId.current) return;
      // Un done con error puede ser solo el corte del stream (IPC, transporte) con la ejecución viva en el núcleo: entonces se vuelve a
      // enganchar (el núcleo repite desde seq 0) en lugar de cerrar la vista y perder el paso pendiente. Si no se puede preguntar, se cierra.
      let failed = false;
      const live = await core.assistListRuns().then((rs) => rs.find((x) => x.runId === e.runId && x.active), () => { failed = true; return undefined; });
      if (e.runId !== runId.current) return;
      // Si no se pudo preguntar (corte del IPC) o se agotaron los reenganches, la ejecución puede seguir viva: no se cierra, queda «sin conexión».
      if (failed || (live && retries.current >= MAX_REATTACH)) {
        setRun((r) => (r ? { ...r, offline: true } : r));
        return;
      }
      if (live) {
        retries.current++;
        lastSeq.current = 0;
        setRun((r) => ({ ...fromInfo(live), notes: r?.notes })); // estado del núcleo (paso pendiente incluido) y registro vacío: la repetición lo vuelve a llenar sin duplicar
        core.assistWatch(e.runId).catch((err) => onErrorRef.current(errorText(err)));
        return;
      }
      setRun((r) => (r ? { ...r, active: false, pending: null, stopped: false, failReason: r.failReason || e.error || "" } : r));
    });
    return () => { off1(); off2(); };
  }, [core]);

  // Al abrir el módulo, volver a una ejecución que quedó viva (la ventana se cerró o se reinició la UI).
  useEffect(() => {
    if (hasStart) return; // una reversa pendiente maneja solo la suya: no le roba el stream a otra ejecución viva
    let alive = true;
    core.assistListRuns().then((runs) => {
      // La engancha el módulo dueño. Una sin dueño (almacenamiento borrado, o iniciada desde mctl) la toma el primer módulo
      // que la vea y queda como su dueño: así la franja del shell lleva a él y nunca se queda sin quién la confirme o aborte.
      // Primero la propia: si también hay una sin dueño, no se queda con esa y deja la suya sin vista.
      const live = runs.find((r) => r.active && assistOwner(r.runId) === moduleId) ?? runs.find((r) => r.active && !assistOwner(r.runId));
      if (!alive || !live || runId.current) return;
      if (!assistOwner(live.runId) && moduleId) try { localStorage.setItem(assistOwnerKey(live.runId), moduleId); } catch { /* sin almacenamiento */ }
      runId.current = live.runId; lastSeq.current = 0; maxSeq.current = 0; retries.current = 0;
      setRun((r) => ({ ...fromInfo(live), notes: r?.notes }));
      return core.assistWatch(live.runId); // el núcleo repite el historial: el estado se reconstruye solo
    }).catch((e) => alive && onError(errorText(e)));
    return () => { alive = false; };
  }, [core, onError, moduleId, hasStart]);

  // Volver a enganchar la ejecución que quedó sin conexión: si el núcleo ya no la tiene viva, la vista se cierra.
  const reattach = async () => {
    const id = runId.current;
    try {
      const live = (await core.assistListRuns()).find((x) => x.runId === id && x.active);
      if (id !== runId.current) return;
      if (!live) { setRun((r) => (r ? { ...r, active: false, pending: null, stopped: false, offline: false } : r)); return; }
      lastSeq.current = 0; retries.current = 0;
      setRun((r) => ({ ...fromInfo(live), notes: r?.notes }));
      await core.assistWatch(id);
    } catch (e) {
      onError(errorText(e));
    }
  };

  const doStart = async () => {
    if (!plan || !armed || starting.current) return;
    starting.current = true; // antes del await: el segundo clic no pasa
    onError("");
    try {
      const id = await (start ? start(true) : core.assistStart(plan.planId, true));
      runId.current = id; lastSeq.current = 0; maxSeq.current = 0; retries.current = 0;
      // El núcleo no sabe qué módulo inició la ejecución; la franja del shell lo necesita para llevar de vuelta.
      try { if (moduleId) localStorage.setItem(assistOwnerKey(id), moduleId); } catch { /* sin almacenamiento */ }
      const notes = Object.fromEntries(plan.plan.devices.filter((d) => (d.notes ?? []).length > 0).map((d) => [d.device, d.notes!]));
      setRun({ id, active: true, state: "running", pending: null, failReason: "", stopped: false, changed: [], log: [], notes });
      onStarted(); setArmed(false); // el plan se usa una sola vez
      await core.assistWatch(id); // con el id ya guardado: el núcleo repite desde el primer evento, ninguno se pierde
    } catch (e) {
      onError(errorText(e));
    } finally {
      starting.current = false;
    }
  };

  const act = (f: () => Promise<void>) => f().catch((e) => onError(errorText(e)));
  const terminal = run && !run.active && finalText[run.state] ? t(finalText[run.state]) : "";

  return (
    <div data-assist>
      {plan && (
        <>
          {!start && <PlanView r={plan} />}
          <Check label={t("assist.arm")} checked={armed} onChange={setArmed} />
          <div className="actions"><button className="danger" disabled={!armed} onClick={doStart}>{t("assist.start", { n: plan.plan.devices.length })}</button></div>
        </>
      )}

      {run && (
        <div>
          <header className="page-head run-head"><h3 ref={head} tabIndex={-1}>{t("assist.run", { id: run.id, state: vocab(t, "assistState", run.state) })}</h3></header>
          <p className="meta" role="status">{run.pending ? t(ready ? "assist.ready" : run.pending.kind === "close" ? "assist.readFirst.close" : "assist.readFirst") : ""}</p>
          {run.offline && run.active && (
            <div>
              <Notice kind="warn">{t("assist.offline")}</Notice>
              <div className="actions"><button onClick={reattach}>{t("assist.reattach")}</button></div>
            </div>
          )}
          {run.pending && (
            <PendingStep key={run.pending.id} step={run.pending} changed={run.changed} notes={run.notes?.[run.pending.device ?? ""] ?? []} ready={ready} reapply={hasStart} onConfirm={() => act(() => core.assistConfirm(run.id, run.pending!.id))}
              onRevert={() => act(() => core.assistRollback(run.id))} onAbort={() => act(() => core.assistAbort(run.id))} />
          )}
          {run.stopped && (
            <div>
              <Notice kind="error">{t("assist.stopped", { reason: run.failReason })}{run.changed.length > 0 && <> {changedText(run.changed, t)}</>}</Notice>
              <div className="actions">
                <button onClick={() => act(() => core.assistRollback(run.id))}>{t("assist.proposeRollback")}</button>
                <button onClick={() => act(() => core.assistAbort(run.id))}>{t("assist.abort")}</button>
              </div>
            </div>
          )}
          {run.active && !run.pending && !run.stopped && <div className="actions"><button className="quiet" onClick={() => act(() => core.assistAbort(run.id))}>{t("assist.abort")}</button></div>}
          {!run.active && run.failReason && !run.stopped && <Notice kind="error">{t("assist.reason", { reason: run.failReason })}</Notice>}
          {terminal && <Notice kind={run.state === "done" || run.state === "rolled-back" ? "ok" : "info"}>{terminal}</Notice>}
          {!run.active && run.state === "done" && run.unsaved && <Notice kind="warn">{t("assist.final.unsaved", { x: run.unsaved.join(", ") || "—" })}</Notice>}
          {!run.active && run.state !== "done" && run.state !== "rolled-back" && run.changed.length > 0 && <><p role="status" className="warn">{changedText(run.changed, t)}</p><PendingRollbacks core={core} runId={run.id} onActive={onActive} /></>}
          <details className="plan-more"><summary>{t("assist.deviceOutput")}</summary><Terminal text={run.log.join("\n")} /></details>
        </div>
      )}
    </div>
  );
}
