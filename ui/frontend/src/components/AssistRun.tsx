// Lo que comparten las vistas del modo de cambio asistido (ADR 0007): mostrar el plan con su reversa, activar el modo por ejecución,
// seguir la ejecución paso a paso y volver a una que quedó viva. Una vista solo arma el formulario y pide el plan.
import { useContext, useEffect, useRef, useState } from "react";
import type { CoreAPI } from "../lib/core";
import type { AssistEvent, AssistRunInfo, AssistStep, PortsPlanResult } from "../modules/ports/api";
import { Check, Notice, errorText } from "./Field";
import { Badge } from "./Page";
import { Icon } from "./Icon";
import { Hl, Terminal } from "./Terminal";
import { useT } from "../lib/i18n";
import { vocab } from "../lib/vocab";
import type { Key } from "../lib/i18n/es";
import { ModuleIdContext } from "../app/activity";
import { assistOwner, assistOwnerKey } from "../app/useShellStatus";

export type AssistRunCore = Pick<CoreAPI, "assistStart" | "assistWatch" | "assistListRuns" | "assistConfirm" | "assistAbort" | "assistRollback" | "onAssist" | "onAssistDone">;

interface RunState {
  id: string;
  active: boolean; // desde que arranca hasta que el núcleo cierra el stream
  state: string;
  pending: AssistStep | null;
  failReason: string;
  stopped: boolean; // la ejecución se detuvo y espera: reversa o abortar
  changed: string[]; // equipos cambiados que siguen cambiados
  log: string[];
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
function CodeLines({ lines, mark }: { lines: string[]; mark?: string }) {
  return <pre className="code">{lines.map((l, i) => <div key={i}>{mark && <span className="mark" aria-hidden="true">{mark} </span>}<Hl text={l} /></div>)}</pre>;
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
function PendingStep({ step, changed, onConfirm, onRevert, onAbort }: { step: AssistStep; changed: string[]; onConfirm: () => void; onRevert: () => void; onAbort: () => void }) {
  const t = useT();
  const [ready, setReady] = useState(false);
  useEffect(() => {
    setReady(false);
    const id = window.setTimeout(() => setReady(true), CONFIRM_DELAY_MS);
    return () => window.clearTimeout(id);
  }, [step.id]);
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
        <h4>{t(step.kind === "rollback" ? "assist.step.rollback" : step.kind === "save" ? "assist.step.save" : close ? "assist.step.close" : "assist.step.apply", { device })}</h4>
        <Badge tone="warn">{t("assist.waiting")}</Badge>
      </header>
      <div className="panel-body">
        {close ? <><p>{t("assist.close.desc")}</p>{changed.length > 0 && <p className="meta">{t("assist.close.changed", { x: changed.join(", ") })}</p>}</> : <>
          <p className="meta">{t("assist.lines")}</p>
          <CodeLines lines={lines} mark={step.kind === "rollback" ? "↺" : "+"} />
        </>}
        <div className="actions">
          <button className="primary" disabled={!ready} onClick={onConfirm}>{label}</button>
          {(step.kind === "apply" || step.kind === "save" || close) && <button onClick={onRevert}>{t(close ? "assist.revert.all" : "assist.revert")}</button>}
          <button className="quiet" onClick={onAbort}>{t("assist.abort")}</button>
          {!ready && <span className="meta" role="status">{t(close ? "assist.readFirst.close" : "assist.readFirst")}</span>}
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
export function AssistExecution({ core, plan, onStarted, onActive, onError }: {
  core: AssistRunCore;
  plan: PortsPlanResult | null;
  onStarted: () => void;
  onActive: (active: boolean) => void;
  onError: (msg: string) => void;
}) {
  const t = useT();
  const moduleId = useContext(ModuleIdContext);
  const [armed, setArmed] = useState(false); // por ejecución: nunca se recuerda
  const [run, setRun] = useState<RunState | null>(null);
  const runId = useRef("");
  const lastSeq = useRef(0); // el núcleo repite el historial: un seq ya visto no se aplica dos veces

  useEffect(() => setArmed(false), [plan]);
  useEffect(() => { onActive(!!run?.active); }, [run?.active, onActive]);

  useEffect(() => {
    const off1 = core.onAssist((e: AssistEvent) => {
      if (e.runId !== runId.current) return;
      // El primer evento (seq 0) llega sin seq (protojson omite el 0) y se aplica siempre: con un solo módulo enganchado por
      // ejecución solo se repetiría al reenganchar, y es el estado inicial, que no cambia nada al repetirse.
      if (e.seq) { if (e.seq <= lastSeq.current) return; lastSeq.current = e.seq; }
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
          n.log = [...n.log, `${e.device ?? ""}: ${(e.text ?? "").trimEnd()}`];
        }
        return n;
      });
    });
    const off2 = core.onAssistDone((e) => {
      if (e.runId !== runId.current) return;
      setRun((r) => (r ? { ...r, active: false, pending: null, stopped: false, failReason: r.failReason || e.error || "" } : r));
    });
    return () => { off1(); off2(); };
  }, [core]);

  // Al abrir el módulo, volver a una ejecución que quedó viva (la ventana se cerró o se reinició la UI).
  useEffect(() => {
    let alive = true;
    core.assistListRuns().then((runs) => {
      // La engancha el módulo dueño. Una sin dueño (almacenamiento borrado, o iniciada desde mctl) la toma el primer módulo
      // que la vea y queda como su dueño: así la franja del shell lleva a él y nunca se queda sin quién la confirme o aborte.
      const live = runs.find((r) => r.active && [moduleId, ""].includes(assistOwner(r.runId)));
      if (!alive || !live || runId.current) return;
      if (!assistOwner(live.runId) && moduleId) try { localStorage.setItem(assistOwnerKey(live.runId), moduleId); } catch { /* sin almacenamiento */ }
      runId.current = live.runId; lastSeq.current = 0;
      setRun(fromInfo(live));
      return core.assistWatch(live.runId); // el núcleo repite el historial: el estado se reconstruye solo
    }).catch((e) => alive && onError(errorText(e)));
    return () => { alive = false; };
  }, [core, onError, moduleId]);

  const doStart = async () => {
    if (!plan || !armed) return;
    onError("");
    try {
      const id = await core.assistStart(plan.planId, true);
      runId.current = id; lastSeq.current = 0;
      // El núcleo no sabe qué módulo inició la ejecución; la franja del shell lo necesita para llevar de vuelta.
      try { if (moduleId) localStorage.setItem(assistOwnerKey(id), moduleId); } catch { /* sin almacenamiento */ }
      setRun({ id, active: true, state: "running", pending: null, failReason: "", stopped: false, changed: [], log: [] });
      onStarted(); setArmed(false); // el plan se usa una sola vez
      await core.assistWatch(id); // con el id ya guardado: el núcleo repite desde el primer evento, ninguno se pierde
    } catch (e) {
      onError(errorText(e));
    }
  };

  const act = (f: () => Promise<void>) => f().catch((e) => onError(errorText(e)));
  const terminal = run && !run.active && finalText[run.state] ? t(finalText[run.state]) : "";

  return (
    <div data-assist>
      {plan && (
        <>
          <PlanView r={plan} />
          <Check label={t("assist.arm")} checked={armed} onChange={setArmed} />
          <div className="actions"><button className="danger" disabled={!armed} onClick={doStart}>{t("assist.start", { n: plan.plan.devices.length })}</button></div>
        </>
      )}

      {run && (
        <div>
          <header className="page-head run-head"><h3>{t("assist.run", { id: run.id, state: vocab(t, "assistState", run.state) })}</h3></header>
          {run.pending && (
            <PendingStep key={run.pending.id} step={run.pending} changed={run.changed} onConfirm={() => act(() => core.assistConfirm(run.id, run.pending!.id))}
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
          {!run.active && run.failReason && !run.stopped && <Notice kind="error">{t("assist.reason", { reason: run.failReason })}</Notice>}
          {terminal && <Notice kind={run.state === "done" || run.state === "rolled-back" ? "ok" : "info"}>{terminal}</Notice>}
          {!run.active && run.state === "done" && run.unsaved && <Notice kind="warn">{t("assist.final.unsaved", { x: run.unsaved.join(", ") || "—" })}</Notice>}
          {!run.active && run.state !== "done" && run.state !== "rolled-back" && run.changed.length > 0 && <p role="status" className="warn">{changedText(run.changed, t)}</p>}
          <details className="plan-more"><summary>{t("assist.deviceOutput")}</summary><Terminal text={run.log.join("\n")} /></details>
        </div>
      )}
    </div>
  );
}
