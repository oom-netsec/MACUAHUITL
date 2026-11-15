// Reversas pendientes del modo de cambio asistido: lo que una ejecución dejó guardado para deshacer equipos que quedaron cambiados.
// Aplicar reversa usa el mismo flujo paso a paso (AssistExecution) arrancando con StartPendingRollback.
import { useCallback, useEffect, useState } from "react";
import type { PendingRollback, PortsPlanResult } from "../modules/ports/api";
import { AssistExecution, CodeLines, type AssistRunCore } from "./AssistRun";
import { Check, ConfirmButton, Notice, errorText } from "./Field";
import { Badge } from "./Page";
import { useT } from "../lib/i18n";
import { errInfo } from "../lib/coreError";

// Más de 24 h exige aceptación explícita (el núcleo lo valida igual con assist.svc.reversa_vieja).
export const OLD_SECONDS = 86400;

function ageText(s: number, t: ReturnType<typeof useT>): string {
  return s < 3600 ? t("pending.age.min", { n: Math.floor(s / 60) }) : s < OLD_SECONDS ? t("pending.age.h", { n: Math.floor(s / 3600) }) : t("pending.age.d", { n: Math.floor(s / OLD_SECONDS) });
}

// Plan sintético: cada equipo aplica sus líneas de reversa, sin pre/post/rollback.
const planOf = (r: PendingRollback): PortsPlanResult => ({ planId: r.runId, plan: { function: r.kind, devices: r.devices.map((d) => ({ device: d.device, pre: [], apply: d.rollbackLines, rollback: [], post: [] })) } });

function Entry({ core, r, onStarted, onChanged }: { core: AssistRunCore; r: PendingRollback; onStarted: (r: PendingRollback) => void; onChanged: () => void }) {
  const t = useT();
  const [applying, setApplying] = useState(false);
  const [plan, setPlan] = useState<PortsPlanResult | null>(null);
  const [needAge, setNeedAge] = useState(false); // el núcleo respondió reversa_vieja
  const [accepted, setAccepted] = useState(false);
  const [started, setStarted] = useState(false);
  const [err, setErr] = useState("");
  const old = r.ageSeconds > OLD_SECONDS || needAge;
  const age = ageText(r.ageSeconds, t);

  const start = async (assisted: boolean) => {
    try {
      return await core.assistStartPendingRollback(r.runId, accepted, assisted);
    } catch (e) {
      // El texto lo decide el motivo estable, nunca el mensaje del núcleo.
      const reason = errInfo(e)?.reason;
      if (reason === "assist.svc.reversa_vieja") setNeedAge(true);
      throw new Error(reason === "assist.svc.reversa_vieja" ? t("pending.err.old") : reason === "assist.svc.reversa_no_existe" ? t("pending.err.gone")
        : reason === "assist.svc.reversa_en_curso" ? t("pending.err.busy") : reason === "assist.pending.no_state" || reason === "assist.pending.not_verifiable" ? t("pending.err.manual") : errorText(e));
    }
  };
  const discard = () => core.assistDiscardPendingRollback(r.runId).then(onChanged, (e) => setErr(errorText(e)));

  return (
    <section className="panel flush" aria-label={t("pending.run", { id: r.runId })}>
      <header className="panel-head">
        <h4>{r.devices.map((d) => d.device).join(", ") || r.runId}</h4>
        {!r.unreadable && <Badge tone="warn">{t("pending.kind", { kind: r.kind })}</Badge>}
        {!r.unreadable && <span className="meta">{t("pending.age", { age })}</span>}
      </header>
      <div className="panel-body">
        {r.unreadable ? <Notice kind="warn">{t("pending.unreadable")}</Notice> : <>
          {r.devices.map((d) => <div key={d.device}>{r.devices.length > 1 && <p className="meta">{d.device}</p>}<CodeLines lines={d.rollbackLines} mark="↺" /></div>)}
          {r.writeMemory && <Notice kind="warn">{t("pending.writeMem")}</Notice>}
        </>}
        {err && <Notice kind="error">{err}</Notice>}
        {applying && old && !started && <Check label={t("pending.acceptAge", { age })} checked={accepted} onChange={setAccepted} />}
        {applying && (!old || accepted || started) && (
          <AssistExecution core={core} plan={plan} start={start} onStarted={() => { setPlan(null); setStarted(true); onStarted(r); }} onActive={() => {}} onError={setErr} />
        )}
        <div className="actions">
          {!r.unreadable && !applying && <button className="primary" onClick={() => { setApplying(true); setPlan(planOf(r)); }}>{t("pending.apply")}</button>}
          {!started && <ConfirmButton label={t("pending.discard")} confirmLabel={t("pending.discard.confirm")} onConfirm={discard} />}
        </div>
      </div>
    </section>
  );
}

// runId: solo la reversa de esa ejecución (el aviso de equipo cambiado); sin él, todas.
export function PendingRollbacks({ core, runId }: { core: AssistRunCore; runId?: string }) {
  const t = useT();
  const [list, setList] = useState<PendingRollback[] | null>(null);
  const [sticky, setSticky] = useState<PendingRollback[]>([]); // las que ya arrancaron siguen en pantalla aunque el núcleo las borre al terminar
  const [locked, setLocked] = useState(false);
  const [err, setErr] = useState("");

  const refresh = useCallback(() => core.assistListPendingRollbacks().then((l) => { setList(l); setLocked(false); setErr(""); }, (e) => {
    if (errInfo(e)?.code === "FailedPrecondition") setLocked(true); else setErr(errorText(e));
  }), [core]);
  useEffect(() => { refresh(); return core.onAssistDone(() => { refresh(); }); }, [core, refresh]);

  if (locked) return <Notice kind="warn">{t("pending.locked")}</Notice>;
  const base = list ?? [];
  const shown = [...base, ...sticky.filter((s) => !base.some((b) => b.runId === s.runId))].filter((r) => !runId || r.runId === runId);
  return (
    <div className="pending-rollbacks">
      {runId ? shown.length > 0 && <h4>{t("pending.offer")}</h4> : <h3>{t("pending.title")}</h3>}
      {err && <Notice kind="error">{err}</Notice>}
      {list && !runId && shown.length === 0 && <p className="meta">{t("pending.empty")}</p>}
      {shown.map((r) => <Entry key={r.runId} core={core} r={r} onStarted={(x) => setSticky((s) => [...s, x])} onChanged={refresh} />)}
    </div>
  );
}
