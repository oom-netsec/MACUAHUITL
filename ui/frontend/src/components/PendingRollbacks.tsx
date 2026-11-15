// Reversas pendientes del modo de cambio asistido: lo que una ejecución dejó guardado para deshacer equipos que quedaron cambiados.
// Aplicar reversa usa el mismo flujo paso a paso (AssistExecution) arrancando con StartPendingRollback.
import { useCallback, useEffect, useState } from "react";
import type { PendingRollback, PortsPlanResult } from "../modules/ports/api";
import { AssistExecution, CodeLines, type AssistRunCore } from "./AssistRun";
import { Check, ConfirmButton, Field, Notice, errorText } from "./Field";
import { Badge } from "./Page";
import { useT } from "../lib/i18n";
import type { Key } from "../lib/i18n/es";
import { errInfo } from "../lib/coreError";
import { es } from "../lib/i18n/es";
import { useVaultVersion } from "../lib/vaultSignal";

// Más de 24 h exige aceptación explícita (el núcleo lo valida igual con assist.svc.reversa_vieja).
export const OLD_SECONDS = 86400;

// Motivos con que el núcleo dice «bóveda cerrada» (assist.go vault() y VaultErr de vault.ErrLocked).
const LOCKED = ["assist.svc.abre_la_boveda_el_modo", "vault.err.locked"];
const KINDS = ["ports", "snippet-vlan", "snippet-trunk", "snippet-svi", "snippet-ruta-estatica", "snippet-loopback", "snippet-helper-address", "snippet-ntp-server", "credrotate", "restore-diff"];

function ageText(s: number, t: ReturnType<typeof useT>): string {
  return s < 3600 ? t("pending.age.min", { n: Math.floor(s / 60) }) : s < OLD_SECONDS ? t("pending.age.h", { n: Math.floor(s / 3600) }) : t("pending.age.d", { n: Math.floor(s / OLD_SECONDS) });
}

// Antigüedad con la hora actual; sin hora de fin (0) vale la que calculó el núcleo.
const ageNow = (r: PendingRollback) => (r.endedUnix > 0 ? Math.max(0, Math.floor(Date.now() / 1000) - r.endedUnix) : r.ageSeconds);

// Plan sintético: cada equipo aplica sus líneas de reversa. No se dibuja (la entrada ya las muestra); solo alimenta al flujo asistido.
const planOf = (r: PendingRollback): PortsPlanResult => ({ planId: r.runId, plan: { function: r.kind, devices: r.devices.map((d) => ({ device: d.device, pre: [], apply: d.rollbackLines, rollback: [], post: [] })) } });

// gone: el núcleo ya no la lista (la reversa terminó bien y se borró): queda solo el resultado, sin acciones.
function Entry({ core, r, gone, onStarted, onChanged, onActive }: { core: AssistRunCore; r: PendingRollback; gone: boolean; onStarted: (r: PendingRollback) => void; onChanged: () => void; onActive: (id: string, active: boolean) => void }) {
  const t = useT();
  const [applying, setApplying] = useState(false);
  const [plan, setPlan] = useState<PortsPlanResult | null>(null);
  const [age, setAge] = useState(() => ageNow(r)); // se recalcula al pulsar Aplicar
  const [needAge, setNeedAge] = useState(false); // el núcleo respondió reversa_vieja
  const [accepted, setAccepted] = useState(false);
  const [live, setLive] = useState(false); // la ejecución de reversa de esta entrada sigue viva
  const [err, setErr] = useState("");
  const rotation = r.kind === "credrotate" && !r.unreadable;
  const rotDevice = (r.devices[0]?.device || r.runId).trim(); // nunca vacío: escribir nada no habilita Descartar
  const [typed, setTyped] = useState("");
  // Con el usuario rotado y la credencial asociada (campos 9 y 10 del núcleo) el aviso es exacto; sin ellos, el texto general.
  const rotationText = !r.rotatedUser ? [t("pending.discard.rotation", { device: rotDevice })]
    : [t("pending.discard.rotation.user", { device: rotDevice, user: r.rotatedUser }), t(!r.updateCredentialId ? "pending.discard.noVaultCred" : r.generatedSecret ? "pending.discard.vaultStaleGen" : "pending.discard.vaultStale", { user: r.rotatedUser })];
  if (r.generatedSecret) rotationText.push(t("pending.discard.generated"));
  const old = age > OLD_SECONDS || needAge;
  const ageLabel = ageText(age, t);
  const gated = plan && old && !accepted; // sin aceptar, el flujo asistido no recibe el plan: no hay con qué iniciar
  const report = useCallback((a: boolean) => { setLive(a); onActive(r.runId, a); }, [onActive, r.runId]);

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
  const discard = () => (setErr(""), core.assistDiscardPendingRollback(r.runId).then(onChanged, (e) => {
    const reason = errInfo(e)?.reason;
    if (reason === "assist.svc.reversa_no_existe") onChanged(); // ya no está: basta refrescar
    else setErr(reason === "assist.svc.reversa_aplicandose" ? t("pending.err.applying") : reason === "assist.svc.reversa_en_curso" ? t("pending.err.busy") : errorText(e));
  }));
  const apply = () => { setErr(""); setAge(ageNow(r)); setAccepted(false); setApplying(true); setPlan(planOf(r)); };
  // Los snippet-* sin clave propia llevan el nombre de su plantilla (snippet.<id>.name); sin esa clave, el id.
  const tpl = `snippet.${r.kind.replace(/^snippet-/, "")}.name`;
  const kind = KINDS.includes(r.kind) ? t(`pending.kind.${r.kind}` as Key)
    : r.kind.startsWith("snippet-") && tpl in es ? t("pending.kind.snippet", { name: t(tpl as Key) }) : r.kind;

  return (
    <section className="panel flush" aria-label={t("pending.run", { id: r.runId })}>
      <header className="panel-head">
        <h4>{r.devices.map((d) => d.device).join(", ") || r.runId}</h4>
        {!r.unreadable && <Badge tone="warn">{t("pending.kind", { kind })}</Badge>}
        {!r.unreadable && <span className="meta">{t("pending.age", { age: ageText(ageNow(r), t) })}</span>}
      </header>
      <div className="panel-body">
        {r.unreadable ? <Notice kind="warn">{t("pending.unreadable")}</Notice> : <>
          {r.devices.map((d) => <div key={d.device}>{r.devices.length > 1 && <p className="meta">{d.device}</p>}<CodeLines lines={d.rollbackLines} mark="↺" /></div>)}
          {r.writeMemory && <Notice kind="warn">{t("pending.writeMem")}</Notice>}
          {r.devices.some((d) => d.provisional) && <Notice kind="warn">{t("pending.provisional", { devices: r.devices.filter((d) => d.provisional).map((d) => d.device).join(", ") })}</Notice>}
        </>}
        {err && <Notice kind="error">{err}</Notice>}
        {applying && <p className="meta">{t("pending.revertNote")}</p>}
        {gated && <Check label={t("pending.acceptAge", { age: ageLabel })} checked={accepted} onChange={setAccepted} />}
        {applying && (
          <AssistExecution core={core} plan={gated ? null : plan} start={start} onStarted={() => { setPlan(null); onStarted(r); }} onActive={report} onError={setErr} />
        )}
        {!live && !gone && (
          <div className="actions">
            {!r.unreadable && !plan && <button className="primary" onClick={apply}>{t("pending.apply")}</button>}
            {!rotation && <ConfirmButton label={t("pending.discard")} confirmLabel={t("pending.discard.confirm")} onConfirm={discard} />}
          </div>
        )}
        {!live && !gone && rotation && (
          // Descartar una rotación deja al equipo con la contraseña nueva y a la bóveda con la anterior: aviso y nombre del equipo escrito.
          <div className="pending-discard-rotation">
            <Notice kind="warn">{rotationText.join(" ")}</Notice>
            <Field label={t("pending.discard.typeName", { device: rotDevice })} hint={t("pending.discard.typeHint")} value={typed} onChange={setTyped} w="md" mono />
            <div className="actions">
              {typed.trim() === rotDevice
                ? <ConfirmButton label={t("pending.discard")} confirmLabel={t("pending.discard.confirm")} onConfirm={discard} />
                : <button type="button" className="quiet danger-text" disabled>{t("pending.discard")}</button>}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

// runId: solo la reversa de esa ejecución (el aviso de equipo cambiado); sin él, todas. onActive: hay una reversa viva (el anfitrión apaga «Planear»).
export function PendingRollbacks({ core, runId, onActive }: { core: AssistRunCore; runId?: string; onActive?: (active: boolean) => void }) {
  const t = useT();
  const [list, setList] = useState<PendingRollback[] | null>(null);
  const [sticky, setSticky] = useState<PendingRollback[]>([]); // las que ya arrancaron siguen en pantalla aunque el núcleo las borre al terminar
  const [locked, setLocked] = useState(false);
  const [err, setErr] = useState("");
  const [liveIds, setLiveIds] = useState<string[]>([]);
  const vv = useVaultVersion(); // la bóveda se abrió o cerró: volver a listar

  const refresh = useCallback(() => core.assistListPendingRollbacks().then((l) => { setList(l); setLocked(false); setErr(""); }, (e) => {
    if (LOCKED.includes(errInfo(e)?.reason ?? "")) { setLocked(true); setList([]); setErr(""); } else setErr(errorText(e));
  }), [core]);
  useEffect(() => { refresh(); }, [refresh, vv]);
  useEffect(() => core.onAssistDone(() => { refresh(); }), [core, refresh]);
  const report = useCallback((id: string, a: boolean) => setLiveIds((l) => (a ? (l.includes(id) ? l : [...l, id]) : l.filter((x) => x !== id))), []);
  const any = liveIds.length > 0;
  useEffect(() => { onActive?.(any); }, [any, onActive]);
  useEffect(() => () => onActive?.(false), [onActive]); // al desmontarse no deja al anfitrión creyendo que hay una reversa viva

  const base = list ?? [];
  const shown = [...base, ...sticky.filter((s) => !base.some((b) => b.runId === s.runId))].filter((r) => !runId || r.runId === runId);
  return (
    <div className="pending-rollbacks">
      {runId ? shown.length > 0 && <h4>{t("pending.offer")}</h4> : <h3>{t("pending.title")}</h3>}
      {locked && <Notice kind="warn">{t("pending.locked")}</Notice>}
      {err && <Notice kind="error">{err}</Notice>}
      {list && !runId && !locked && shown.length === 0 && <p className="meta">{t("pending.empty")}</p>}
      {shown.map((r) => <Entry key={r.runId} core={core} r={r} gone={list !== null && !locked && !base.some((b) => b.runId === r.runId)} onStarted={(x) => setSticky((s) => [...s, x])} onChanged={refresh} onActive={report} />)}
    </div>
  );
}
