import { useEffect, useRef, useState } from "react";
import { RunButton } from "../../components/RunButton";
import type { CoreAPI, Credential } from "../../lib/core";
import { resolveAccepted } from "../../lib/hostkeys";
import { Advanced } from "../../components/Advanced";
import { TargetField } from "../inventory/TargetField";
import { planTarget } from "../../lib/targets";
import { AssistBanner, AssistExecution } from "../../components/AssistRun";
import { CredentialSelect, type VaultGate } from "../../components/CredentialSelect";
import { Check, Field, Notice, errorText } from "../../components/Field";
import { Section } from "../../components/Page";
import { Hl, Terminal } from "../../components/Terminal";
import type { PortsPlanResult } from "../ports/api";
import type { BackupEntry, RestoreRefusal, RestoreRequest } from "./api";
import { useT } from "../../lib/i18n";

// Restaurar por diff (fase 16c): el núcleo compara el running del equipo con el respaldo y propone solo las líneas que difieren, con su
// reversa. Planear solo lee. Nada se cambia sin activar el modo asistido para esta ejecución y confirmar cada paso.

// guessAddress toma la IP o el nombre del final de «SW1_192.0.2.1» (así nombra el respaldo la carpeta de Patrol).
function guessAddress(device: string): string {
  const i = device.lastIndexOf("_");
  return i >= 0 ? device.slice(i + 1) : device;
}

function Refused({ items, title }: { items: RestoreRefusal[]; title: string }) {
  const t = useT();
  return (
    <section aria-label={t("backup.restore.refused")} className="refused">
      <h4>{title}</h4>
      <Terminal as="ul" aria-label={title}>
        {items.map((r, i) => <li key={i}><Hl text={`${r.path ? `${r.path} › ` : ""}${r.line}`} /> <span className="t-dim">({r.why})</span></li>)}
      </Terminal>
    </section>
  );
}

export function RestorePanel({ core, entry, creds, vault, onClose }: { core: CoreAPI; entry: BackupEntry; creds: Credential[]; vault: VaultGate; onClose: () => void }) {
  const t = useT();
  const [credId, setCredId] = useState("");
  const [equipo, setEquipo] = useState(guessAddress(entry.device));
  const [mgmt, setMgmt] = useState("");
  const [maxLines, setMaxLines] = useState("200");
  const [partial, setPartial] = useState(false);
  const [writeMem, setWriteMem] = useState(false);
  const [fps, setFps] = useState("");
  const [plan, setPlan] = useState<PortsPlanResult | null>(null);
  const [refused, setRefused] = useState<RestoreRefusal[]>([]);
  const [reason, setReason] = useState("");
  const [err, setErr] = useState("");
  const [active, setActive] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => { // al abrir, el foco va al título del panel (queda en la fila si no)
    const h = box.current?.querySelector("h3");
    h?.setAttribute("tabindex", "-1");
    h?.focus();
  }, []);

  const doPlan = async () => {
    setErr(""); setPlan(null); setRefused([]); setReason("");
    const req: RestoreRequest = { target: planTarget(equipo, credId), backupId: entry.id, allowPartial: partial, writeMemory: writeMem };
    if (mgmt.trim()) req.managementInterface = mgmt.trim();
    const n = Number(maxLines);
    if (n > 0) req.maxLines = n;
    const accepted = fps.split(/[\s,]+/).filter(Boolean);
    if (accepted.length) req.acceptedHostKeyFingerprints = accepted;
    const keys = resolveAccepted(fps, [req.target]).keys;
    if (keys.length) req.acceptedHostKeys = keys;
    try {
      const r = await core.assistPlanRestore(req);
      setRefused(r.refused ?? []);
      if (!r.planId || !r.plan) setReason(r.reason ?? t("backup.restore.rejected"));
      else setPlan({ planId: r.planId, plan: r.plan });
    } catch (e) {
      setErr(errorText(e));
    }
  };

  const linesOk = Number(maxLines) >= 0 && Number(maxLines) <= 1000;

  return (
    <div className="restore-block" ref={box}><Section title={t("backup.restore.heading", { id: entry.id })}>
      <AssistBanner active={active} />
      <Notice kind="warn">{t("backup.restore.warn")}</Notice>
      <div className="field-row">
        <TargetField core={core} value={equipo} onChange={setEquipo} onPickCredential={(id) => { if (!credId && creds.some((c) => c.id === id)) setCredId(id); }} />
        <CredentialSelect creds={creds} vault={vault} notice={false} value={credId} onChange={setCredId} />
      </div>
      <Check label={t("backup.restore.writeMem")} checked={writeMem} onChange={setWriteMem} />
      <Field label={t("fps.accepted")} hint={t("fps.accepted.hint")} value={fps} onChange={setFps} w="full" mono />
      {/* La interfaz de gestión queda a la vista: el núcleo la exige cuando no la deduce y su rechazo llega como texto, sin código para abrir un panel. */}
      <Field label={t("backup.restore.mgmt")} value={mgmt} onChange={setMgmt} w="lg" mono />
      <Advanced changed={[maxLines !== "200", partial].filter(Boolean).length} forceOpen={!linesOk}>
        <Field label={t("backup.restore.maxLines")} type="number" value={maxLines} onChange={setMaxLines} w="sm" mono error={linesOk ? undefined : t("backup.restore.maxLines.bad")} />
        <Check label={t("backup.restore.partial")} checked={partial} onChange={setPartial} />
      </Advanced>
      <div className="actions">
        <RunButton disabled={active} onClick={doPlan} missing={[!equipo.trim() && t("need.target"), !credId && t("need.cred"), !linesOk && t("need.restoreLines")]}>{t("backup.restore.plan")}</RunButton>
        <button onClick={onClose} disabled={active}>{t("backup.restore.close")}</button>
      </div>
      {err && <Notice kind="error">{err}</Notice>}
      {reason && <Notice kind="error">{t("backup.restore.rejectedWhy", { reason })}</Notice>}
      {refused.length > 0 && <Refused items={refused} title={t(plan ? "backup.restore.refusedPartial" : "backup.restore.refusedManual")} />}
      <AssistExecution core={core} plan={plan} onStarted={() => setPlan(null)} onActive={setActive} onError={setErr} />
    </Section></div>
  );
}
