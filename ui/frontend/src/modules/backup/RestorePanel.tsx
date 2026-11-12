import { useEffect, useState } from "react";
import type { CoreAPI, Credential } from "../../lib/core";
import { AssistBanner, AssistExecution, targetOf } from "../../components/AssistRun";
import { Check, Field, Notice, Select, errorText } from "../../components/Field";
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

export function RestorePanel({ core, entry, creds, onClose }: { core: CoreAPI; entry: BackupEntry; creds: Credential[]; onClose: () => void }) {
  const t = useT();
  const [credId, setCredId] = useState(creds[0]?.id ?? "");
  useEffect(() => { setCredId((c) => c || creds[0]?.id || ""); }, [creds]);
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

  const doPlan = async () => {
    setErr(""); setPlan(null); setRefused([]); setReason("");
    const req: RestoreRequest = { target: targetOf(equipo, credId), backupId: entry.id, allowPartial: partial, writeMemory: writeMem };
    if (mgmt.trim()) req.managementInterface = mgmt.trim();
    const n = Number(maxLines);
    if (n > 0) req.maxLines = n;
    const accepted = fps.split(/[\s,]+/).filter(Boolean);
    if (accepted.length) req.acceptedHostKeyFingerprints = accepted;
    try {
      const r = await core.assistPlanRestore(req);
      setRefused(r.refused ?? []);
      if (!r.planId || !r.plan) setReason(r.reason ?? t("backup.restore.rejected"));
      else setPlan({ planId: r.planId, plan: r.plan });
    } catch (e) {
      setErr(errorText(e));
    }
  };

  const canPlan = equipo.trim() !== "" && credId !== "" && Number(maxLines) >= 0 && Number(maxLines) <= 1000;

  return (
    <div className="restore-block"><Section title={t("backup.restore.heading", { id: entry.id })}>
      <AssistBanner active={active} />
      <Notice kind="warn">{t("backup.restore.warn")}</Notice>
      <div className="field-row">
        <Field label={t("backup.restore.device")} value={equipo} onChange={setEquipo} w="lg" mono />
        <Select label={t("backup.restore.cred")} value={credId} onChange={setCredId} options={creds.map((c) => [c.id, `${c.label} (${c.username})`])} w="md" />
      </div>
      <div className="field-row">
        <Field label={t("backup.restore.mgmt")} value={mgmt} onChange={setMgmt} w="lg" mono />
        <Field label={t("backup.restore.maxLines")} type="number" value={maxLines} onChange={setMaxLines} w="sm" mono />
      </div>
      <Check label={t("backup.restore.partial")} checked={partial} onChange={setPartial} />
      <Check label={t("backup.restore.writeMem")} checked={writeMem} onChange={setWriteMem} />
      <Field label={t("fps.accepted")} value={fps} onChange={setFps} w="full" mono />
      <div className="actions">
        <button disabled={!canPlan || active} onClick={doPlan}>{t("backup.restore.plan")}</button>
        <button onClick={onClose} disabled={active}>{t("backup.restore.close")}</button>
      </div>
      {err && <Notice kind="error">{err}</Notice>}
      {reason && <Notice kind="error">{t("backup.restore.rejectedWhy", { reason })}</Notice>}
      {refused.length > 0 && <Refused items={refused} title={t(plan ? "backup.restore.refusedPartial" : "backup.restore.refusedManual")} />}
      <AssistExecution core={core} plan={plan} onStarted={() => setPlan(null)} onActive={setActive} onError={setErr} />
    </Section></div>
  );
}
