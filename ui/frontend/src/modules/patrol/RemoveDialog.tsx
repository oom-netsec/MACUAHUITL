import { useState } from "react";
import type { Job } from "../../lib/core";
import { Dialog } from "../../components/Dialog";
import { Notice, errorText } from "../../components/Field";
import { CopyButton } from "../../components/Data";
import { useT } from "../../lib/i18n";
import { errInfo } from "../../lib/coreError";

// Confirmación de quitar del historial: dice que la evidencia en disco no se borra y deja copiar cada carpeta (la app no abre carpetas).
export function RemoveDialog({ title, body, jobs, onConfirm, onClose }: { title: string; body: string; jobs: Job[]; onConfirm: () => Promise<void>; onClose: () => void }) {
  const t = useT();
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const go = async () => {
    setErr(""); setBusy(true);
    try {
      await onConfirm();
    } catch (e) {
      const i = errInfo(e);
      setErr(i?.reason === "patrol.job_active" ? t("patrol.history.activeBlocked", { ids: i.metadata.job_ids ?? "" }) : errorText(e));
      setBusy(false);
    }
  };
  return (
    <Dialog title={title} onClose={onClose}>
      <p>{body}</p>
      <ul className="remove-dirs">
        {jobs.filter((j) => j.outputDir).map((j) => (
          <li key={j.id}>{jobs.length > 1 && <strong>{j.name}</strong>} <code className="mono">{j.outputDir}</code> <CopyButton value={j.outputDir!} label={t("patrol.package.copy")} /></li>
        ))}
      </ul>
      {err && <Notice kind="error">{err}</Notice>}
      <div className="actions">
        <button type="button" className="primary" onClick={go} disabled={busy} aria-busy={busy}>{t("patrol.history.confirm")}</button>
        <button type="button" onClick={onClose}>{t("common.cancel")}</button>
      </div>
    </Dialog>
  );
}
