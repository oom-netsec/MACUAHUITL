import { useState } from "react";
import type { Job, RemoveResult, RemoveSkipped } from "../../lib/core";
import { Dialog } from "../../components/Dialog";
import { Notice, errorText } from "../../components/Field";
import { CopyButton } from "../../components/Data";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";

const REASONS = ["active", "change_pre", "backup_import", "adhoc_unread"];

// Confirmación de quitar del historial: dice que la evidencia en disco no se borra y deja copiar cada carpeta (la app no abre carpetas).
// Mientras la llamada corre no se puede cerrar. Si el núcleo omite trabajos, el diálogo sigue abierto y dice cuáles y por qué.
export function RemoveDialog({ title, body, jobs, onConfirm, onDone, onClose }: { title: string; body: string; jobs: Job[]; onConfirm: () => Promise<RemoveResult>; onDone: () => void; onClose: () => void }) {
  const t = useT();
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [skipped, setSkipped] = useState<RemoveSkipped[]>([]);
  const go = async () => {
    setErr(""); setSkipped([]); setBusy(true);
    try {
      const r = await onConfirm();
      if (r.skipped?.length) { setSkipped(r.skipped); setBusy(false); } else onDone();
    } catch (e) {
      setErr(errorText(e));
      setBusy(false);
    }
  };
  const nameOf = (id: string) => jobs.find((j) => j.id === id)?.name ?? id;
  const why = (r: string) => (REASONS.includes(r) ? t(`patrol.history.skip.${r}` as Key) : t("patrol.history.skip.unknown", { reason: r }));
  return (
    <Dialog title={title} onClose={() => { if (!busy) onClose(); }}>
      <p>{body}</p>
      <ul className="remove-dirs">
        {jobs.map((j) => (
          <li key={j.id}>
            {jobs.length > 1 && <strong>{j.name}</strong>}{" "}
            {j.outputDir
              ? <><code className="mono">{j.outputDir}</code> <CopyButton value={j.outputDir} label={t("patrol.history.copyFolder", { name: j.name })} /></>
              : <span className="meta">{t("patrol.history.noFolder")}</span>}
          </li>
        ))}
      </ul>
      {err && <Notice kind="error">{err}</Notice>}
      {skipped.length > 0 && (
        <Notice kind="warn">
          {t("patrol.history.skipped", { n: skipped.length })}
          <ul>{skipped.map((s) => <li key={s.jobId}>{t("patrol.history.skippedItem", { name: nameOf(s.jobId), why: why(s.reason) })}</li>)}</ul>
        </Notice>
      )}
      <div className="actions">
        <button type="button" className="primary" onClick={go} disabled={busy} aria-busy={busy}>{t("patrol.history.confirm")}</button>
        <button type="button" onClick={onClose} disabled={busy}>{t("common.cancel")}</button>
      </div>
    </Dialog>
  );
}
