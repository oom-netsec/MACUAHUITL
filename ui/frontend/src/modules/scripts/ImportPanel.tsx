import { useState } from "react";
import { Notice, errorText } from "../../components/Field";
import { Badge, ResultPanel, type Tone } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import type { ImportAction, ImportDecision, ImportItem, ImportPreview, ImportResult, ImportState } from "./api";
import { tokenGone, warningText } from "./text";

const tone: Record<ImportState, Tone> = { nuevo: "ok", igual: "", conflicto_id: "warn", conflicto_nombre: "warn" };
export const isConflict = (s: string) => s === "conflicto_id" || s === "conflicto_nombre";

// Avisos de la vista previa (p. ej. archivo sin suma de verificación): se muestran antes de aplicar.
export function Warnings({ list }: { list: string[] }) {
  const t = useT();
  if (list.length === 0) return null;
  return (
    <Notice kind="warn">
      <strong>{t("scripts.import.warnings")}</strong>
      <ul>{list.map((w, i) => <li key={i}>{warningText(t, w)}</li>)}</ul>
    </Notice>
  );
}

// Tabla de scripts del archivo con una decisión por conflicto. «Reemplazar» no se ofrece contra la biblioteca (el núcleo lo rechaza).
export function ScriptRows({ items, picks, onPick, nameOf }: { items: ImportItem[]; picks: Record<string, ImportAction>; onPick: (id: string, a: ImportAction) => void; nameOf: (id: string) => string }) {
  const t = useT();
  return (
    <table>
      <thead><tr><th>{t("scripts.import.col.script")}</th><th>{t("scripts.import.col.state")}</th><th>{t("scripts.import.col.with")}</th><th>{t("scripts.import.col.action")}</th></tr></thead>
      <tbody>
        {items.map((i) => (
          <tr key={i.script.id}>
            <td>{i.script.name}</td>
            <td><Badge tone={tone[i.state]}>{t(`scripts.state.${i.state}` as Key)}</Badge></td>
            <td>{i.conflictsWith ? nameOf(i.conflictsWith) : ""}</td>
            <td>
              {isConflict(i.state) && (
                <select aria-label={t("scripts.import.decision", { name: i.script.name })} value={picks[i.script.id] ?? ""} onChange={(e) => onPick(i.script.id, e.target.value as ImportAction)}>
                  <option value="" disabled>{t("scripts.act.choose")}</option>
                  <option value="renombrar">{t("scripts.act.renombrar")}</option>
                  {!i.conflictsWith.startsWith("lib-") && <option value="reemplazar">{t("scripts.act.reemplazar")}</option>}
                  <option value="omitir">{t("scripts.act.omitir")}</option>
                </select>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// Paso 2 del import: una decisión por conflicto.
export function ImportPanel({ preview, nameOf, onApply, onClose, onExpired }: {
  preview: ImportPreview;
  nameOf: (id: string) => string; // nombre visible de un ID guardado
  onApply: (token: string, decisions: ImportDecision[]) => Promise<ImportResult>;
  onClose: (r?: ImportResult) => void;
  onExpired: () => void; // el token venció o ya se usó: la vista previa ya no sirve
}) {
  const t = useT();
  const [picks, setPicks] = useState<Record<string, ImportAction>>({});
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const conflicts = preview.items.filter((i) => isConflict(i.state));
  const ready = conflicts.every((i) => picks[i.script.id]);
  const apply = async () => {
    setErr(""); setBusy(true);
    try {
      onClose(await onApply(preview.token, conflicts.map((i) => ({ scriptId: i.script.id, action: picks[i.script.id] }))));
    } catch (e) {
      if (tokenGone(e)) { onExpired(); return; }
      setErr(errorText(e)); setBusy(false);
    }
  };
  return (
    <ResultPanel title={t("scripts.import.preview")} pad
      actions={<><button type="button" className="primary" disabled={!ready || busy} aria-busy={busy} onClick={apply}>{t("scripts.import.apply")}</button><button type="button" onClick={() => onClose()}>{t("scripts.f.cancel")}</button></>}>
      <Warnings list={preview.warnings} />
      <ScriptRows items={preview.items} picks={picks} onPick={(id, a) => setPicks({ ...picks, [id]: a })} nameOf={nameOf} />
      {err && <Notice kind="error">{err}</Notice>}
      {!ready && <Notice kind="info">{t("scripts.import.needs")}</Notice>}
    </ResultPanel>
  );
}
