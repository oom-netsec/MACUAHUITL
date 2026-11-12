import { useState } from "react";
import { Notice, errorText } from "../../components/Field";
import { Badge, ResultPanel, type Tone } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { FAVORITES_ID, type CollectionImportState, type CollectionsImportPreview, type CollectionsImportResult, type ImportAction, type ImportDecision } from "./api";
import { ScriptRows, Warnings, isConflict } from "./ImportPanel";
import { colName, tokenGone } from "./text";

const tone: Record<CollectionImportState, Tone> = { nueva: "ok", igual: "", fusionar: "ok", conflicto_id: "warn", conflicto_nombre: "warn" };

// Paso 2 del import de colecciones: decisiones aparte para colecciones y para scripts. «favoritos» solo se fusiona
// (sin decisión) y «reemplazar» no se ofrece contra ella ni contra la biblioteca; el núcleo lo rechazaría.
export function CollectionsImportPanel({ preview, colNameOf, scriptNameOf, onApply, onClose, onExpired }: {
  preview: CollectionsImportPreview;
  colNameOf: (id: string) => string;
  scriptNameOf: (id: string) => string;
  onApply: (token: string, scriptDecisions: ImportDecision[], collectionDecisions: ImportDecision[]) => Promise<CollectionsImportResult>;
  onClose: (r?: CollectionsImportResult) => void;
  onExpired: () => void;
}) {
  const t = useT();
  const [cpicks, setCpicks] = useState<Record<string, ImportAction>>({});
  const [spicks, setSpicks] = useState<Record<string, ImportAction>>({});
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const cconf = preview.collections.filter((i) => isConflict(i.state));
  const sconf = preview.scripts.filter((i) => isConflict(i.state));
  const ready = cconf.every((i) => cpicks[i.collection.id]) && sconf.every((i) => spicks[i.script.id]);
  const apply = async () => {
    setErr(""); setBusy(true);
    try {
      onClose(await onApply(preview.token, sconf.map((i) => ({ scriptId: i.script.id, action: spicks[i.script.id] })), cconf.map((i) => ({ scriptId: i.collection.id, action: cpicks[i.collection.id] }))));
    } catch (e) {
      if (tokenGone(e)) { onExpired(); return; }
      setErr(errorText(e)); setBusy(false);
    }
  };
  return (
    <ResultPanel title={t("scripts.cimport.preview")} pad
      actions={<><button type="button" className="primary" disabled={!ready || busy} aria-busy={busy} onClick={apply}>{t("scripts.import.apply")}</button><button type="button" onClick={() => onClose()}>{t("scripts.f.cancel")}</button></>}>
      <Warnings list={preview.warnings} />
      <h4>{t("scripts.cimport.cols")}</h4>
      <table>
        <thead><tr><th>{t("scripts.cimport.col.col")}</th><th>{t("scripts.import.col.state")}</th><th>{t("scripts.import.col.with")}</th><th>{t("scripts.import.col.action")}</th></tr></thead>
        <tbody>
          {preview.collections.map((i) => (
            <tr key={i.collection.id}>
              <td>{colName(t, i.collection)}</td>
              <td><Badge tone={tone[i.state]}>{t(`scripts.cstate.${i.state}` as Key)}</Badge></td>
              <td>{i.conflictsWith ? colNameOf(i.conflictsWith) : ""}</td>
              <td>
                {i.state === "fusionar" && <span className="hint">{t("scripts.cimport.merge")}</span>}
                {isConflict(i.state) && (
                  <select aria-label={t("scripts.cimport.decision", { name: colName(t, i.collection) })} value={cpicks[i.collection.id] ?? ""} onChange={(e) => setCpicks({ ...cpicks, [i.collection.id]: e.target.value as ImportAction })}>
                    <option value="" disabled>{t("scripts.act.choose")}</option>
                    <option value="renombrar">{t("scripts.act.renombrar")}</option>
                    {i.conflictsWith !== FAVORITES_ID && i.collection.id !== FAVORITES_ID && <option value="reemplazar">{t("scripts.act.reemplazar")}</option>}
                    <option value="omitir">{t("scripts.act.omitir")}</option>
                  </select>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <h4>{t("scripts.cimport.scripts")}</h4>
      {preview.scripts.length === 0 ? <p className="hint">{t("scripts.cimport.noScripts")}</p> : <ScriptRows items={preview.scripts} picks={spicks} onPick={(id, a) => setSpicks({ ...spicks, [id]: a })} nameOf={scriptNameOf} />}
      {err && <Notice kind="error">{err}</Notice>}
      {!ready && <Notice kind="info">{t("scripts.import.needs")}</Notice>}
    </ResultPanel>
  );
}
