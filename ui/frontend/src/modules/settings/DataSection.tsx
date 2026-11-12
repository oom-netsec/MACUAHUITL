import { HostsDataCard } from "./HostsDataCard";
import { useEffect, useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { cleanOnFail } from "../../lib/cleanOnFail";
import { Notice, errorText } from "../../components/Field";
import { Icon } from "../../components/Icon";
import { DetailsButton } from "../../components/Dialog";
import { useT } from "../../lib/i18n";
import { useNav } from "../../app/activity";
import type { Key } from "../../lib/i18n/es";
import { FAVORITES_ID, type ImportFormatField, type ImportKind } from "../scripts/api";
import { scriptsChanged } from "../scripts/signal";
import { useImportFlow } from "../scripts/useImportFlow";

// Tipos que describe el núcleo (en español); otro valor se muestra tal cual.
const TYPES: Record<string, Key> = { texto: "settings.data.type.texto", entero: "settings.data.type.entero", "fecha RFC 3339": "settings.data.type.fecha", arreglo: "settings.data.type.arreglo", "lista de texto": "settings.data.type.lista" };

// Una tarjeta por tipo de dato: qué contiene, formato aceptado, plantilla de ejemplo, exportar e importar. La tabla de campos (del núcleo, de las
// mismas reglas que validan el import) y la nota del formato van en «Ver detalles». Las descripciones de campo del núcleo vienen en español y no se muestran: la vista no mezcla idiomas.
function DataCard({ core, kind, tk, wk }: { core: CoreAPI; kind: ImportKind; tk: Key; wk: Key }) {
  const t = useT();
  const [fields, setFields] = useState<ImportFormatField[] | null>(null);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const imp = useImportFlow(core, kind, scriptsChanged);
  useEffect(() => {
    let live = true;
    core.importFormat(kind).then((f) => { if (live) setFields(f); }, (e) => { if (live) setErr(errorText(e)); });
    return () => { live = false; };
  }, [core, kind]);

  const run = async (f: () => Promise<void>) => { setErr(""); setMsg(""); try { await f(); } catch (e) { setErr(errorText(e)); } };
  const template = () => run(async () => {
    const body = await core.importTemplate(kind);
    const path = await core.pickSavePath(t(kind === "scripts" ? "settings.data.templateName" : "settings.data.templateNameCols"));
    if (!path) return;
    await core.writeFile(path, body, "utf8", true); // pickSavePath ya confirmó el reemplazo
    setMsg(t("settings.data.templateSaved", { path }));
  });
  const exportAll = () => run(async () => {
    const all = kind === "colecciones" ? await core.listCollections() : [];
    const ids = kind === "scripts" ? (await core.listScripts()).filter((s) => s.origin === "usuario").map((s) => s.id) : all.map((c) => c.id);
    // Con solo «favoritos» y vacía tampoco hay nada que llevar.
    if (ids.length === 0 || (all.length === 1 && all[0].id === FAVORITES_ID && all[0].scriptIds.length === 0)) { setMsg(t("settings.data.exportNone")); return; }
    const path = await core.pickSavePath(t(kind === "scripts" ? "scripts.exportName" : "scripts.col.exportName"));
    if (!path) return;
    if (kind === "scripts") setMsg(t("settings.data.exportedScripts", { n: String(await cleanOnFail(core, path, core.exportScripts(ids, path, true))), path }));
    else { const r = await cleanOnFail(core, path, core.exportCollections(ids, path, true)); setMsg(t("scripts.col.exported", { c: r.collections, s: r.scripts, path })); }
  });

  return (
    <article className="data-card" aria-labelledby={`data-${kind}`}>
      <h4 id={`data-${kind}`}>{t(tk)}</h4>
      <p>{t(wk)}</p>
      <p className="hint">{t("settings.data.formatShort")}</p>
      <div className="actions">
        <button type="button" onClick={() => void template()}><Icon name="download" />{t("settings.data.template")}</button>
        <button type="button" onClick={() => void exportAll()}><Icon name="download" />{t("settings.data.export")}</button>
        <button type="button" onClick={() => void imp.start()}><Icon name="upload" />{t("settings.data.import")}</button>
        <DetailsButton label={t("settings.data.details")} title={t("settings.data.details.title", { name: t(tk) })}>
          <p className="hint">{t("settings.data.format")}</p>
          {fields && (
            <div className="data-fields">
              <table aria-label={t("settings.data.fields") + " · " + t(tk)}>
                <thead><tr><th>{t("settings.data.col.name")}</th><th>{t("settings.data.col.type")}</th><th>{t("settings.data.col.req")}</th><th>{t("settings.data.col.example")}</th></tr></thead>
                <tbody>
                  {fields.map((f) => (
                    <tr key={f.name}>
                      <td><code>{f.name}</code></td>
                      <td>{TYPES[f.type] ? t(TYPES[f.type]) : f.type}</td>
                      <td>{t(f.required ? "settings.data.yes" : "settings.data.no")}</td>
                      <td><code>{f.example}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </DetailsButton>
      </div>
      {err && <Notice kind="error">{err}</Notice>}
      {msg && <Notice kind="ok">{msg}</Notice>}
      {imp.node}
    </article>
  );
}

export function DataSection({ core }: { core: CoreAPI }) {
  const t = useT();
  const go = useNav();
  return (
    <div className="data-cards">
      <DataCard core={core} kind="scripts" tk="settings.data.scripts" wk="settings.data.scripts.what" />
      <DataCard core={core} kind="colecciones" tk="settings.data.cols" wk="settings.data.cols.what" />
      <HostsDataCard core={core} />
      <article className="data-card" aria-labelledby="data-vault">
        <h4 id="data-vault">{t("settings.data.vault")}</h4>
        <p>{t("settings.data.vault.what")}</p>
        <div className="actions"><button type="button" onClick={() => go("vault")}><Icon name="lock" />{t("settings.data.vault.open")}</button></div>
      </article>
    </div>
  );
}
