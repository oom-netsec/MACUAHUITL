import { cleanOnFail } from "../../lib/cleanOnFail";
import { useEffect, useId, useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Check, Notice, Select, errorText } from "../../components/Field";
import { Badge } from "../../components/Page";
import { Icon } from "../../components/Icon";
import { DetailsButton } from "../../components/Dialog";
import { useLang, useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import type { Host, HostFileFormat, HostImportAction, HostImportItem, HostsFormat, HostsImportPreview, HostsImportResult } from "../inventory/api";
import { knownWarning, useCoreText } from "../inventory/coreText";
import { hostsChanged, useHostsVersion } from "../inventory/signal";
import "../inventory/hosts.css";

// Tipos y descripciones de la tabla de campos: el núcleo los describe en español; aquí se traducen por nombre de campo/tipo.
// Un campo o tipo que la vista no conozca se muestra tal cual el núcleo lo dijo solo en español; en inglés se oculta (la app no mezcla idiomas).
const TYPES: Record<string, Key> = { texto: "hosts.data.type.texto", entero: "hosts.data.type.entero", lista: "hosts.data.type.lista" };
const FIELD_NAMES = new Set(["name", "address", "port", "platform", "folder", "tags", "credential_label", "notes"]);
// Ejemplos que no dependen del idioma (IP, puerto, plataforma); los demás vienen en español del núcleo y en inglés no se muestran.
const NEUTRAL = new Set(["address", "port", "platform"]);
const neutral = (n: string) => NEUTRAL.has(n);
const descKey = (n: string) => `hosts.data.field.${n}` as Key;

// Tarjeta «Hosts» de Ajustes → Datos: qué contiene, formatos, tabla de campos, plantillas, exportar e importar con vista previa.
// La vista previa trae el error de cada fila inválida (no bloquean las demás) y solo se aplican las válidas.
export function HostsDataCard({ core }: { core: CoreAPI }) {
  const t = useT();
  const lang = useLang();
  const ct = useCoreText();
  const uid = useId();
  const hv = useHostsVersion();
  const [fmt, setFmt] = useState<HostsFormat | null>(null);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [warn, setWarn] = useState("");
  const [format, setFormat] = useState<HostFileFormat>("csv");
  const [scope, setScope] = useState<"all" | "some">("all");
  const [book, setBook] = useState<Host[]>([]);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [prev, setPrev] = useState<HostsImportPreview | null>(null);
  const [acts, setActs] = useState<Record<string, HostImportAction>>({});
  const [result, setResult] = useState<HostsImportResult | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    core.hostsImportFormat().then((f) => { if (live) setFmt(f); }, (e) => { if (live) setErr(ct(errorText(e), "hosts.coreError", e)); });
    return () => { live = false; };
  }, [core]);
  useEffect(() => {
    if (scope !== "some") return;
    let live = true;
    core.listHosts().then((l) => { if (live) { setBook(l); setPicked((p) => new Set([...p].filter((id) => l.some((h) => h.id === id)))); } }, (e) => { if (live) setErr(ct(errorText(e), "hosts.coreError", e)); });
    return () => { live = false; };
  }, [core, scope, hv]);

  const run = async (f: () => Promise<void>) => { setErr(""); setMsg(""); setWarn(""); setBusy(true); try { await f(); } catch (e) { setErr(ct(errorText(e), "hosts.coreError", e)); } finally { setBusy(false); } };

  const template = (format: HostFileFormat) => run(async () => {
    const tpl = await core.hostsImportTemplate(format);
    const path = await core.pickSavePath(tpl.filename);
    if (!path) return;
    await core.writeFile(path, tpl.content, "utf8", true); // pickSavePath ya confirmó el reemplazo
    setMsg(t("hosts.data.template.saved", { path }));
  });

  const exportHosts = () => run(async () => {
    const ids = scope === "all" ? [] : [...picked];
    if (scope === "some" && ids.length === 0) { setMsg(t("hosts.data.export.none")); return; }
    if (scope === "all" && (await core.listHosts()).length === 0) { setMsg(t("hosts.data.export.none")); return; }
    const path = await core.pickSavePath(`hosts.${format}`);
    if (!path) return;
    // Si falla, se borra el archivo vacío que dejó pickSavePath (un archivo previo con contenido no se toca) y se muestra el error real.
    const r = await cleanOnFail(core, path, core.exportHosts(ids, path, true, format));
    setMsg(t("hosts.data.export.done", { n: String(r.count), path }));
    if (r.warnings.length) setWarn(ct(r.warnings.join(" "), "hosts.coreWarn"));
  });

  const startImport = () => run(async () => {
    const path = await core.pickPath({ title: t("hosts.data.import"), filters: [{ name: "CSV / JSON", pattern: "*.csv;*.json" }] });
    if (!path) return;
    const p = await core.previewHostsImport(path);
    setPrev(p); setResult(null);
    setActs(Object.fromEntries(p.items.filter((i) => i.state === "conflicto").map((i) => [i.key, "omitir" as HostImportAction])));
  });

  const apply = () => run(async () => {
    if (!prev) return;
    try {
      const r = await core.applyHostsImport(prev.token, Object.entries(acts).map(([key, action]) => ({ key, action })));
      setResult(r); setPrev(null); hostsChanged();
    } catch (e) {
      if (!/NotFound|FailedPrecondition/.test(String(e instanceof Error ? e.message : e))) throw e; // errorText quita el código: se mira el mensaje crudo
      setPrev(null); setErr(t("hosts.data.import.expired")); // el token vale 10 minutos y un solo uso: hay que volver a abrir el archivo
    }
  });

  const fieldName = (n: string) => <code>{n}</code>;
  // Avisos conocidos traducidos; los demás, el texto del núcleo en español y un genérico en inglés.
  const warnText = (w: string) => { const k = knownWarning(w); return k === "nosum" ? t("hosts.data.import.w.nosum") : k === "cred" ? t("hosts.data.import.w.cred", { n: String(prev?.items.filter((i) => i.credentialMissing).length || 1) }) : ct(w, "hosts.data.import.w.other"); };
  const stateOf = (i: HostImportItem) => (i.state === "conflicto" ? t(`hosts.data.import.state.${i.reason === "nombre" ? "nombre" : "direccion"}`) : t(`hosts.data.import.state.${i.state}`));

  return (
    <article className="hosts-data" aria-labelledby={`${uid}-h`}>
      <h4 id={`${uid}-h`}>{t("hosts.data.title")}</h4>
      <p>{t("hosts.data.what")}</p>
      <p className="hint">{t("hosts.data.formatShort")}</p>

      <div className="actions">
        <button type="button" disabled={busy} onClick={() => void template("csv")}><Icon name="download" />{t("hosts.data.template.csv")}</button>
        <button type="button" disabled={busy} onClick={() => void template("json")}><Icon name="download" />{t("hosts.data.template.json")}</button>
        <DetailsButton label={t("settings.data.details")} title={t("settings.data.details.title", { name: t("hosts.data.title") })}>
          <p className="hint">{t("hosts.data.formats")}</p>
          {fmt && <p className="hint">{t("hosts.data.limits", { rows: String(fmt.maxRows), size: String(Math.round(fmt.maxBytes / (1 << 20))) })}</p>}
          {fmt && (
            <div className="hosts-table">
              <table aria-label={t("hosts.data.fields")}>
                <thead><tr>{(["name", "type", "req", "example", "desc"] as const).map((c) => <th key={c} scope="col">{t(`hosts.data.col.${c}`)}</th>)}</tr></thead>
                <tbody>
                  {fmt.fields.map((f) => (
                    <tr key={f.name}>
                      <td>{fieldName(f.name)}</td>
                      <td>{TYPES[f.type] ? t(TYPES[f.type]) : ct(f.type, "hosts.data.field.exampleHidden")}</td>
                      <td>{t(f.required ? "hosts.data.yes" : "hosts.data.no")}</td>
                      <td>{neutral(f.name) ? <code>{f.example}</code> : ct(f.example, "hosts.data.field.exampleHidden")}</td>
                      <td>{FIELD_NAMES.has(f.name) ? t(descKey(f.name)) : ct(f.description, "hosts.data.field.exampleHidden")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="hint">{t("hosts.data.template.note")}</p>
        </DetailsButton>
      </div>

      <fieldset className="hosts-export">
        <legend>{t("hosts.data.export")}</legend>
        <div className="field-row">
          <Select label={t("hosts.data.export.format")} value={format} onChange={setFormat} w="sm" options={[["csv", "CSV"], ["json", "JSON"]]} />
          <Select label={t("hosts.data.export.scope")} value={scope} onChange={setScope} w="md" options={[["all", t("hosts.data.export.all")], ["some", t("hosts.data.export.some")]]} />
        </div>
        {scope === "some" && (
          <div role="group" aria-label={t("hosts.data.export.list")} className="hosts-pick-list">
            {book.map((h) => (
              <Check key={h.id} label={`${h.name} · ${h.address}:${h.port}`} checked={picked.has(h.id)}
                onChange={(v) => setPicked((s) => { const n = new Set(s); if (v) n.add(h.id); else n.delete(h.id); return n; })} />
            ))}
          </div>
        )}
        <div className="actions">
          <button type="button" disabled={busy} onClick={() => void exportHosts()}><Icon name="download" />{t("hosts.data.export.run")}</button>
          <button type="button" disabled={busy} onClick={() => void startImport()}><Icon name="upload" />{t("hosts.data.import")}</button>
        </div>
      </fieldset>

      {err && <Notice kind="error">{err}</Notice>}
      {msg && <Notice kind="ok">{msg}</Notice>}
      {warn && <Notice kind="warn">{warn}</Notice>}
      {result && <Notice kind="ok">{t("hosts.data.import.done", { created: String(result.created), replaced: String(result.replaced), renamed: String(result.renamed), skipped: String(result.skipped), invalid: String(result.invalid) })}</Notice>}

      {prev && (
        <section className="hosts-preview" aria-label={t("hosts.data.import.preview")}>
          <h5>{t("hosts.data.import.preview")} <Badge>{t("hosts.data.import.format", { format: prev.format.toUpperCase() })}</Badge></h5>
          {prev.warnings.length > 0 && (
            <Notice kind="warn">
              <strong>{t("hosts.data.import.warnings")}</strong>
              <ul>{prev.warnings.map((w, i) => <li key={i}>{warnText(w)}</li>)}</ul>
            </Notice>
          )}
          {prev.errors.length > 0 && (
            <>
              <h6>{t("hosts.data.import.errors", { n: String(prev.errors.length) })}</h6>
              <p className="hint">{t("hosts.data.import.errors.note")}</p>
              <div className="hosts-table">
                <table aria-label={t("hosts.data.import.errors.table")}>
                  <thead><tr><th scope="col">{t("hosts.data.import.col.line")}</th><th scope="col">{t("hosts.data.import.col.field")}</th><th scope="col">{t("hosts.data.import.col.core")}</th></tr></thead>
                  <tbody>
                    {prev.errors.map((e, i) => (
                      <tr key={i}>
                        <td className="mono">{e.line}</td>
                        <td>{e.field ? fieldName(e.field) : t("hosts.data.import.wholeRow")}</td>
                        <td className="hosts-core-cell">{lang === "es" ? e.reason : t(e.field ? "hosts.data.import.invalid" : "hosts.data.import.invalidRow")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {prev.items.length === 0 ? <p className="hint">{t("hosts.data.import.nothing")}</p> : (
            <>
              <h6>{t("hosts.data.import.states", { n: String(prev.items.length) })}</h6>
              <div className="hosts-table">
                <table aria-label={t("hosts.data.import.states.table")}>
                  <thead><tr>{(["host", "dest", "state", "cred", "action"] as const).map((c) => <th key={c} scope="col">{t(`hosts.data.import.col.${c}`)}</th>)}</tr></thead>
                  <tbody>
                    {prev.items.map((i) => (
                      <tr key={i.key}>
                        <td>{i.host.name}</td>
                        <td className="mono">{i.key}</td>
                        <td><Badge tone={i.state === "conflicto" ? "warn" : i.state === "nuevo" ? "ok" : ""}>{stateOf(i)}</Badge></td>
                        <td>{i.host.credentialLabel || "—"}{i.credentialMissing && <div className="hint">{t("hosts.data.import.credMissing")}</div>}</td>
                        <td>
                          {i.state === "conflicto" ? (
                            <Select label={t("hosts.data.import.action.aria", { name: i.host.name })} value={acts[i.key] ?? "omitir"} onChange={(v) => setActs((a) => ({ ...a, [i.key]: v }))}
                              options={(["omitir", "reemplazar", ...(i.reason === "nombre" ? ["renombrar"] : [])] as HostImportAction[]).map((a) => [a, t(`hosts.data.import.action.${a}`)] as [HostImportAction, string])} />
                          ) : <span className="hint">{t("hosts.data.import.auto")}</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {prev.errors.length > 0 && <p className="hint">{t("hosts.data.import.applyNote", { n: String(prev.errors.length) })}</p>}
          <div className="actions">
            <button type="button" className="primary" disabled={busy || prev.items.length === 0} onClick={() => void apply()}>{t("hosts.data.import.apply")}</button>
            <button type="button" onClick={() => setPrev(null)}>{t("hosts.data.import.cancel")}</button>
          </div>
        </section>
      )}
    </article>
  );
}
