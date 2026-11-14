import { useEffect, useState } from "react";
import { scriptsChanged } from "../scripts/signal";
import type { CoreAPI } from "../../lib/core";
import { cleanOnFail } from "../../lib/cleanOnFail";
import { errInfo } from "../../lib/coreError";
import { Check, Field, Notice, Select, errorText } from "../../components/Field";
import { Dialog } from "../../components/Dialog";
import { useT } from "../../lib/i18n";
import type { PackExportResult, PackImportDecision, PackImportResult } from "./api";
import type { ScriptItem } from "../scripts/api";

// Todo texto que viene del paquete (nombres, IDs) se dibuja como texto de React: sin HTML, imágenes ni enlaces (ADR 0010).
// Como el núcleo (pack.go idRe y thirdPartyEditor); los editores reservados (oom, lib, plataformas…) los rechaza él.
const EDITOR_RE = /^[a-z0-9]{1,16}\/[a-z0-9][a-z0-9-]{0,31}$/;
// Rechazos que indican que el estado cambió desde la vista previa: hay que volver a abrir el archivo.
const STALE = ["pack.err.import.changed", "pack.err.import.missing", "pack.err.import.decision"];

export function ExportDialog({ core, onClose }: { core: CoreAPI; onClose: () => void }) {
  const t = useT();
  const [scripts, setScripts] = useState<ScriptItem[]>([]);
  const [picked, setPicked] = useState<string[]>([]);
  const [editor, setEditor] = useState("");
  const [playbooks, setPlaybooks] = useState(false);
  const [license, setLicense] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [author, setAuthor] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<PackExportResult | null>(null);
  useEffect(() => { core.listScripts().then((l) => setScripts(l.filter((s) => s.origin === "usuario")), (e) => setErr(errorText(e))); }, [core]);
  const go = async () => {
    setBusy(true); setErr(""); setRes(null);
    try {
      const path = await core.pickSavePath(t("packs.export.fileName")); // confirma el reemplazo y deja el archivo vacío
      if (!path) return;
      setRes(await cleanOnFail(core, path, core.packExport({ editorName: editor, scriptIds: picked, includePlaybooks: playbooks, license, path, overwrite: true, name, nameEn: "", description, descriptionEn: "", author })));
    } catch (e) { setErr(errorText(e)); } finally { setBusy(false); }
  };
  return (
    <Dialog title={t("packs.export.title")} onClose={onClose}>
      <Field label={t("packs.export.editor")} hint={t("packs.export.editorHint")} value={editor} onChange={setEditor} mono
        error={editor && !EDITOR_RE.test(editor) ? t("packs.export.editorBad") : undefined} />
      <h4>{t("packs.export.scripts")}</h4>
      {scripts.length === 0 && <p className="hint">{t("packs.export.noScripts")}</p>}
      {scripts.map((s) => <Check key={s.id} label={s.name} checked={picked.includes(s.id)} onChange={(v) => setPicked((p) => (v ? [...p, s.id] : p.filter((x) => x !== s.id)))} />)}
      <Check label={t("packs.export.playbooks")} checked={playbooks} onChange={setPlaybooks} />
      <Field label={t("packs.export.name")} value={name} onChange={setName} />
      <Field label={t("packs.export.description")} value={description} onChange={setDescription} />
      <Field label={t("packs.export.author")} value={author} onChange={setAuthor} />
      <Field label={t("packs.export.license")} hint={t("packs.export.licenseHint")} value={license} onChange={setLicense} />
      {!picked.length && !playbooks && <p className="hint">{t("packs.export.nothing")}</p>}
      {err && <Notice kind="error">{err}</Notice>}
      {res && <Notice kind="ok">{t("packs.export.done", { id: res.id, version: res.version, sha: res.sha256, scripts: res.scripts, playbooks: res.playbooks })}</Notice>}
      {res && res.omittedPlaybooks.length > 0 && <Notice kind="warn">{t("packs.export.omitted", { ids: res.omittedPlaybooks.join(", ") })}</Notice>}
      <div className="actions"><button type="button" className="primary" disabled={busy || !EDITOR_RE.test(editor) || (!picked.length && !playbooks)} onClick={go}>{t("packs.export.go")}</button></div>
    </Dialog>
  );
}

export function ImportDialog({ core, path, preview, onDone, onClose }: { core: CoreAPI; path: string; preview: PackImportResult; onDone: () => void; onClose: () => void }) {
  const t = useT();
  const [choice, setChoice] = useState<Record<string, string>>({});
  const [err, setErr] = useState("");
  const [changed, setChanged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<PackImportResult | null>(null);
  const conflicts = preview.items.filter((i) => i.state.startsWith("conflicto"));
  const ck = (i: { kind: string; id: string }) => `${i.kind}:${i.id}`; // un script y un playbook con el mismo id no comparten la elección
  const pending = conflicts.filter((i) => !choice[ck(i)]).length;
  const ready = !res && !changed && pending === 0;
  const go = async () => {
    setBusy(true); setErr(""); setChanged(false);
    try {
      const decisions: PackImportDecision[] = conflicts.map((i) => ({ itemId: i.id, action: choice[ck(i)] }));
      setRes(await core.packImport(path, preview.sha256, decisions));
      onDone(); scriptsChanged(); // la biblioteca de scripts y los favoritos de la terminal cambiaron
    } catch (e) { setErr(errorText(e)); setChanged(STALE.includes(errInfo(e)?.reason ?? "")); } finally { setBusy(false); }
  };
  const line = (k: string, c: number, r: number, s: number) => <p>{t("packs.import.done", { kind: k, created: c, renamed: r, skipped: s })}</p>;
  return (
    <Dialog title={t("packs.import.title")} onClose={onClose}>
      <ul className="pack-import-items">
        {preview.items.map((i) => (
          <li key={`${i.kind}:${i.id}`}>
            <span>{t(`packs.import.kind.${i.kind}` as never)} · <code>{i.id}</code> · {i.name} · {t(`packs.import.state.${i.state}` as never)}</span>
            {i.state.startsWith("conflicto") && (
              <Select label={t("packs.import.decision", { id: i.id })} value={choice[ck(i)] ?? ""} placeholder={t("packs.import.choose")} disabled={!!res}
                onChange={(v) => setChoice((c) => ({ ...c, [ck(i)]: v }))} options={[["renombrar", t("packs.import.rename")], ["omitir", t("packs.import.skip")]]} />
            )}
          </li>
        ))}
      </ul>
      {err && <Notice kind="error">{err}</Notice>}
      {changed && <Notice kind="warn">{t("packs.import.changed")}</Notice>}
      {res && <>{line(t("packs.import.kinds.scripts"), res.scriptsCreated, res.scriptsRenamed, res.scriptsSkipped)}{line(t("packs.import.kinds.playbooks"), res.playbooksCreated, res.playbooksRenamed, res.playbooksSkipped)}</>}
      {!res && pending > 0 && <p className="hint">{t("packs.import.pending", { n: pending })}</p>}
      {!res && <div className="actions"><button type="button" className="primary" disabled={busy || !ready} onClick={go}>{t("packs.import.go")}</button></div>}
    </Dialog>
  );
}
