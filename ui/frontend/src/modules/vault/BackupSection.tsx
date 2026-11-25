import { useEffect, useRef, useState } from "react";
import { RunButton } from "../../components/RunButton";
import type { CoreAPI, VaultBackupAction, VaultBackupPreview, VaultBackupResult, VaultBackupState } from "../../lib/core";
import { Check, Field, Labeled, Notice, errorText } from "../../components/Field";
import { Badge, ResultPanel, Section, type Tone } from "../../components/Page";
import { Segmented } from "../../components/Segmented";
import { Icon } from "../../components/Icon";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { errInfo } from "../../lib/coreError";
import type { Msg } from "./VaultView";

const MIN_PHRASE = 12;
const tone: Record<VaultBackupState, Tone> = { nueva: "ok", igual: "", conflicto_etiqueta: "warn", reservada: "" };

// Respaldo cifrado de la bóveda: exportar con una frase propia e importar en dos pasos. Las frases no se guardan: se vacían los campos al enviarlas.
// La maestra que pide el export va en un campo NO controlado: vive solo en el DOM, se lee al enviar y se borra siempre.
// onPreview avisa a la vista si hay una vista previa abierta; onClosed, que la bóveda se cerró y la vista previa se descartó.
export function BackupSection({ core, sshKeys, setMsg, onImported, onPreview, onClosed }: {
  core: CoreAPI; sshKeys: number; setMsg: (m: Msg) => void; onImported: () => void; onPreview: (open: boolean) => void; onClosed: () => void;
}) {
  const t = useT();
  const [mode, setMode] = useState<"export" | "import">("export");
  const [f1, setF1] = useState("");
  const [f2, setF2] = useState("");
  const [sure, setSure] = useState(false);
  const [imp, setImp] = useState("");
  const [busy, setBusy] = useState(false);
  const master = useRef<HTMLInputElement>(null);
  const [preview, setPreview] = useState<VaultBackupPreview | null>(null);
  const fail = (e: unknown) => setMsg({ kind: "error", text: errorText(e) });
  useEffect(() => onPreview(preview !== null), [preview, onPreview]);

  const exportBackup = async () => {
    const mp = master.current?.value ?? "";
    if (master.current) master.current.value = ""; // se vacía antes de cualquier salida: también si la frase no sirve
    if ([...f1].length < MIN_PHRASE) return setMsg({ kind: "error", text: t("vault.backup.err.short") });
    if (f1 !== f2) return setMsg({ kind: "error", text: t("vault.backup.err.mismatch") });
    if (!mp) { master.current?.focus(); return setMsg({ kind: "error", text: t("vault.backup.err.master") }); }
    const phrase = f1;
    setBusy(true);
    let path = "";
    try {
      path = await core.pickSavePath(t("vault.backup.fileName")); // confirma el reemplazo y deja el archivo vacío
      if (!path) return;
      const r = await core.exportVaultBackup(path, phrase, mp, true, sure);
      setMsg({ kind: "ok", text: t("vault.backup.exported", { n: r.count, path }) + (r.noPermissions ? ` ${t("vault.backup.noPerms")}` : "") + (r.sshKeysIncluded > 0 ? ` ${t("vault.backup.keys.after", { n: String(r.sshKeysIncluded) })}` : "") });
      setSure(false);
    } catch (e) {
      if (path) await core.removeEmptyFile(path).catch(() => {}); // el diálogo dejó un archivo vacío que no sirve
      fail(e);
    } finally {
      setF1(""); setF2(""); setBusy(false);
    }
  };

  const importBackup = async () => {
    if (!imp) return setMsg({ kind: "error", text: t("vault.backup.err.empty") });
    const phrase = imp;
    setBusy(true);
    try {
      const path = await core.pickPath({ title: t("vault.backup.import.file"), filters: [{ name: "MCVAULT", pattern: "*.mcvault" }] });
      if (!path) return;
      setMsg(null);
      setPreview(await core.previewVaultBackupImport(path, phrase));
    } catch (e) {
      fail(e);
    } finally {
      setImp(""); setBusy(false);
    }
  };

  const end = (r?: VaultBackupResult) => {
    setPreview(null);
    if (!r) return;
    setMsg({ kind: "ok", text: t("vault.backup.done", { created: String(r.created), replaced: String(r.replaced), renamed: String(r.renamed), skipped: String(r.skipped) }) });
    onImported();
  };
  const expired = () => { setPreview(null); setMsg({ kind: "error", text: t("vault.backup.expired") }); };

  return (
    <Section title={t("vault.backup")} description={t("vault.backup.desc")}>
      <Segmented legend={t("vault.backup.mode")} value={mode} onChange={(m) => { setMode(m); setF1(""); setF2(""); setImp(""); setSure(false); }} options={[["export", t("vault.backup.modeExport")], ["import", t("vault.backup.modeImport")]]} />
      {mode === "export" ? (
        <>
      <div className="field-row">
        <Labeled label={t("vault.backup.master")} hint={t("vault.backup.masterHint")} w="md">
          {(id, hintId) => <input id={id} ref={master} type="password" autoComplete="off" spellCheck={false} aria-describedby={hintId} />}
        </Labeled>
      </div>
      <div className="field-row">
        <Field label={t("vault.backup.phrase")} hint={t("vault.backup.phraseHint")} type="password" value={f1} onChange={setF1} autoComplete="new-password" w="md" />
        <Field label={t("vault.backup.phrase2")} type="password" value={f2} onChange={setF2} autoComplete="new-password" w="md" />
      </div>
      {sshKeys > 0 && <Notice kind="warn">{t("vault.backup.keys.before", { n: String(sshKeys) })}</Notice>}
      <Check label={t("vault.backup.confirm")} checked={sure} onChange={setSure} />
      <div className="actions">
        <RunButton busy={busy} missing={[!sure && t("need.backupSure")]} onClick={exportBackup}><Icon name="download" />{t("vault.backup.export")}</RunButton>
      </div>
        </>
      ) : (
        <>
      <div className="field-row">
        <Field label={t("vault.backup.import.phrase")} type="password" value={imp} onChange={setImp} autoComplete="off" w="md" />
      </div>
      <div className="actions">
        <RunButton busy={busy} missing={[!imp && t("need.backupPhrase")]} onClick={importBackup}><Icon name="upload" />{t("vault.backup.import")}</RunButton>
      </div>
        </>
      )}
      {preview && <PreviewPanel core={core} preview={preview} onClose={end} onExpired={expired} onClosed={() => { setPreview(null); onClosed(); }} setMsg={setMsg} />}
    </Section>
  );
}

// Paso 2 del import: una decisión por credencial en conflicto. No muestra secretos: etiqueta, usuario y estado.
function PreviewPanel({ core, preview, onClose, onExpired, onClosed, setMsg }: {
  core: CoreAPI; preview: VaultBackupPreview; onClose: (r?: VaultBackupResult) => void; onExpired: () => void; onClosed: () => void; setMsg: (m: Msg) => void;
}) {
  const t = useT();
  const [picks, setPicks] = useState<Record<string, VaultBackupAction>>({});
  const [busy, setBusy] = useState(false);
  const conflicts = preview.items.filter((i) => i.state === "conflicto_etiqueta");
  const ready = conflicts.every((i) => picks[i.id]);
  const apply = async () => {
    setMsg(null); setBusy(true);
    try {
      onClose(await core.applyVaultBackupImport(preview.token, conflicts.map((i) => ({ id: i.id, action: picks[i.id] }))));
    } catch (e) {
      // Si la bóveda se cerró, el núcleo ya descartó lo descifrado: se sabe por su estado, no por el texto del error.
      const st = await core.vaultStatus().then((v) => v.state, () => "unlocked");
      if (st !== "unlocked") { onClosed(); return; }
      // La credencial de la bóveda cambió tras la vista previa: se cierra y se muestra el texto del núcleo.
      if (errInfo(e)?.reason === "respaldo.err.target_changed") { onClose(); setMsg({ kind: "error", text: errorText(e) }); return; }
      // NotFound (token gastado o descartado) y FailedPrecondition (vencido o bóveda cerrada) no se corrigen con otra decisión; InvalidArgument sí.
      if (/code = (NotFound|FailedPrecondition)\b/.test(e instanceof Error ? e.message : String(e))) { onExpired(); return; }
      setMsg({ kind: "error", text: errorText(e) }); setBusy(false);
    }
  };
  return (
    <ResultPanel title={t("vault.backup.preview")} pad
      actions={<><RunButton primary quiet busy={busy} missing={[!ready && t("need.backupDecisions")]} onClick={apply}>{t("vault.backup.apply")}</RunButton><button type="button" onClick={() => onClose()}>{t("vault.backup.cancel")}</button></>}>
      <table>
        <thead><tr><th>{t("vault.col.label")}</th><th>{t("vault.col.user")}</th><th>{t("vault.backup.col.id")}</th><th>{t("vault.backup.col.state")}</th><th>{t("vault.backup.col.action")}</th></tr></thead>
        <tbody>
          {preview.items.map((i) => (
            <tr key={i.id}>
              <td>{i.label}</td>
              <td className="mono">{i.username}</td>
              <td className="mono">{i.id}{i.state === "conflicto_etiqueta" && i.targetId ? <><br /><span>{t("vault.backup.col.targetId")}: {i.targetId}</span></> : null}</td>
              <td><Badge tone={tone[i.state]}>{t(`vault.backup.state.${i.state}` as Key)}</Badge></td>
              <td>
                {i.state === "conflicto_etiqueta" && (
                  <select aria-label={t("vault.backup.decision", { name: i.label })} value={picks[i.id] ?? ""} onChange={(e) => setPicks({ ...picks, [i.id]: e.target.value as VaultBackupAction })}>
                    <option value="" disabled>{t("vault.backup.act.choose")}</option>
                    <option value="renombrar">{t("vault.backup.act.renombrar")}</option>
                    <option value="reemplazar">{t("vault.backup.act.reemplazar")}</option>
                    <option value="omitir">{t("vault.backup.act.omitir")}</option>
                  </select>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {conflicts.length > 0 && <div className="actions"><button type="button" onClick={() => setPicks(Object.fromEntries(conflicts.map((i) => [i.id, "omitir" as const])))}>{t("vault.backup.skipAll")}</button></div>}
      {!ready && <Notice kind="info">{t("vault.backup.needs")}</Notice>}
      <Notice kind="info">{t("vault.backup.memory")}</Notice>
    </ResultPanel>
  );
}
