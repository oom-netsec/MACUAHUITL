import { useEffect, useState } from "react";
import type { CoreAPI, VaultBackupAction, VaultBackupPreview, VaultBackupResult, VaultBackupState } from "../../lib/core";
import { Check, Field, Notice, errorText } from "../../components/Field";
import { Badge, ResultPanel, Section, type Tone } from "../../components/Page";
import { Icon } from "../../components/Icon";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import type { Msg } from "./VaultView";

const MIN_PHRASE = 12;
const tone: Record<VaultBackupState, Tone> = { nueva: "ok", igual: "", conflicto_etiqueta: "warn", reservada: "" };

// Respaldo cifrado de la bóveda: exportar con una frase propia e importar en dos pasos. Las frases no se guardan: se vacían los campos al enviarlas.
// onPreview avisa a la vista si hay una vista previa abierta; onClosed, que la bóveda se cerró y la vista previa se descartó.
export function BackupSection({ core, setMsg, onImported, onPreview, onClosed }: {
  core: CoreAPI; setMsg: (m: Msg) => void; onImported: () => void; onPreview: (open: boolean) => void; onClosed: () => void;
}) {
  const t = useT();
  const [f1, setF1] = useState("");
  const [f2, setF2] = useState("");
  const [sure, setSure] = useState(false);
  const [imp, setImp] = useState("");
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<VaultBackupPreview | null>(null);
  const fail = (e: unknown) => setMsg({ kind: "error", text: errorText(e) });
  useEffect(() => onPreview(preview !== null), [preview, onPreview]);

  const exportBackup = async () => {
    if ([...f1].length < MIN_PHRASE) return setMsg({ kind: "error", text: t("vault.backup.err.short") });
    if (f1 !== f2) return setMsg({ kind: "error", text: t("vault.backup.err.mismatch") });
    const phrase = f1;
    setBusy(true);
    let path = "";
    try {
      path = await core.pickSavePath(t("vault.backup.fileName")); // confirma el reemplazo y deja el archivo vacío
      if (!path) return;
      const r = await core.exportVaultBackup(path, phrase, true, sure);
      setMsg({ kind: "ok", text: t("vault.backup.exported", { n: String(r.count), path }) + (r.noPermissions ? ` ${t("vault.backup.noPerms")}` : "") });
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
    setMsg({ kind: "ok", text: t("vault.backup.done", { created: String(r.created), replaced: String(r.replaced), renamed: String(r.renamed), skipped: String(r.skipped), same: String(r.same) }) });
    onImported();
  };
  const expired = () => { setPreview(null); setMsg({ kind: "error", text: t("vault.backup.expired") }); };

  return (
    <Section title={t("vault.backup")} description={t("vault.backup.desc")}>
      <div className="field-row">
        <Field label={t("vault.backup.phrase")} hint={t("vault.backup.phraseHint")} type="password" value={f1} onChange={setF1} autoComplete="new-password" w="md" />
        <Field label={t("vault.backup.phrase2")} type="password" value={f2} onChange={setF2} autoComplete="new-password" w="md" />
      </div>
      <Check label={t("vault.backup.confirm")} checked={sure} onChange={setSure} />
      <div className="actions">
        <button type="button" disabled={!sure || busy} aria-busy={busy} onClick={exportBackup}><Icon name="download" />{t("vault.backup.export")}</button>
      </div>
      <div className="field-row">
        <Field label={t("vault.backup.import.phrase")} type="password" value={imp} onChange={setImp} autoComplete="off" w="md" />
      </div>
      <div className="actions">
        <button type="button" disabled={!imp || busy} aria-busy={busy} onClick={importBackup}><Icon name="upload" />{t("vault.backup.import")}</button>
      </div>
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
      // NotFound (token gastado o descartado) y FailedPrecondition (vencido o bóveda cerrada) no se corrigen con otra decisión; InvalidArgument sí.
      if (/code = (NotFound|FailedPrecondition)\b/.test(e instanceof Error ? e.message : String(e))) { onExpired(); return; }
      setMsg({ kind: "error", text: errorText(e) }); setBusy(false);
    }
  };
  return (
    <ResultPanel title={t("vault.backup.preview")} pad
      actions={<><button type="button" className="primary" disabled={!ready || busy} aria-busy={busy} onClick={apply}>{t("vault.backup.apply")}</button><button type="button" onClick={() => onClose()}>{t("vault.backup.cancel")}</button></>}>
      <table>
        <thead><tr><th>{t("vault.col.label")}</th><th>{t("vault.col.user")}</th><th>{t("vault.backup.col.state")}</th><th>{t("vault.backup.col.action")}</th></tr></thead>
        <tbody>
          {preview.items.map((i) => (
            <tr key={i.id}>
              <td>{i.label}</td>
              <td className="mono">{i.username}</td>
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
      {!ready && <Notice kind="info">{t("vault.backup.needs")}</Notice>}
      <Notice kind="info">{t("vault.backup.memory")}</Notice>
    </ResultPanel>
  );
}
