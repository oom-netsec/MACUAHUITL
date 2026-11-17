import { useEffect, useRef, useState } from "react";
import type { CoreAPI, VaultImportKeyResult } from "../../lib/core";
import { Field, Notice, errorText } from "../../components/Field";
import { CopyButton } from "../../components/Data";
import { Section } from "../../components/Page";
import { errInfo } from "../../lib/coreError";
import { useT } from "../../lib/i18n";

export const MAX_KEY_BYTES = 64 * 1024;

// Importar una privada existente: por archivo (solo viaja la ruta) o pegada. La privada pegada y la frase viven solo en este estado
// y se vacían en cuanto el núcleo responde, bien o mal, y al desmontar. Nada va a localStorage ni a logs.
export function ImportKeyForm({ core, onDone, onClose }: { core: CoreAPI; onDone: () => void; onClose: () => void }) {
  const t = useT();
  const [label, setLabel] = useState("");
  const [user, setUser] = useState("");
  const [path, setPath] = useState("");
  const [text, setText] = useState("");
  const [pass, setPass] = useState("");
  const [needPass, setNeedPass] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<(VaultImportKeyResult & { label: string }) | null>(null);
  const passRef = useRef<HTMLInputElement>(null);
  useEffect(() => () => { setText(""); setPass(""); }, []); // al desmontar
  useEffect(() => { if (needPass) passRef.current?.focus(); }, [needPass]);

  const reasonText = (e: unknown) => {
    const i = errInfo(e);
    switch (i?.reason) {
      case "vault.err.key_passphrase_wrong": return t("vault.import.err.passWrong");
      case "vault.err.key_import_invalid": return t("vault.import.err.invalid", { format: i.metadata.format ?? "?" });
      case "vault.err.key_import_unsupported": return t("vault.import.err.unsupported", { type: i.metadata.type ?? "?" }) + (i.metadata.format === "pkcs8-encrypted" ? " " + t("vault.import.err.pkcs8") : "");
      case "vault.err.field_too_long": return t("vault.import.err.tooLong");
      default: return errorText(e);
    }
  };
  const tooBig = new Blob([text]).size > MAX_KEY_BYTES;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return setErr(t("vault.err.userRequired"));
    if (!path && !text.trim()) return setErr(t("vault.import.needSource"));
    if (!path && tooBig) return setErr(t("vault.import.tooBig"));
    setErr(""); setNeedPass(false); setBusy(true);
    try {
      const r = await core.vaultImportKey({ label, username: user, ...(path ? { path } : { privateKey: text }), ...(pass ? { passphrase: pass } : {}) });
      setRes({ ...r, label: label || user }); setLabel(""); setUser(""); setPath("");
      onDone();
    } catch (x) {
      if (errInfo(x)?.reason === "vault.err.key_passphrase_required") { setNeedPass(true); setErr(t("vault.import.err.passRequired")); } else setErr(reasonText(x));
    } finally {
      setText(""); setPass(""); setBusy(false);
    }
  };
  const pick = async () => { const p = await core.pickPath({ title: t("vault.import.file") }).catch(() => ""); if (p) { setPath(p); setText(""); } };

  if (res) {
    return (
      <Section title={t("vault.import.done", { label: res.label })}>
        <Notice kind="ok">{t("vault.import.stored")}</Notice>
        {res.weak && <Notice kind="warn">{t("vault.import.weak", { bits: res.bits })}</Notice>}
        <p className="meta">{t("vault.import.kept")}</p>
        <p><code className="mono vault-pub">{res.publicKey}</code> <CopyButton value={res.publicKey} label={t("vault.key.copyLabel")} /></p>
        <p>{t("vault.import.fp")}: <code className="mono">{res.fingerprint}</code> <CopyButton value={res.fingerprint} label={t("vault.import.fpCopy")} /></p>
        <div className="actions"><button type="button" onClick={onClose}>{t("window.close")}</button></div>
      </Section>
    );
  }
  return (
    <form onSubmit={submit}>
      <Section title={t("vault.import.title")}>
        <p className="meta">{t("vault.import.hint")}</p>
        <p className="meta">{t("vault.import.stored")} {t("vault.import.kept")}</p>
        <div className="field-row">
          <Field label={t("vault.import.label")} value={label} onChange={setLabel} w="md" />
          <Field label={t("vault.import.user")} value={user} onChange={setUser} w="md" />
        </div>
        <div className="actions">
          <button type="button" onClick={pick}>{t("vault.import.pick")}</button>
          {path && <span className="meta">{t("vault.import.fileChosen", { path })}</span>}
        </div>
        <div className="field">
          <label htmlFor="vault-import-text">{t("vault.import.pasteLabel")}</label>
          <textarea id="vault-import-text" className="mono" rows={6} value={text} disabled={!!path} autoComplete="off" autoCorrect="off" spellCheck={false}
            aria-invalid={tooBig || undefined} onChange={(e) => setText(e.target.value)} />
          {tooBig && <div className="field-error">{t("vault.import.tooBig")}</div>}
        </div>
        <div className="field" data-w="md">
          <label htmlFor="vault-import-pass">{t("vault.import.pass")}</label>
          <input id="vault-import-pass" ref={passRef} type="password" value={pass} autoComplete="off" spellCheck={false} aria-invalid={needPass || undefined}
            aria-describedby={needPass ? "vault-import-pass-e" : undefined} onChange={(e) => setPass(e.target.value)} />
          {needPass && <div id="vault-import-pass-e" className="field-error">{t("vault.import.err.passRequired")}</div>}
        </div>
        {err && !needPass && <Notice kind="error">{err}</Notice>}
        <div className="actions">
          <button type="submit" aria-busy={busy} disabled={busy}>{t("vault.import.submit")}</button>
          <button type="button" onClick={onClose}>{t("common.cancel")}</button>
        </div>
      </Section>
    </form>
  );
}
