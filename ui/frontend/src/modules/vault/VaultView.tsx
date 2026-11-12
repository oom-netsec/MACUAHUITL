import { useCallback, useEffect, useRef, useState } from "react";
import type { CoreAPI, Credential, VaultState } from "../../lib/core";
import { ConfirmButton, Field, Notice, errorText } from "../../components/Field";
import { Badge, EmptyState, Page, Section } from "../../components/Page";
import { Glyph } from "../../components/Glyph";
import { DataTable, type Column } from "../../components/DataTable";
import { useT } from "../../lib/i18n";
import { useVaultVersion, vaultChanged } from "../../lib/vaultSignal";
import { BackupSection } from "./BackupSection";
import "./vault.css";

// Al pegar una contraseña suele venir el salto de línea final; los espacios internos son parte de ella.
export const trimTrailingNewline = (s: string) => s.replace(/\r?\n$/, "");

export type Msg = { kind: "error" | "ok"; text: string } | null;

export function VaultView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [state, setState] = useState<VaultState | null>(null);
  const [creds, setCreds] = useState<Credential[]>([]);
  const [msg, setMsg] = useState<Msg>(null);
  const fail = (e: unknown) => setMsg({ kind: "error", text: errorText(e) });
  const previewOpen = useRef(false); // hay una vista previa de un respaldo con credenciales descifradas en el núcleo
  const refresh = useCallback(async () => {
    try {
      const s = await core.vaultStatus();
      if (s.state !== "unlocked" && previewOpen.current) { // el núcleo la descartó al cerrarse la bóveda
        previewOpen.current = false;
        setMsg({ kind: "error", text: t("vault.backup.discarded") });
      }
      setState(s.state);
      setCreds(s.state === "unlocked" ? await core.listCredentials() : []);
    } catch (e) {
      fail(e);
    }
  }, [core, t]);
  const vv = useVaultVersion(); // cerrada desde la paleta o por tiempo: la vista se pone al día
  useEffect(() => void refresh(), [refresh, vv]);
  const onPreview = useCallback((open: boolean) => { previewOpen.current = open; }, []);
  const changed = useCallback(() => { vaultChanged(); return refresh(); }, [refresh]); // avisa a las demás vistas

  const notice = msg && <Notice kind={msg.kind}>{msg.text}</Notice>;
  // Sin estado aún: no se dibuja ningún diseño para no saltar de "abierta" a "cerrada" al llegar la respuesta.
  if (state === null && !msg) return <div className="skeleton" role="status" aria-label={t("shell.loading")}><i /><i /><i /></div>;
  if (state === "absent" || state === "locked") {
    return (
      <section aria-labelledby="vault-h" className="lockscreen">
        <div className="lock-card">
          <span className="lock-glyph"><Glyph size={56} /></span>
          <h2 id="vault-h">{t("vault.title")}</h2>
          <p className="meta">{t(state === "absent" ? "vault.absent" : "vault.locked")}</p>
          {notice}
          {state === "absent" ? <CreateForm core={core} onDone={changed} setMsg={setMsg} /> : <UnlockForm core={core} onDone={changed} setMsg={setMsg} />}
        </div>
      </section>
    );
  }
  return (
    <Page title={t("vault.title")} description={t("vault.desc")}
      actions={state === "unlocked" && (
        <button onClick={async () => {
          try { await core.vaultLock(); setCreds([]); setMsg(null); changed(); } catch (e) { fail(e); }
        }}>{t("vault.lock")}</button>
      )}>
      {notice}
      {state === "unlocked" && (
        <>
          <CredentialList creds={creds} onDelete={async (id) => {
            try { await core.deleteCredential(id); setMsg({ kind: "ok", text: t("vault.deleted") }); changed(); } catch (e) { fail(e); }
          }} />
          <CredentialForm core={core} onDone={changed} setMsg={setMsg} />
          <BackupSection core={core} setMsg={setMsg} onImported={changed} onPreview={onPreview} onClosed={() => { previewOpen.current = false; setMsg({ kind: "error", text: t("vault.backup.discarded") }); changed(); }} />
        </>
      )}
    </Page>
  );
}

type FormProps = { core: CoreAPI; onDone: () => void; setMsg: (m: Msg) => void };

function CreateForm({ core, onDone, setMsg }: FormProps) {
  const t = useT();
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const pa = trimTrailingNewline(a), pb = trimTrailingNewline(b);
    if (!pa) return setMsg({ kind: "error", text: t("vault.err.empty") });
    if (pa !== pb) return setMsg({ kind: "error", text: t("vault.err.mismatch") });
    setBusy(true);
    try {
      await core.vaultCreate(pa);
      setMsg({ kind: "ok", text: t("vault.created") });
      onDone();
    } catch (err) {
      setMsg({ kind: "error", text: errorText(err) });
    } finally {
      setA(""); setB(""); setBusy(false);
    }
  };
  return (
    <form onSubmit={submit}>
      <Field label={t("vault.masterNew")} type="password" value={a} onChange={setA} autoComplete="new-password" />
      <Field label={t("vault.masterConfirm")} type="password" value={b} onChange={setB} autoComplete="new-password" />
      <button type="submit" aria-busy={busy} disabled={busy}>{t("vault.create")}</button>
    </form>
  );
}

function UnlockForm({ core, onDone, setMsg }: FormProps) {
  const t = useT();
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const p = trimTrailingNewline(pw);
    setPw(""); setBusy(true);
    try {
      await core.vaultUnlock(p);
      setMsg(null);
      onDone();
    } catch (err) {
      setMsg({ kind: "error", text: errorText(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit}>
      <Field label={t("vault.master")} type="password" value={pw} onChange={setPw} autoComplete="current-password" />
      <button type="submit" aria-busy={busy} disabled={busy}>{t("vault.unlock")}</button>
    </form>
  );
}

function CredentialList({ creds, onDelete }: { creds: Credential[]; onDelete: (id: string) => void }) {
  const t = useT();
  if (!creds.length) return <EmptyState icon="lock" title={t("vault.creds.empty")}>{t("vault.creds.empty.hint")}</EmptyState>;
  const cols: Column<Credential>[] = [
    { id: "label", header: t("vault.col.label"), value: (c) => c.label },
    { id: "user", header: t("vault.col.user"), value: (c) => c.username, mono: true },
    { id: "details", header: t("vault.col.details"), value: (c) => [c.hasEnable && t("vault.hasEnable"), c.hasSshKey && t("vault.hasSshKey")].filter(Boolean).join(" "),
      render: (c) => <>{c.hasEnable && <Badge>{t("vault.hasEnable")}</Badge>}{c.hasSshKey && <Badge>{t("vault.hasSshKey")}</Badge>}</> },
    { id: "actions", header: t("vault.col.actions"), value: () => "", width: 120,
      render: (c) => <ConfirmButton label={t("vault.deleteCred", { label: c.label })} confirmLabel={t("vault.confirmCred", { label: c.label })} onConfirm={() => onDelete(c.id)}>{t("common.delete")}</ConfirmButton> },
  ];
  return (
    <Section title={t("vault.creds")}>
      <DataTable label={t("vault.creds")} columns={cols} rows={creds} rowKey={(c) => c.id} height={Math.min(420, 76 + 32 * creds.length)} />
    </Section>
  );
}

function CredentialForm({ core, onDone, setMsg }: FormProps) {
  const t = useT();
  const [label, setLabel] = useState("");
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [en, setEn] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const p = trimTrailingNewline(pass), x = trimTrailingNewline(en);
    setPass(""); setEn("");
    if (!user || !p) return setMsg({ kind: "error", text: t("vault.err.required") });
    setBusy(true);
    try {
      await core.putCredential(label, user, p, x);
      setLabel(""); setUser(""); setMsg({ kind: "ok", text: t("vault.saved") });
      onDone();
    } catch (err) {
      setMsg({ kind: "error", text: errorText(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit}>
      <Section title={t("vault.newCred")}>
        <div className="field-row">
          <Field label={t("vault.label")} value={label} onChange={setLabel} w="md" />
          <Field label={t("vault.user")} value={user} onChange={setUser} w="md" />
        </div>
        <div className="field-row">
          <Field label={t("vault.pass")} type="password" value={pass} onChange={setPass} w="md" />
          <Field label={t("vault.enable")} type="password" value={en} onChange={setEn} w="md" />
        </div>
        <div className="actions">
          <button type="submit" aria-busy={busy} disabled={busy}>{t("vault.save")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
        </div>
      </Section>
    </form>
  );
}
