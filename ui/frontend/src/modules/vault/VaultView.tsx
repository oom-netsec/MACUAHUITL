import { useCallback, useEffect, useId, useRef, useState } from "react";
import type { CoreAPI, Credential, VaultState } from "../../lib/core";
import { ConfirmButton, Field, Notice, errorText } from "../../components/Field";
import { CopyButton } from "../../components/Data";
import { Badge, EmptyState, Page, Section } from "../../components/Page";
import { Glyph } from "../../components/Glyph";
import { DataTable, type Column } from "../../components/DataTable";
import { useT } from "../../lib/i18n";
import { vaultChanged } from "../../lib/vaultSignal";
import { useCoreLoad } from "../../lib/useCoreLoad";
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
  const [keyShown, setKeyShown] = useState<ShownKey | null>(null); // llave pública a la vista (recién creada o consultada), con la credencial a la que pertenece
  const lastView = useRef(""); // último «Ver» pedido: una respuesta tardía de otra credencial se descarta
  const fail = (e: unknown) => setMsg({ kind: "error", text: errorText(e) });
  const previewOpen = useRef(false); // hay una vista previa de un respaldo con credenciales descifradas en el núcleo
  const reloadErr = useRef<Msg>(null); // el aviso que dejó la última recarga fallida
  const load = useCallback(async (live: () => boolean = () => true) => {
    const s = await core.vaultStatus();
    if (!live()) return;
    setMsg((m) => (m === reloadErr.current ? null : m)); // el núcleo respondió: el error de una recarga anterior ya no vale (los de acciones se quedan)
    if (s.state !== "unlocked" && previewOpen.current) { // el núcleo la descartó al cerrarse la bóveda
      previewOpen.current = false;
      setMsg({ kind: "error", text: t("vault.backup.discarded") });
    }
    setState(s.state);
    const l = s.state === "unlocked" ? await core.listCredentials() : [];
    if (live()) setCreds(l);
  }, [core, t]);
  const refresh = useCallback(() => load().catch((e) => { reloadErr.current = { kind: "error", text: errorText(e) }; setMsg(reloadErr.current); }), [load]);
  // Cerrada desde la paleta o por tiempo, o núcleo reconectado: la vista se pone al día y el error de carga se va al reintentar.
  const [loadErr] = useCoreLoad(load, [load]);
  const onPreview = useCallback((open: boolean) => { previewOpen.current = open; }, []);
  const changed = useCallback(() => { vaultChanged(); return refresh(); }, [refresh]); // avisa a las demás vistas

  const notice = msg ? <Notice kind={msg.kind}>{msg.text}</Notice> : loadErr && <Notice kind="error">{loadErr}</Notice>;
  // Sin estado aún: no se dibuja ningún diseño para no saltar de "abierta" a "cerrada" al llegar la respuesta.
  if (state === null && !msg && !loadErr) return <div className="skeleton" role="status" aria-label={t("shell.loading")}><i /><i /><i /></div>;
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
          try { await core.vaultLock(); setCreds([]); setKeyShown(null); setMsg(null); changed(); } catch (e) { fail(e); }
        }}>{t("vault.lock")}</button>
      )}>
      {notice}
      {state === "unlocked" && (
        <>
          <CredentialList creds={creds} onViewKey={async (c) => {
            lastView.current = c.id;
            try {
              const publicKey = await core.credentialPublicKey(c.id);
              if (lastView.current === c.id) setKeyShown({ id: c.id, label: c.label, username: c.username, publicKey });
            } catch (e) { if (lastView.current === c.id) fail(e); }
          }} onRegenerate={async (c) => {
            lastView.current = c.id;
            try {
              const publicKey = await core.regenerateKeyCredential(c.id, true); // la confirmación la dio la persona en el botón
              if (lastView.current !== c.id) { setMsg({ kind: "ok", text: t("vault.key.regenerated") }); return; } // la persona ya miró otra credencial: no se la pisa
              setKeyShown({ id: c.id, label: c.label, username: c.username, publicKey, regenerated: true });
              setMsg(null);
            } catch (e) { fail(e); }
          }} onDelete={async (id) => {
            try { await core.deleteCredential(id); setKeyShown((k) => (k?.id === id ? null : k)); setMsg({ kind: "ok", text: t("vault.deleted") }); changed(); } catch (e) { fail(e); }
          }} />
          {keyShown && <PublicKey key={keyShown.id + keyShown.publicKey} k={keyShown} onClose={() => setKeyShown(null)} />}
          <CredentialForm core={core} onDone={changed} setMsg={setMsg} />
          <KeyForm core={core} onDone={changed} setMsg={setMsg} onCreated={(k) => { lastView.current = k.id; setKeyShown(k); }} />
          <BackupSection core={core} sshKeys={creds.filter((c) => c.hasSshKey).length} setMsg={setMsg} onImported={changed} onPreview={onPreview} onClosed={() => { previewOpen.current = false; setMsg({ kind: "error", text: t("vault.backup.discarded") }); changed(); }} />
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

function CredentialList({ creds, onDelete, onViewKey, onRegenerate }: { creds: Credential[]; onDelete: (id: string) => void; onViewKey: (c: Credential) => void; onRegenerate: (c: Credential) => void }) {
  const t = useT();
  if (!creds.length) return <EmptyState icon="lock" title={t("vault.creds.empty")}>{t("vault.creds.empty.hint")}</EmptyState>;
  const cols: Column<Credential>[] = [
    { id: "label", header: t("vault.col.label"), value: (c) => c.label },
    { id: "user", header: t("vault.col.user"), value: (c) => c.username, mono: true },
    { id: "details", header: t("vault.col.details"), value: (c) => [c.kind === "key" && t("vault.kind.key"), c.hasEnable && t("vault.hasEnable"), c.hasSshKey && c.kind !== "key" && t("vault.hasSshKey")].filter(Boolean).join(" "),
      render: (c) => <>{c.kind === "key" && <Badge>{t("vault.kind.key")}</Badge>}{c.hasEnable && <Badge>{t("vault.hasEnable")}</Badge>}{c.hasSshKey && c.kind !== "key" && <Badge>{t("vault.hasSshKey")}</Badge>}</> },
    { id: "actions", header: t("vault.col.actions"), value: () => "", width: 380,
      render: (c) => <>{c.kind === "key" && <button type="button" className="sm" aria-label={t("vault.key.view", { label: c.label })} onClick={() => onViewKey(c)}>{t("vault.key.viewBtn")}</button>} {c.kind === "key" && <ConfirmButton label={t("vault.key.regen.aria", { label: c.label })} confirmLabel={t("vault.key.regen.confirm", { label: c.label })} onConfirm={() => onRegenerate(c)}>{t("vault.key.regen")}</ConfirmButton>} <ConfirmButton label={t("vault.deleteCred", { label: c.label })} confirmLabel={t("vault.confirmCred", { label: c.label })} onConfirm={() => onDelete(c.id)}>{t("common.delete")}</ConfirmButton></> },
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

type ShownKey = { id: string; label: string; username: string; publicKey: string; regenerated?: boolean };

// Llave pública: texto de solo lectura, monoespaciado y seleccionable, con Copiar y dónde pegarla en el equipo.
// Al aparecer toma el foco (el lector de pantalla anuncia el título y quien la abrió la ve sin buscarla).
function PublicKey({ k, onClose }: { k: ShownKey; onClose: () => void }) {
  const t = useT();
  const h = useId();
  const ref = useRef<HTMLElement>(null);
  useEffect(() => { ref.current?.focus(); ref.current?.scrollIntoView?.({ block: "nearest" }); }, []);
  return (
    <section ref={ref} tabIndex={-1} className="section vault-pubbox" aria-labelledby={h} aria-describedby={`${h}-d`}>
      <h3 id={h}>{t("vault.key.titleOf", { label: k.label })}</h3>
      {k.regenerated && <Notice kind="warn">{t("vault.key.regenerated")}</Notice>}
      <p id={`${h}-d`} className="meta">{t("vault.key.hint")}</p>
      <p><code className="mono vault-pub">{k.publicKey}</code> <CopyButton value={k.publicKey} label={t("vault.key.copyLabel")} /></p>
      <h4>{t("vault.key.where")}</h4>
      <ul>
        <li>{t("vault.key.linux")}</li>
        <li>{t("vault.key.linux.perms")}</li>
        <li>{t("vault.key.win.admin")}</li>
        <li>{t("vault.key.win.user")}</li>
      </ul>
      <p className="meta">{t("vault.key.win.perms")}</p>
      <div className="actions"><button type="button" onClick={onClose}>{t("window.close")}</button></div>
    </section>
  );
}

// Alta con llave SSH: solo etiqueta y usuario. La privada se genera y se queda en el núcleo; no hay forma de importar una.
function KeyForm({ core, onDone, setMsg, onCreated }: FormProps & { onCreated: (k: ShownKey) => void }) {
  const t = useT();
  const [label, setLabel] = useState("");
  const [user, setUser] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return setMsg({ kind: "error", text: t("vault.err.userRequired") });
    setBusy(true);
    try {
      const k = await core.createKeyCredential(label, user);
      onCreated({ id: k.id, label: label || user, username: user, publicKey: k.publicKey });
      setLabel(""); setUser(""); setMsg({ kind: "ok", text: t("vault.key.created") });
      onDone();
    } catch (err) {
      setMsg({ kind: "error", text: errorText(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit}>
      <Section title={t("vault.key.new")}>
        <p className="meta">{t("vault.key.newHint")}</p>
        <div className="field-row">
          <Field label={t("vault.key.label")} value={label} onChange={setLabel} w="md" />
          <Field label={t("vault.key.user")} value={user} onChange={setUser} w="md" />
        </div>
        <div className="actions"><button type="submit" aria-busy={busy} disabled={busy}>{t("vault.key.create")}</button></div>
      </Section>
    </form>
  );
}
