import { useEffect, useId, useRef, useState } from "react";
import { useBusy } from "../../app/activity";
import { Check, Console, Field, Notice, PathField, Select, TextArea, errorText } from "../../components/Field";
import { CopyButton } from "../../components/Data";
import { Segmented } from "../../components/Segmented";
import type { CoreAPI, Credential } from "../../lib/core";
import { ResultPanel, Section } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { TransferResult } from "./api";
import { absPath, buildURL, clientErrors, clientProtos, getParams, parseClientURL, portOf, putParams, putProtos, usesCred, usesSsh, type ClientForm, type ClientProto } from "./client";
import { hostKeyFromError } from "./validate";
import { useVaultVersion } from "../../lib/vaultSignal";

const label = (p: ClientProto) => p.toUpperCase();
// Campos con error que viven dentro de «Opciones avanzadas».
const advancedKeys = ["hash", "maxMB", "minutes"];

export function ClientPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const outId = useId();
  const [f, setF] = useState<ClientForm>({
    dir: "get", proto: "tftp", host: "", port: "", portTouched: false, path: "", cred: "", hash: "", name: "", destDir: "", src: "",
    accepted: "", maxMB: "", minutes: "", legacy: false, insecure: false,
  });
  const set = (o: Partial<ClientForm>) => setF((x) => ({ ...x, ...o }));
  const [paste, setPaste] = useState("");
  const [pasteMsg, setPasteMsg] = useState<"" | "invalid" | "password">("");
  const [advOpen, setAdvOpen] = useState(false);
  const [failed, setFailed] = useState(0); // envíos rechazados por validación: dispara el foco al primer campo inválido
  const formRef = useRef<HTMLDivElement>(null);
  const [creds, setCreds] = useState<Credential[]>([]);
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [pending, setPending] = useState<{ fp: string; changed: boolean } | null>(null);
  const [res, setRes] = useState<TransferResult | null>(null);
  useBusy(busy);
  const vv = useVaultVersion(); // la bóveda cambió: volver a listar credenciales
  useEffect(() => { core.listCredentials().then((l) => { setCreds(l ?? []); setF((x) => ((l ?? []).some((c) => c.id === x.cred) ? x : { ...x, cred: "" })); }).catch(() => setCreds([])); }, [core, vv]);

  useEffect(() => { if (failed) formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus(); }, [failed]);

  const ssh = usesSsh(f.proto);
  const errors = clientErrors(f);
  const shown = (k: keyof typeof errors) => (tried && errors[k] ? t(errors[k]!) : undefined);
  const url = buildURL(f);

  // La URL pegada se interpreta al pegar y al salir del campo, no en cada tecla. Con contraseña se borra y se avisa.
  const apply = (text: string): boolean => {
    const v = text.trim();
    const p = v ? parseClientURL(v, f.dir) : "";
    setPasteMsg(p === "password" ? "password" : p === null ? "invalid" : "");
    if (p === "password") setPaste("");
    else if (p) set({ proto: p.proto, host: p.host, port: p.port, portTouched: !!p.port, path: p.path });
    return p === "password";
  };
  const pasteErr = pasteMsg === "password" ? t("transfer.err.urlPassword") : pasteMsg === "invalid" ? t("transfer.paste.err") : undefined;

  const run = async (form: ClientForm) => {
    setTried(true);
    const bad = Object.keys(clientErrors(form));
    if (bad.length) {
      if (bad.some((k) => advancedKeys.includes(k))) setAdvOpen(true); // el error está en un panel plegado: se abre
      setFailed((n) => n + 1);
      return;
    }
    setErr(""); setPending(null); setRes(null); setBusy(true);
    try {
      setRes(await (form.dir === "get" ? core.transferGet(getParams(form)) : core.transferPut(putParams(form))));
    } catch (e) {
      const m = errorText(e);
      const hk = hostKeyFromError(m);
      if (hk) setPending(hk); else setErr(m);
    } finally {
      setBusy(false);
    }
  };
  // Aceptar es un acto explícito del usuario sobre esa huella; se reintenta con ella y queda en la bitácora del núcleo.
  const accept = () => {
    const next = { ...f, accepted: [f.accepted.trim(), pending!.fp].filter(Boolean).join(" ") };
    setF(next);
    void run(next);
  };
  const mismatch = /no coincide/.test(err);
  const protos = f.dir === "put" ? putProtos : clientProtos;
  const showFix = tried && Object.keys(errors).length > 0;
  return (
    <div ref={formRef}>
    <Section title={t("transfer.form.client")}>
      <div className="seg-row">
      <Segmented legend={t("transfer.dir")} value={f.dir} onChange={(dir) => set({ dir, ...(dir === "put" && !putProtos.includes(f.proto) ? { proto: "tftp" } : {}) })}
        options={[["get", t("transfer.dir.get")], ["put", t("transfer.dir.put")]]} />
      <Segmented legend={t("transfer.c.proto")} value={f.proto} onChange={(proto) => set({ proto })} options={protos.map((p) => [p, label(p)] as [ClientProto, string])} />
      </div>
      <div className="field-row">
        <Field label={t("transfer.c.host")} hint={t("transfer.c.host.hint")} error={shown("host")} value={f.host} onChange={(host) => set({ host })} w="lg" mono />
        <Field label={t("transfer.c.port")} hint={t("transfer.c.port.hint")} error={shown("port")} value={portOf(f)} onChange={(port) => set({ port, portTouched: true })} w="sm" mono />
      </div>
      <Field label={t("transfer.c.path")} hint={absPath(f.proto) ? t("transfer.c.path.hint.ssh") : t("transfer.c.path.hint")} error={shown("path")} value={f.path} onChange={(path) => set({ path })} w="full" mono />
      <div className="field" data-w="full">
        <label htmlFor={outId}>{t("transfer.url.out")}</label>
        <div className="path">
          <input id={outId} readOnly value={url} placeholder="—" spellCheck={false} />
          <CopyButton value={url} label={t("transfer.url.out")} />
        </div>
      </div>
      {usesCred(f.proto) && (
        <Select label={t("transfer.cred")} hint={ssh ? t("transfer.cred.need") : t("transfer.cred.anon")} error={shown("cred")} value={f.cred} onChange={(cred) => set({ cred })}
          options={[["", t("common.select")], ...creds.map((c) => [c.id, `${c.label} (${c.username})`] as [string, string])]} />
      )}
      {f.dir === "get" ? (
        <PathField label={t("transfer.destDir")} hint={t("transfer.destDir.hint")} value={f.destDir} onChange={(destDir) => set({ destDir })} pick={() => core.pickPath({ title: t("transfer.destDir"), directory: true })} />
      ) : (
        <PathField label={t("transfer.src")} error={shown("src")} value={f.src} onChange={(src) => set({ src })} pick={() => core.pickPath({ title: t("transfer.src") })} />
      )}
      <details className="adv" open={advOpen} onToggle={(e) => setAdvOpen(e.currentTarget.open)}>
        <summary>{t("transfer.adv")}</summary>
        <div onPaste={(e) => { if (apply(e.clipboardData.getData("text"))) e.preventDefault(); }} onBlur={(e) => apply((e.target as HTMLInputElement).value)}>
          <Field label={t("transfer.paste")} hint={t("transfer.paste.hint")} error={pasteErr} value={paste} onChange={setPaste} w="full" mono />
        </div>
        {f.dir === "get" && <Field label={t("transfer.c.name")} hint={t("transfer.c.name.hint")} value={f.name} onChange={(name) => set({ name })} w="lg" />}
        {f.dir === "get" && <Field label={t("transfer.hash")} hint={t("transfer.hash.hint")} error={shown("hash")} value={f.hash} onChange={(hash) => set({ hash })} w="full" mono />}
        <div className="field-row">
          <Field label={t("transfer.maxmb")} error={shown("maxMB")} value={f.maxMB} onChange={(maxMB) => set({ maxMB })} w="md" mono />
          <Field label={t("transfer.cminutes")} hint={t("transfer.cminutes.hint")} error={shown("minutes")} value={f.minutes} onChange={(minutes) => set({ minutes })} w="md" mono />
        </div>
        {ssh && <TextArea label={t("fps.accepted")} hint={t("transfer.accepted.hint")} value={f.accepted} onChange={(accepted) => set({ accepted })} rows={2} mono />}
        {ssh && <Check label={t("transfer.legacy")} checked={f.legacy} onChange={(legacy) => set({ legacy })} />}
        {f.dir === "get" && f.proto === "https" && <Check label={t("transfer.insecure")} checked={f.insecure} onChange={(insecure) => set({ insecure })} />}
        {f.dir === "get" && f.proto === "https" && f.insecure && <Notice kind="warn">{t("transfer.insecure.warn")}</Notice>}
      </details>
      <div className="actions"><button className="primary" disabled={busy} aria-busy={busy} onClick={() => run(f)}>{f.dir === "get" ? t("transfer.get") : t("transfer.put")}<kbd aria-hidden="true">Ctrl ↵</kbd></button></div>
      {showFix && <Notice kind="error">{t("transfer.err.fix")}</Notice>}
      {busy && <p role="status" className="meta">{t("transfer.working")}</p>}
      {err && <Notice kind="error">{mismatch ? <>{t("transfer.mismatch")} {err}</> : err}</Notice>}
      {pending && (
        <Notice kind="warn">
          <p>{pending.changed ? t("transfer.hostKey.changed") : t("transfer.hostKey.new")}</p>
          <p><code>{pending.fp}</code></p>
          <button type="button" onClick={accept}>{t("transfer.hostKey.accept")}</button>
        </Notice>
      )}
    </Section>
      {res && (
        <ResultPanel pad title={t("transfer.result")} status={{ tone: "ok", label: res.verified === "ok" ? t("transfer.verified") : t("transfer.done") }}>
          <Console label={t("transfer.result")} copy={core.copyText}
            text={[`${t("transfer.result.path")}: ${res.path}`, `${t("transfer.log.bytes")}: ${res.bytes}`, `MD5: ${res.md5}`, `SHA-256: ${res.sha256}`,
              `${t("transfer.result.verified")}: ${res.verified === "ok" ? t("transfer.log.ok") : t("transfer.result.none")}`].join("\n")} />
        </ResultPanel>
      )}
    </div>
  );
}
