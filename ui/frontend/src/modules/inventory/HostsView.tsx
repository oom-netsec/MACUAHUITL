import { useEffect, useMemo, useRef, useState } from "react";
import type { CoreAPI, Credential } from "../../lib/core";
import { ConfirmButton, Field, Notice, Select, TextArea, errorText } from "../../components/Field";
import { Badge, EmptyState, Page, Section } from "../../components/Page";
import { Icon } from "../../components/Icon";
import { useLang, useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { useVaultVersion } from "../../lib/vaultSignal";
import type { Host, KnownDevice } from "./api";
import { PLATFORMS, coreErrorField, coreErrorKey, draftOf, groupByFolder, emptyForm, formOf, validateHost, type HostField, type HostForm } from "./hostForm";
import { useCoreText } from "./coreText";
import { hostsChanged, useHostsVersion } from "./signal";
import "./hosts.css";

const platformName = (p: string) => PLATFORMS.find(([v]) => v === p)?.[1] ?? p;
const norm = (s: string) => s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();

// Libreta de hosts (fase 29b): los equipos que la persona agrega a mano. Los que la app descubrió solos salen aparte y de solo lectura,
// con una acción para pasarlos a la libreta. Una credencial es la referencia a la bóveda; nunca un secreto.
export function HostsView({ core }: { core: CoreAPI }) {
  const t = useT();
  const lang = useLang();
  const ct = useCoreText();
  const hv = useHostsVersion();
  const vv = useVaultVersion();
  const [hosts, setHosts] = useState<Host[] | null>(null);
  const [found, setFound] = useState<KnownDevice[]>([]);
  const [creds, setCreds] = useState<Credential[]>([]);
  const [vaultOpen, setVaultOpen] = useState(false); // la última lista de credenciales se pudo leer: la bóveda está abierta
  const [q, setQ] = useState("");
  const [folder, setFolder] = useState("");
  const [editing, setEditing] = useState<{ id?: string; title: string; form: HostForm; hiddenCred?: string } | null>(null);
  const [errs, setErrs] = useState<Partial<Record<HostField, string>>>({});
  const [coreDetail, setCoreDetail] = useState("");
  const [warns, setWarns] = useState<string[]>([]);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    core.listHosts().then((l) => { if (live) setHosts(l); }, (e) => { if (live) { setHosts([]); setErr(ct(errorText(e), "hosts.coreError")); } });
    // Sin outputs/ o sin descubiertos la lista puede fallar o venir vacía: la libreta no depende de ella.
    core.listDevices().then((l) => { if (live) setFound(l.devices.filter((d) => !d.sources.includes("manual") && d.address)); }, () => { if (live) setFound([]); });
    return () => { live = false; };
  }, [core, hv]);
  useEffect(() => {
    let live = true;
    core.listCredentials().then((l) => { if (live) { setCreds(l); setVaultOpen(true); } }, () => { if (live) { setCreds([]); setVaultOpen(false); } }); // bóveda cerrada: sin lista
    return () => { live = false; };
  }, [core, vv]);

  const folders = useMemo(() => [...new Set((hosts ?? []).map((h) => h.folder).filter(Boolean))].sort((a, b) => a.localeCompare(b)), [hosts]);
  const shown = useMemo(() => {
    const s = norm(q.trim());
    return (hosts ?? []).filter((h) => (!folder || h.folder === folder) && (!s || norm([h.name, h.address, h.folder, ...h.tags].join("\n")).includes(s)));
  }, [hosts, q, folder]);
  const groups = useMemo(() => groupByFolder(shown), [shown]);

  // Foco: al abrir el formulario va a su primer campo (y se trae a la vista); al cerrarlo vuelve al botón de origen.
  const formRef = useRef<HTMLFormElement>(null);
  const newBtn = useRef<HTMLButtonElement>(null);
  const origin = useRef<{ el: HTMLElement | null; found: boolean }>({ el: null, found: false });
  const [seq, setSeq] = useState({ open: 0, close: 0, saved: false });
  useEffect(() => {
    if (seq.open === 0) return;
    formRef.current?.querySelector<HTMLElement>("input")?.focus();
    formRef.current?.scrollIntoView?.({ block: "nearest" });
  }, [seq.open]);
  useEffect(() => {
    if (seq.close === 0) return;
    const o = origin.current;
    // Una fila descubierta desaparece de su tabla al guardarse: el foco va al botón «Nuevo host».
    (o.el?.isConnected && !(o.found && seq.saved) ? o.el : newBtn.current)?.focus();
  }, [seq.close, seq.saved]);
  const closeForm = (saved = false) => { setEditing(null); setSeq((q) => ({ ...q, close: q.close + 1, saved })); };

  const open = (title: string, form: HostForm, id?: string, hiddenCred = "", found = false) => { origin.current = { el: document.activeElement as HTMLElement | null, found }; setSeq((q) => ({ ...q, open: q.open + 1 })); setEditing({ id, title, form, hiddenCred }); setErrs({}); setCoreDetail(""); setMsg(""); setErr(""); setWarns([]); };
  const edit = (h: Host) => open(t("hosts.form.edit", { name: h.name }), formOf(h), h.id, h.credentialId);
  const fromFound = (d: KnownDevice) => open(t("hosts.form.new"), { ...emptyForm, name: d.hostname, address: d.address, platform: PLATFORMS.some(([v]) => v === d.platform) ? (d.platform as HostForm["platform"]) : "" }, undefined, "", true);
  const set = <K extends HostField>(k: K, v: HostForm[K]) => editing && setEditing({ ...editing, form: { ...editing.form, [k]: v } });

  const save = async () => {
    if (!editing) return;
    const v = validateHost(editing.form);
    setErrs(Object.fromEntries(Object.entries(v).map(([k, key]) => [k, t(key as Key)])));
    if (Object.keys(v).length) return;
    setBusy(true); setCoreDetail(""); setErr("");
    try {
      const r = await core.saveHost(draftOf(editing.form, editing.id));
      setWarns(r.warnings.map((w) => ct(w, "hosts.coreWarn")).filter((w, i, a) => a.indexOf(w) === i));
      setMsg(t("hosts.saved", { name: editing.form.name.trim() }));
      closeForm(true);
      hostsChanged();
    } catch (e) {
      const m = errorText(e);
      const f = coreErrorField(m);
      if (f) { setErrs({ [f]: t(coreErrorKey(m) || "hosts.coreField") }); setCoreDetail(m); } else setErr(ct(m, "hosts.coreError"));
    } finally { setBusy(false); }
  };
  const del = async (h: Host) => {
    setErr(""); setMsg("");
    try { await core.deleteHost(h.id); setMsg(t("hosts.deleted", { name: h.name })); if (editing?.id === h.id) closeForm(); hostsChanged(); } catch (e) { setErr(ct(errorText(e), "hosts.coreError")); }
  };

  const f = editing?.form;
  // Con la bóveda cerrada la credencial guardada no está en la lista: se conserva como opción para no perderla al guardar.
  const credOptions: [string, string][] = [["", t("hosts.cred.none")], ...creds.map((c) => [c.id, `${c.label} (${c.username})`] as [string, string])];
  const missing = () => t(vaultOpen ? "hosts.cred.gone" : "hosts.cred.hidden"); // abierta y sin esa credencial = borrada; cerrada = solo no se puede ver
  if (f && f.credentialId && !creds.some((c) => c.id === f.credentialId)) credOptions.push([f.credentialId, missing()]);

  const form = editing && f && (
    <Section title={editing.title}>
      <form ref={formRef} onSubmit={(e) => { e.preventDefault(); void save(); }} noValidate>
        <div className="field-row">
          <Field label={t("hosts.f.name")} hint={t("hosts.f.name.hint")} error={errs.name} value={f.name} onChange={(v) => set("name", v)} w="md" required />
          <Field label={t("hosts.f.address")} hint={t("hosts.f.address.hint")} error={errs.address} value={f.address} onChange={(v) => set("address", v)} w="lg" mono required />
          <Field label={t("hosts.f.port")} error={errs.port} value={f.port} onChange={(v) => set("port", v)} w="xs" mono inputMode="numeric" />
        </div>
        <div className="field-row">
          <Select label={t("hosts.f.platform")} value={f.platform} onChange={(v) => set("platform", v)} w="md" error={errs.platform}
            options={[["", t("hosts.platform.none")], ...PLATFORMS]} />
          <Field label={t("hosts.f.folder")} hint={t("hosts.f.folder.hint")} error={errs.folder} value={f.folder} onChange={(v) => set("folder", v)} w="md" />
          <Field label={t("hosts.f.tags")} hint={t("hosts.f.tags.hint")} error={errs.tags} value={f.tags} onChange={(v) => set("tags", v)} w="lg" mono />
        </div>
        <div className="field-row">
          <Select label={t("hosts.f.cred")} value={f.credentialId} onChange={(v) => set("credentialId", v)} w="lg" error={errs.credentialId}
            hint={!vaultOpen && editing.hiddenCred ? t("hosts.cred.vaultHint") : undefined} options={credOptions} />
        </div>
        <TextArea label={t("hosts.f.notes")} value={f.notes} onChange={(v) => set("notes", v)} rows={3} error={errs.notes} />
        {coreDetail && lang === "es" && <p className="hosts-core"><strong>{t("hosts.coreDetail")}:</strong> <span>{coreDetail}</span></p>}
        <div className="actions">
          <button type="submit" className="primary" disabled={busy} aria-busy={busy}>{t("hosts.save")}</button>
          <button type="button" onClick={() => closeForm()}>{t("hosts.cancel")}</button>
        </div>
      </form>
    </Section>
  );

  const row = (h: Host) => (
    <tr key={h.id}>
      <td>{h.name}</td>
      <td className="mono">{h.address}:{h.port}</td>
      <td>{h.platform ? <Badge>{platformName(h.platform)}</Badge> : <span className="hint">{t("hosts.platform.none")}</span>}</td>
      <td>{h.credentialLabel || creds.find((c) => c.id === h.credentialId)?.label || <span className="hint">{h.credentialId ? missing() : t("hosts.cred.none")}</span>}</td>
      <td>{h.tags.map((x) => <Badge key={x}>{x}</Badge>)}</td>
      <td className="hosts-actions">
        <button type="button" className="quiet" aria-label={t("hosts.edit.aria", { name: h.name })} onClick={() => edit(h)}>{t("hosts.edit")}</button>
        <ConfirmButton label={t("hosts.delete.aria", { name: h.name })} confirmLabel={t("common.confirmDelete")} onConfirm={() => void del(h)}>{t("hosts.delete")}</ConfirmButton>
      </td>
    </tr>
  );

  return (
    <Page title={t("hosts.title")} description={t("hosts.desc")}
      actions={<button type="button" className="primary" ref={newBtn} onClick={() => open(t("hosts.form.new"), emptyForm)}><Icon name="plus" />{t("hosts.new")}</button>}>
      {msg && <Notice kind="ok">{msg}</Notice>}
      {warns.length > 0 && <Notice kind="warn">{warns.join(" ")}</Notice>}
      {err && <Notice kind="error">{err}</Notice>}
      {form}
      <Section title={t("hosts.table")}>
        <div className="field-row hosts-filters">
          <Field label={t("hosts.search")} value={q} onChange={setQ} w="lg" />
          <Select label={t("hosts.folder.filter")} value={folder} onChange={setFolder} w="md" options={[["", t("hosts.folder.all")], ...folders.map((x) => [x, x] as [string, string])]} />
        </div>
        {hosts && hosts.length === 0 ? <EmptyState icon="list" title={t("hosts.empty.title")}>{t("hosts.empty.body")}</EmptyState>
          : hosts && shown.length === 0 ? <p className="hint">{t("hosts.noMatch")}</p>
          : (
            // shortcut: sin virtualizar; la libreta admite 5000 hosts y una tabla de ese tamaño aún se desplaza bien. Virtualizar si se nota lenta.
            <div className="hosts-table">
              <table aria-label={t("hosts.table")}>
                <thead><tr>
                  {(["name", "address", "platform", "cred", "tags", "actions"] as const).map((c) => <th key={c} scope="col">{t(`hosts.col.${c}`)}</th>)}
                </tr></thead>
                {groups.map(([name, list]) => (
                  <tbody key={name || "\0"}>
                    <tr className="hosts-folder"><th scope="rowgroup" colSpan={6}>{name || t("hosts.folder.none")} <span className="hint">({list.length})</span></th></tr>
                    {list.map(row)}
                  </tbody>
                ))}
              </table>
            </div>
          )}
      </Section>
      {found.length > 0 && (
        <Section title={t("hosts.discovered.title")} description={t("hosts.discovered.desc")}>
          <div className="hosts-table">
            <table aria-label={t("hosts.discovered.table")}>
              <thead><tr>
                <th scope="col">{t("hosts.col.name")}</th><th scope="col">{t("hosts.col.address")}</th><th scope="col">{t("hosts.col.platform")}</th>
                <th scope="col">{t("hosts.discovered.sources")}</th><th scope="col">{t("hosts.col.actions")}</th>
              </tr></thead>
              <tbody>
                {found.map((d) => (
                  <tr key={d.id}>
                    <td>{d.hostname || "—"}</td>
                    <td className="mono">{d.address}</td>
                    <td>{d.platform ? <Badge>{platformName(d.platform)}</Badge> : null}</td>
                    <td>{d.sources.map((s) => <Badge key={s}>{t(`hosts.src.${s as "patrol" | "flota" | "respaldos"}`)}</Badge>)}</td>
                    <td className="hosts-actions"><button type="button" aria-label={t("hosts.discovered.save.aria", { name: d.hostname || d.address })} className="quiet" onClick={() => fromFound(d)}>{t("hosts.discovered.save")}</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      )}
    </Page>
  );
}
