import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CoreAPI, Credential } from "../../lib/core";
import { ConfirmButton, Field, Notice, Select, TextArea, errorText } from "../../components/Field";
import { Badge, EmptyState, Page, Section } from "../../components/Page";
import { Icon } from "../../components/Icon";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { useVaultVersion } from "../../lib/vaultSignal";
import type { Host, KnownDevice } from "./api";
import { PLATFORMS, hasStartCommand, validFolderName, coreErrorField, hostPlatformOf, coreErrorKey, draftOf, groupByFolder, emptyForm, formOf, validateHost, type HostField, type HostForm } from "./hostForm";
import { hostsChanged, useHostsVersion } from "./signal";
import { addrPort } from "./HostPicker";
import "./hosts.css";

const platformName = (p: string) => PLATFORMS.find(([v]) => v === p)?.[1] ?? p;
const norm = (s: string) => s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();

// Libreta de hosts (fase 29b): los equipos que la persona agrega a mano. Los que la app descubrió solos salen aparte y de solo lectura,
// con una acción para pasarlos a la libreta. Una credencial es la referencia a la bóveda; nunca un secreto.
export function HostsView({ core }: { core: CoreAPI }) {
  const t = useT();
  const hv = useHostsVersion();
  const vv = useVaultVersion();
  const [hosts, setHosts] = useState<Host[] | null>(null);
  const [found, setFound] = useState<KnownDevice[]>([]);
  const [creds, setCreds] = useState<Credential[]>([]);
  const [vaultOpen, setVaultOpen] = useState(false); // la última lista de credenciales se pudo leer: la bóveda está abierta
  const [folderList, setFolderList] = useState<{ name: string; count: number }[]>([]);
  const [fedit, setFedit] = useState<{ old?: string; name: string; err: string } | null>(null); // alta o renombrado de carpeta
  const [moving, setMoving] = useState(""); // id del host cuyo «Mover a…» está abierto
  const [over, setOver] = useState<string | null>(null); // carpeta bajo el arrastre ("" = sin carpeta)
  const drag = useRef("");
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
    core.listHosts().then((l) => { if (live) setHosts(l); }, (e) => { if (live) { setHosts([]); setErr(errorText(e)); } });
    // Sin outputs/ o sin descubiertos la lista puede fallar o venir vacía: la libreta no depende de ella.
    core.listFolders().then((l) => { if (live) setFolderList(l); }, () => { if (live) setFolderList([]); });
    core.listDevices().then((l) => { if (live) setFound(l.devices.filter((d) => !d.sources.includes("manual") && d.address)); }, () => { if (live) setFound([]); });
    return () => { live = false; };
  }, [core, hv]);
  useEffect(() => {
    let live = true;
    core.listCredentials().then((l) => { if (live) { setCreds(l); setVaultOpen(true); } }, () => { if (live) { setCreds([]); setVaultOpen(false); } }); // bóveda cerrada: sin lista
    return () => { live = false; };
  }, [core, vv]);

  const folders = useMemo(() => [...new Set([...folderList.map((x) => x.name), ...(hosts ?? []).map((h) => h.folder).filter(Boolean)])].sort((a, b) => a.localeCompare(b)), [folderList, hosts]);
  const shown = useMemo(() => {
    const s = norm(q.trim());
    return (hosts ?? []).filter((h) => (!folder || h.folder === folder) && (!s || norm([h.name, h.address, h.folder, ...h.tags].join("\n")).includes(s)));
  }, [hosts, q, folder]);
  const groups = useMemo(() => {
    const g = new Map(groupByFolder(shown));
    // Sin búsqueda, las carpetas vacías y «Sin carpeta» salen también: son destinos para soltar un host.
    if (!q.trim()) for (const n of ["", ...folders]) if (!g.has(n) && (!folder || n === folder)) g.set(n, []);
    return [...g.entries()].sort(([a], [b]) => (a === "" ? 1 : b === "" ? -1 : a.localeCompare(b)));
  }, [shown, q, folder, folders]);

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
  const fromFound = (d: KnownDevice) => open(t("hosts.form.new"), { ...emptyForm, name: d.hostname, address: d.address, platform: hostPlatformOf(d.platform) }, undefined, "", true);
  const set = <K extends HostField>(k: K, v: HostForm[K]) => editing && setEditing({ ...editing, form: { ...editing.form, [k]: v } });

  const save = async () => {
    if (!editing) return;
    const v = validateHost(editing.form);
    setErrs(Object.fromEntries(Object.entries(v).map(([k, key]) => [k, t(key as Key)])));
    if (Object.keys(v).length) return;
    setBusy(true); setCoreDetail(""); setErr("");
    try {
      const r = await core.saveHost(draftOf(editing.form, editing.id));
      setWarns(r.warnings.filter((w, i, a) => a.indexOf(w) === i));
      setMsg(t("hosts.saved", { name: editing.form.name.trim() }));
      closeForm(true);
      hostsChanged();
    } catch (e) {
      const m = errorText(e);
      const f = coreErrorField(e);
      if (f) { setErrs({ [f]: t(coreErrorKey(e) || "hosts.coreField") }); setCoreDetail(m); } else setErr(m);
    } finally { setBusy(false); }
  };
  const del = async (h: Host) => {
    setErr(""); setMsg("");
    try { await core.deleteHost(h.id); setMsg(t("hosts.deleted", { name: h.name })); if (editing?.id === h.id) closeForm(); hostsChanged(); } catch (e) { setErr(errorText(e)); }
  };

  const moveTo = async (h: Host, to: string) => {
    setErr(""); setMsg(""); setMoving("");
    try { await core.moveHosts([h.id], to); setMsg(t("hosts.moved", { name: h.name, folder: to || t("hosts.folder.none") })); hostsChanged(); } catch (e) { setErr(errorText(e)); }
  };
  const dropOn = (to: string, dtId: string) => {
    setOver(null);
    const id = drag.current || dtId; // WebView2 y WebKitGTK exigen setData en dragstart; la referencia propia evita depender de getData
    drag.current = "";
    const h = (hosts ?? []).find((x) => x.id === id);
    if (h && h.folder !== to) void moveTo(h, to);
  };
  const saveFolder = async () => {
    if (!fedit) return;
    const name = fedit.name;
    if (!validFolderName(name)) { setFedit({ ...fedit, err: t("hosts.v.folder") }); return; }
    setErr(""); setMsg("");
    try {
      if (fedit.old === undefined) { await core.createFolder(name); setMsg(t("hosts.folder.created", { name })); }
      else { await core.renameFolder(fedit.old, name); if (folder === fedit.old) setFolder(name); setMsg(t("hosts.folder.renamed", { old: fedit.old, name })); }
      setFedit(null); hostsChanged();
    } catch (e) { setFedit({ ...fedit, err: errorText(e) }); }
  };
  const delFolder = async (name: string) => {
    setErr(""); setMsg("");
    try { await core.deleteFolder(name); if (folder === name) setFolder(""); setMsg(t("hosts.folder.deleted", { name })); hostsChanged(); } catch (e) { setErr(errorText(e)); }
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
          <Select label={t("hosts.f.platform")} value={f.platform} onChange={(v) => set("platform", v)} w="md" error={errs.platform} keepUnknown
            options={[["", t("hosts.platform.none")], ...PLATFORMS]} />
          <Select label={t("hosts.f.folder")} hint={t("hosts.f.folder.hint")} error={errs.folder} value={f.folder} onChange={(v) => set("folder", v)} w="md" keepUnknown
            options={[["", t("hosts.folder.none")], ...folders.map((x) => [x, x] as [string, string])]} />
          <Field label={t("hosts.f.tags")} hint={t("hosts.f.tags.hint")} error={errs.tags} value={f.tags} onChange={(v) => set("tags", v)} w="lg" mono />
        </div>
        <div className="field-row">
          <Select label={t("hosts.f.cred")} value={f.credentialId} onChange={(v) => set("credentialId", v)} w="lg" error={errs.credentialId}
            hint={!vaultOpen && editing.hiddenCred ? t("hosts.cred.vaultHint") : undefined} options={credOptions} />
        </div>
        {hasStartCommand(f.platform) && (
          <Field label={t("hosts.f.start")} hint={t("hosts.f.start.hint")} error={errs.startCommand} value={f.startCommand} onChange={(v) => set("startCommand", v)} w="full" mono />
        )}
        <TextArea label={t("hosts.f.notes")} value={f.notes} onChange={(v) => set("notes", v)} rows={3} error={errs.notes} />
        {coreDetail && <p className="hosts-core"><strong>{t("hosts.coreDetail")}:</strong> <span>{coreDetail}</span></p>}
        <div className="actions">
          <button type="submit" className="primary" disabled={busy} aria-busy={busy}>{t("hosts.save")}</button>
          <button type="button" onClick={() => closeForm()}>{t("hosts.cancel")}</button>
        </div>
      </form>
    </Section>
  );

  const row = (h: Host) => (
    <tr key={h.id} draggable
      onDragStart={(e) => { drag.current = h.id; e.dataTransfer.setData("text/plain", h.id); e.dataTransfer.effectAllowed = "move"; }}
      onDragEnd={() => { drag.current = ""; setOver(null); }}>
      <td>{h.name}</td>
      <td className="mono">{addrPort(h)}</td>
      <td>{h.platform ? <Badge>{platformName(h.platform)}</Badge> : <span className="hint">{t("hosts.platform.none")}</span>}</td>
      <td>{h.credentialLabel || creds.find((c) => c.id === h.credentialId)?.label || <span className="hint">{h.credentialId ? missing() : t("hosts.cred.none")}</span>}</td>
      <td>{h.tags.map((x) => <Badge key={x}>{x}</Badge>)}</td>
      <td className="hosts-actions">
        {moving === h.id ? (
          <MoveSelect label={t("hosts.move.select", { name: h.name })} value={h.folder} none={t("hosts.folder.none")} folders={folders} onPick={(v) => void moveTo(h, v)} onCancel={() => setMoving("")} />
        ) : <button type="button" className="quiet" aria-label={t("hosts.move.aria", { name: h.name })} onClick={() => setMoving(h.id)}>{t("hosts.move")}</button>}
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
          <button type="button" onClick={() => setFedit({ name: "", err: "" })}><Icon name="plus" />{t("hosts.folder.new")}</button>
        </div>
        {fedit && (
          <form className="hosts-folder-form" onSubmit={(e) => { e.preventDefault(); void saveFolder(); }} noValidate>
            <Field label={t("hosts.folder.name")} hint={t("hosts.f.folder.hint")} error={fedit.err} value={fedit.name} onChange={(v) => setFedit({ ...fedit, name: v, err: "" })} w="md" />
            <div className="actions">
              <button type="submit" className="primary">{t(fedit.old === undefined ? "hosts.folder.create" : "hosts.folder.rename")}</button>
              <button type="button" onClick={() => setFedit(null)}>{t("hosts.cancel")}</button>
            </div>
          </form>
        )}
        {hosts && hosts.length === 0 && folderList.length === 0 ? <EmptyState icon="list" title={t("hosts.empty.title")}>{t("hosts.empty.body")}</EmptyState>
          : hosts && shown.length === 0 ? <p className="hint">{t("hosts.noMatch")}</p>
          : (
            // shortcut: sin virtualizar; la libreta admite 5000 hosts y una tabla de ese tamaño aún se desplaza bien. Virtualizar si se nota lenta.
            <div className="hosts-table">
              <table aria-label={t("hosts.table")}>
                <thead><tr>
                  {(["name", "address", "platform", "cred", "tags", "actions"] as const).map((c) => <th key={c} scope="col">{t(`hosts.col.${c}`)}</th>)}
                </tr></thead>
                {groups.map(([name, list]) => (
                  <tbody key={name || "\0"} aria-label={name || t("hosts.folder.none")} className={over === name ? "hosts-over" : undefined}
                    onDragOver={(e) => { if (!drag.current) return; e.preventDefault(); e.dataTransfer.dropEffect = "move"; setOver(name); }}
                    onDragLeave={(e) => { if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setOver((o) => (o === name ? null : o)); }}
                    onDrop={(e) => { e.preventDefault(); dropOn(name, e.dataTransfer.getData("text/plain")); }}>
                    <tr className="hosts-folder">
                      <th scope="rowgroup" colSpan={4}>{`${name || t("hosts.folder.none")} (${list.length})`}</th>
                      <td colSpan={2} className="hosts-actions">
                        {name && <>
                          <button type="button" className="quiet" aria-label={t("hosts.folder.rename.aria", { name })} onClick={() => setFedit({ old: name, name, err: "" })}>{t("hosts.folder.rename")}</button>
                          <ConfirmButton label={t("hosts.folder.delete.aria", { name })} confirmLabel={list.length ? t("hosts.folder.delete.confirm", { n: folderList.find((x) => x.name === name)?.count ?? list.length }) : t("common.confirmDelete")} onConfirm={() => void delFolder(name)}>{t("hosts.delete")}</ConfirmButton>
                        </>}
                      </td>
                    </tr>
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

// «Mover a…» sin ratón: un select nativo (teclado y lectores de pantalla) que toma el foco al abrirse; Esc lo cierra.
function MoveSelect({ label, value, none, folders, onPick, onCancel }: { label: string; value: string; none: string; folders: string[]; onPick: (v: string) => void; onCancel: () => void }) {
  const ref = useCallback((el: HTMLSelectElement | null) => el?.focus(), []);
  return (
    <select ref={ref} aria-label={label} value={value} onChange={(e) => onPick(e.target.value)} onBlur={onCancel} onKeyDown={(e) => { if (e.key === "Escape") onCancel(); }}>
      <option value="">{none}</option>
      {folders.map((x) => <option key={x} value={x}>{x}</option>)}
    </select>
  );
}
