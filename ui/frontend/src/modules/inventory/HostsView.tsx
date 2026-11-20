import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { ConfirmButton, Field, Notice, Select, TextArea, errorText } from "../../components/Field";
import { Badge, EmptyState, Page, Section } from "../../components/Page";
import { Icon } from "../../components/Icon";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { Advanced } from "../../components/Advanced";
import { CredentialSelect, useCredentials } from "../../components/CredentialSelect";
import type { Host, KnownDevice } from "./api";
import { PLATFORMS, hasStartCommand, validFolderName, coreErrorField, folderNotEmpty, hostPlatformOf, coreErrorKey, draftOf, groupByFolder, emptyForm, formOf, validateHost, withProtocol, defaultPort, type HostField, type HostForm } from "./hostForm";
import { hostsChanged, useHostsVersion } from "./signal";
import { addrPort } from "../../lib/targets";
import "./hosts.css";

const platformName = (p: string) => PLATFORMS.find(([v]) => v === p)?.[1] ?? p;
const norm = (s: string) => s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();

// Libreta de hosts (fase 29b): los equipos que la persona agrega a mano. Los que la app descubrió solos salen aparte y de solo lectura,
// con una acción para pasarlos a la libreta. Una credencial es la referencia a la bóveda; nunca un secreto.
export function HostsView({ core }: { core: CoreAPI }) {
  const t = useT();
  const hv = useHostsVersion();
  const [hosts, setHosts] = useState<Host[] | null>(null);
  const [found, setFound] = useState<KnownDevice[]>([]);
  const { creds, vault } = useCredentials(core, { keys: true });
  const vaultOpen = vault === "open"; // la última lista de credenciales se pudo leer
  const [folderList, setFolderList] = useState<{ name: string; count: number }[]>([]);
  const [fedit, setFedit] = useState<{ old?: string; name: string; err: string } | null>(null); // alta o renombrado de carpeta
  const [stale, setStale] = useState<{ name: string; n: string } | null>(null); // borrado de carpeta que el núcleo exige reconfirmar
  const [moving, setMoving] = useState(""); // id del host cuyo «Mover a…» está abierto
  const [over, setOver] = useState<string | null>(null); // carpeta bajo el arrastre ("" = sin carpeta)
  const drag = useRef("");
  // Foco de «Mover a…»: al cerrar vuelve al botón de ese host (por id: tras recargar es otro nodo). wait = esperar a que la lista recargue.
  const focusMove = useRef<{ id: string; wait: boolean; hosts: Host[] | null } | null>(null);
  const [fseq, setFseq] = useState(0);
  // Foco del formulario de carpeta: al abrir va al campo; al cerrar, al botón de origen (patrón seq/origin del formulario de host).
  const folderForm = useRef<HTMLFormElement>(null);
  const newFolderBtn = useRef<HTMLButtonElement>(null);
  const forigin = useRef<HTMLElement | null>(null);
  const [fs, setFs] = useState({ open: 0, close: 0, target: "" });
  const [q, setQ] = useState("");
  const [folder, setFolder] = useState("");
  const [editing, setEditing] = useState<{ id?: string; title: string; form: HostForm; base: HostForm; hiddenCred?: string } | null>(null); // base: lo guardado, para «cambiadas»
  const [advTry, setAdvTry] = useState(0); // intentos fallidos con error dentro de Avanzado: cada uno lo vuelve a abrir
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

  const open = (title: string, form: HostForm, id?: string, hiddenCred = "", found = false) => { origin.current = { el: document.activeElement as HTMLElement | null, found }; setSeq((q) => ({ ...q, open: q.open + 1 })); setEditing({ id, title, form, base: form, hiddenCred }); setErrs({}); setAdvTry(0); setCoreDetail(""); setMsg(""); setErr(""); setWarns([]); };
  const edit = (h: Host) => open(t("hosts.form.edit", { name: h.name }), formOf(h), h.id, h.credentialId);
  const fromFound = (d: KnownDevice) => open(t("hosts.form.new"), { ...emptyForm, name: d.hostname, address: d.address, platform: hostPlatformOf(d.platform) }, undefined, "", true);
  const set = <K extends HostField>(k: K, v: HostForm[K]) => editing && setEditing({ ...editing, form: { ...editing.form, [k]: v } });

  const save = async () => {
    if (!editing) return;
    const v = validateHost(editing.form);
    setErrs(Object.fromEntries(Object.entries(v).map(([k, key]) => [k, t(key as Key)])));
    if (v.port || v.tags || v.notes) setAdvTry((n) => n + 1);
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
      if (f) { setErrs({ [f]: t(coreErrorKey(e) || "hosts.coreField") }); setCoreDetail(m); if (f === "port" || f === "tags" || f === "notes") setAdvTry((n) => n + 1); } else setErr(m);
    } finally { setBusy(false); }
  };
  const del = async (h: Host) => {
    setErr(""); setMsg("");
    try { await core.deleteHost(h.id); setMsg(t("hosts.deleted", { name: h.name })); if (editing?.id === h.id) closeForm(); hostsChanged(); } catch (e) { setErr(errorText(e)); }
  };

  useEffect(() => {
    const m = focusMove.current;
    if (!m || moving || (m.wait && m.hosts === hosts)) return;
    focusMove.current = null;
    document.querySelector<HTMLElement>(`[data-move-id="${m.id}"]`)?.focus();
  }, [moving, hosts, fseq]);
  useEffect(() => { if (fs.open) folderForm.current?.querySelector<HTMLElement>("input")?.focus(); }, [fs.open]);
  const fwait = useRef<Host[] | null | undefined>(undefined); // hosts al guardar: se espera a que la lista recargue (el grupo renombrado es otro nodo)
  useEffect(() => {
    if (!fs.close || (fwait.current !== undefined && fwait.current === hosts)) return;
    fwait.current = undefined;
    const o = forigin.current;
    const el = o?.isConnected ? o : fs.target ? document.querySelector<HTMLElement>(`[data-rename-folder="${CSS.escape(fs.target)}"]`) : null; // el grupo renombrado es otro nodo
    (el ?? newFolderBtn.current)?.focus();
  }, [fs.close, fs.target, hosts]);
  const openFolder = (v: { old?: string; name: string }) => { forigin.current = document.activeElement as HTMLElement | null; setFedit({ ...v, err: "" }); setFs((x) => ({ ...x, open: x.open + 1 })); };
  const closeFolder = (target = "", wait = false) => { fwait.current = wait ? hosts : undefined; setFedit(null); setFs((x) => ({ ...x, close: x.close + 1, target })); };
  const closeMove = (id: string, wait = false) => { focusMove.current = { id, wait, hosts }; setMoving(""); setFseq((n) => n + 1); };
  const moveTo = async (h: Host, to: string) => {
    setErr(""); setMsg(""); closeMove(h.id, true);
    try { await core.moveHosts([h.id], to); setMsg(t("hosts.moved", { name: h.name, folder: to || t("hosts.folder.none") })); hostsChanged(); } catch (e) { setErr(errorText(e)); closeMove(h.id); }
  };
  const dropOn = (to: string) => {
    setOver(null);
    const id = drag.current; // solo lo que arrancó en un asa de esta vista; un id en text/plain sin dragstart no cuenta
    drag.current = "";
    const h = (hosts ?? []).find((x) => x.id === id);
    if (h && h.folder !== to) void moveTo(h, to);
  };
  const saveFolder = async () => {
    if (!fedit) return;
    const name = fedit.name;
    if (!validFolderName(name)) { setFedit({ ...fedit, err: t("hosts.v.folder") }); return; }
    if (fedit.old === name) { closeFolder(name); return; } // mismo nombre: nada que decirle al núcleo
    setErr(""); setMsg("");
    try {
      if (fedit.old === undefined) { await core.createFolder(name); setMsg(t("hosts.folder.created", { name })); }
      else { await core.renameFolder(fedit.old, name); if (folder === fedit.old) setFolder(name); setMsg(t("hosts.folder.renamed", { old: fedit.old, name })); }
      closeFolder(name, true); hostsChanged();
    } catch (e) { setFedit((cur) => (cur ? { ...cur, err: errorText(e) } : cur)); } // sin pisar lo que se tecleó mientras esperaba
  };
  // known = hosts que la persona vio al confirmar: con 0 no hay nada que confirmar y va confirm=false; si el núcleo dice que sí hay (cuenta
  // desactualizada) se pide otra confirmación con SU cuenta y solo entonces se reintenta con confirm=true.
  const delFolder = async (name: string, known: number, confirm = known > 0) => {
    setErr(""); setMsg(""); setStale(null);
    try { await core.deleteFolder(name, confirm); if (folder === name) setFolder(""); setMsg(t("hosts.folder.deleted", { name })); hostsChanged(); }
    catch (e) { const ne = !confirm && folderNotEmpty(e); if (ne) setStale({ name, n: ne.n }); else setErr(errorText(e)); }
  };
  const f = editing?.form;
  // Con la bóveda cerrada la credencial guardada no está en la lista: se conserva como opción para no perderla al guardar.
  const credList = creds.filter((c) => c.kind !== "key" || (f?.protocol !== "telnet" && hasStartCommand(f?.platform ?? "")) || c.id === f?.credentialId);
  const missing = () => t(vaultOpen ? "hosts.cred.gone" : "hosts.cred.hidden"); // abierta y sin esa credencial = borrada; cerrada = solo no se puede ver
  const credExtra: [string, string] | undefined = f && f.credentialId && !creds.some((c) => c.id === f.credentialId) ? [f.credentialId, missing()] : undefined;

  const form = editing && f && (
    <Section title={editing.title}>
      <form ref={formRef} onSubmit={(e) => { e.preventDefault(); void save(); }} noValidate>
        <div className="field-row">
          <Field label={t("hosts.f.name")} hint={t("hosts.f.name.hint")} error={errs.name} value={f.name} onChange={(v) => set("name", v)} w="md" required />
          <Field label={t("hosts.f.address")} hint={t("hosts.f.address.hint")} error={errs.address} value={f.address} onChange={(v) => set("address", v)} w="lg" mono required />
        </div>
        <div className="field-row">
          <Select label={t("hosts.f.platform")} value={f.platform} onChange={(v) => set("platform", v)} w="md" error={errs.platform} keepUnknown
            options={[["", t("hosts.platform.none")], ...PLATFORMS]} />
          <Select label={t("hosts.f.folder")} hint={t("hosts.f.folder.hint")} error={errs.folder} value={f.folder} onChange={(v) => set("folder", v)} w="md" keepUnknown
            options={[["", t("hosts.folder.none")], ...folders.map((x) => [x, x] as [string, string])]} />
        </div>
        <div className="field-row">
          <Select label={t("hosts.f.protocol")} hint={t("hosts.f.protocol.hint")} error={errs.protocol} value={f.protocol} w="sm"
            onChange={(v) => { const n = withProtocol(f, v); setEditing({ ...editing, form: v === "telnet" && creds.some((c) => c.kind === "key" && c.id === n.credentialId) ? { ...n, credentialId: "" } : n }); }}
            options={[["ssh", "SSH"], ["telnet", "Telnet"]]} />
          <CredentialSelect creds={credList} vault={vault} notice={!editing.hiddenCred} value={f.credentialId} onChange={(v) => set("credentialId", v)} w="lg" error={errs.credentialId}
            hint={!vaultOpen && editing.hiddenCred ? t("hosts.cred.vaultHint") : undefined} optional extra={credExtra} />
        </div>
        {f.protocol !== "telnet" && hasStartCommand(f.platform) && (
          <Field label={t("hosts.f.start")} hint={t("hosts.f.start.hint")} error={errs.startCommand} value={f.startCommand} onChange={(v) => set("startCommand", v)} w="full" mono />
        )}
        {f.protocol !== "telnet" && hasStartCommand(f.platform) && <Notice kind="info">{t("hosts.f.start.audit")}</Notice>}
        {(f.protocol === "telnet" || !hasStartCommand(f.platform)) && creds.some((c) => c.kind === "key") && <p className="hint">{t("hosts.cred.keyOnlyGeneric")}</p>}
        <Advanced forceOpen={advTry} changed={Number((f.port || String(defaultPort(f.protocol))) !== (editing.base.port || String(defaultPort(editing.base.protocol)))) + Number(f.tags !== editing.base.tags) + Number(f.notes !== editing.base.notes)}>
          <div className="field-row">
            <Field label={t("hosts.f.port")} placeholder={String(defaultPort(f.protocol))} hint={t("hosts.f.port.hint", { port: String(defaultPort(f.protocol)) })} error={errs.port} value={f.port} onChange={(v) => set("port", v)} w="xs" mono inputMode="numeric" />
            <Field label={t("hosts.f.tags")} hint={t("hosts.f.tags.hint")} error={errs.tags} value={f.tags} onChange={(v) => set("tags", v)} w="lg" mono />
          </div>
          <TextArea label={t("hosts.f.notes")} value={f.notes} onChange={(v) => set("notes", v)} rows={3} error={errs.notes} />
        </Advanced>
        {coreDetail && <p className="hosts-core"><strong>{t("hosts.coreDetail")}:</strong> <span>{coreDetail}</span></p>}
        <div className="actions">
          <button type="submit" className="primary" disabled={busy} aria-busy={busy}>{t("hosts.save")}</button>
          <button type="button" onClick={() => closeForm()}>{t("hosts.cancel")}</button>
        </div>
      </form>
    </Section>
  );

  const row = (h: Host) => (
    <tr key={h.id}>
      <td>
        {/* Solo el asa arrastra: así el nombre y la IP de la fila se pueden seleccionar y copiar. Pulsarla abre «Mover a…». */}
        <button type="button" draggable className="quiet icon sm hosts-grip" aria-label={t("hosts.drag.aria", { name: h.name })} onClick={() => setMoving(h.id)}
          onDragStart={(e) => { drag.current = h.id; e.dataTransfer.setData("text/plain", h.id); e.dataTransfer.effectAllowed = "move"; const tr = e.currentTarget.closest("tr"); if (tr) e.dataTransfer.setDragImage?.(tr, 0, 0); }}
          onDragEnd={() => { drag.current = ""; setOver(null); }}>⠿</button>
        {h.name}
        {h.protocol === "telnet" && <span className="badge hosts-start" title={t("hosts.telnet.title")}>Telnet</span>}
        {h.startCommand && <span className="badge hosts-start" title={h.startCommand} aria-label={t("hosts.start.aria", { cmd: h.startCommand })}>{t("hosts.start.badge")}</span>}
      </td>
      <td className="mono">{addrPort(h)}</td>
      <td>{h.platform ? <Badge>{platformName(h.platform)}</Badge> : <span className="hint">{t("hosts.platform.none")}</span>}</td>
      <td>{h.credentialLabel || creds.find((c) => c.id === h.credentialId)?.label || <span className="hint">{h.credentialId ? missing() : t("hosts.cred.none")}</span>}</td>
      <td>{h.tags.map((x) => <Badge key={x}>{x}</Badge>)}</td>
      <td className="hosts-actions">
        {moving === h.id ? (
          <MovePanel label={t("hosts.move.select", { name: h.name })} current={h.folder} none={t("hosts.folder.none")} cancel={t("hosts.cancel")} folders={folders} onPick={(v) => void moveTo(h, v)} onCancel={() => closeMove(h.id)} />
        ) : <button type="button" className="quiet" data-move-id={h.id} aria-label={t("hosts.move.aria", { name: h.name })} onClick={() => setMoving(h.id)}>{t("hosts.move")}</button>}
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
      {stale && (
        <Notice kind="warn">
          <p>{t(stale.n ? "hosts.folder.stale" : "hosts.folder.stale.unknown", { name: stale.name, n: stale.n })}</p>
          <button type="button" className="danger" onClick={() => void delFolder(stale.name, 0, true)}>{t("hosts.folder.stale.confirm")}</button>
          <button type="button" onClick={() => setStale(null)}>{t("hosts.cancel")}</button>
        </Notice>
      )}
      {form}
      <Section title={t("hosts.table")}>
        <div className="field-row hosts-filters">
          <Field label={t("hosts.search")} value={q} onChange={setQ} w="lg" />
          <Select label={t("hosts.folder.filter")} value={folder} onChange={setFolder} w="md" options={[["", t("hosts.folder.all")], ...folders.map((x) => [x, x] as [string, string])]} />
          <button type="button" ref={newFolderBtn} onClick={() => openFolder({ name: "" })}><Icon name="plus" />{t("hosts.folder.new")}</button>
        </div>
        {fedit && (
          <form ref={folderForm} className="hosts-folder-form" onSubmit={(e) => { e.preventDefault(); void saveFolder(); }} noValidate>
            <Field label={t("hosts.folder.name")} hint={t("hosts.f.folder.hint")} error={fedit.err} value={fedit.name} onChange={(v) => setFedit({ ...fedit, name: v, err: "" })} w="md" />
            <div className="actions">
              <button type="submit" className="primary">{t(fedit.old === undefined ? "hosts.folder.create" : "hosts.folder.rename")}</button>
              <button type="button" onClick={() => closeFolder(fedit.old ?? "")}>{t("hosts.cancel")}</button>
            </div>
          </form>
        )}
        {hosts && hosts.length === 0 && folderList.length === 0 ? <EmptyState icon="list" title={t("hosts.empty.title")}>{t("hosts.empty.body")}</EmptyState>
          : hosts && shown.length === 0 && groups.length === 0 ? <p className="hint">{t("hosts.noMatch")}</p>
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
                    onDrop={(e) => { e.preventDefault(); dropOn(name); }}>
                    <tr className="hosts-folder">
                      <th scope="rowgroup" colSpan={4}>{`${name || t("hosts.folder.none")} (${list.length})`}</th>
                      <td colSpan={2} className="hosts-actions">
                        {name && <>
                          <button type="button" className="quiet" aria-label={t("hosts.folder.rename.aria", { name })} data-rename-folder={name} onClick={() => openFolder({ old: name, name })}>{t("hosts.folder.rename")}</button>
                          <ConfirmButton label={t("hosts.folder.delete.aria", { name })} confirmLabel={list.length ? t("hosts.folder.delete.confirm", { n: folderList.find((x) => x.name === name)?.count ?? list.length }) : t("common.confirmDelete")} onConfirm={() => void delFolder(name, folderList.find((x) => x.name === name)?.count ?? list.length)}>{t("hosts.delete")}</ConfirmButton>
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

// «Mover a…» sin ratón: un grupo de botones (uno por carpeta y «Sin carpeta»); ninguna flecha ni cambio de foco mueve nada, solo pulsar.
// (Un select actuaría en «change»: en WebKitGTK y WebView2 la flecha con el select cerrado ya lo dispara.) Esc cancela.
function MovePanel({ label, current, none, cancel, folders, onPick, onCancel }: { label: string; current: string; none: string; cancel: string; folders: string[]; onPick: (v: string) => void; onCancel: () => void }) {
  const ref = useCallback((el: HTMLDivElement | null) => el?.querySelector<HTMLElement>("button")?.focus(), []);
  return (
    <div ref={ref} role="group" aria-label={label} className="hosts-move" onKeyDown={(e) => { if (e.key === "Escape") { e.preventDefault(); onCancel(); } }}>
      {[["", none] as [string, string], ...folders.map((x) => [x, x] as [string, string])].filter(([v]) => v !== current).map(([v, n]) => (
        <button key={v} type="button" className="quiet" onClick={() => onPick(v)}>{n}</button>
      ))}
      <button type="button" onClick={onCancel}>{cancel}</button>
    </div>
  );
}
