import { useCallback, useEffect, useState } from "react";
import type { CoreAPI, PackDetail, PackInfo, PackInspectResult } from "../../lib/core";
import { Check, ConfirmButton, Notice, errorText } from "../../components/Field";
import { Dialog } from "../../components/Dialog";
import { useLang, useT } from "../../lib/i18n";
import "./packs.css";

// Todo texto del paquete (nombre, README, IDs) se dibuja como texto de React: sin HTML, imágenes ni enlaces (ADR 0010).
const libOf = (playbookId: string) => `lib-${playbookId.split("/").pop()}`;

// Un playbook oculto oculta su lib-<id>, salvo que el playbook esté tapado (entonces no filtra nada).
export function hiddenState(pack: PackInfo, playbookIds: string[]) {
  const hidden = new Set(pack.hidden);
  const viaPlaybook = new Set(playbookIds.filter((p) => hidden.has(p) && !pack.shadowed.includes(p)).map(libOf));
  return { hidden, viaPlaybook };
}

function Items({ pack, playbookIds, scriptIds, isHidden, onToggle, busy }: {
  pack: PackInfo; playbookIds: string[]; scriptIds: string[]; isHidden: (id: string) => boolean; onToggle: (id: string, visible: boolean) => void; busy?: boolean;
}) {
  const t = useT();
  const { viaPlaybook } = hiddenState(pack, playbookIds);
  return (
    <div className="pack-items">
      <h4>{t("packs.playbooks")}</h4>
      {playbookIds.map((id) => {
        const shadowed = pack.shadowed.includes(id);
        return <Check key={id} label={shadowed ? `${id} · ${t("packs.shadowedNote")}` : id} checked={shadowed || !isHidden(id)} disabled={busy || shadowed} onChange={(v) => onToggle(id, v)} />;
      })}
      <h4>{t("packs.scripts")}</h4>
      {scriptIds.map((id) => {
        const via = viaPlaybook.has(id);
        return <Check key={id} label={via ? `${id} · ${t("packs.viaPlaybook")}` : id} checked={!via && !isHidden(id)} disabled={busy || via} onChange={(v) => onToggle(id, v)} />;
      })}
    </div>
  );
}

function PackDetailDialog({ core, id, onChange, onClose }: { core: CoreAPI; id: string; onChange: (p: PackInfo) => void; onClose: () => void }) {
  const t = useT();
  const [d, setD] = useState<PackDetail | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => { core.packShow(id).then(setD, (e) => setErr(errorText(e))); }, [core, id]);
  const toggle = async (item: string, visible: boolean) => {
    setBusy(true); setErr("");
    try {
      const pack = await core.packSetItems(id, visible ? [] : [item], visible ? [item] : []);
      setD((x) => (x ? { ...x, pack } : x)); onChange(pack);
    } catch (e) { setErr(errorText(e)); } finally { setBusy(false); }
  };
  return (
    <Dialog title={t("packs.detail", { id })} onClose={onClose}>
      {err && <Notice kind="error">{err}</Notice>}
      {d && (
        <>
          <h4>{t("packs.readme")}</h4>
          <pre className="pack-readme">{d.readme}</pre>
          <Items pack={d.pack} playbookIds={d.playbookIds} scriptIds={d.scriptIds} isHidden={(x) => d.pack.hidden.includes(x)} onToggle={toggle} busy={busy} />
        </>
      )}
    </Dialog>
  );
}

function InstallDialog({ core, path, info, onDone, onClose }: { core: CoreAPI; path: string; info: PackInspectResult; onDone: () => void; onClose: () => void }) {
  const t = useT();
  const { pack, playbookIds, scriptIds } = info;
  const [hide, setHide] = useState(() => new Set(pack.hidden));
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const install = async () => {
    setBusy(true); setErr("");
    let ok = false;
    try {
      await core.packInstallHiding(path, !pack.official, [...playbookIds, ...scriptIds].filter((x) => hide.has(x)), true);
      ok = true;
    } catch (e) { setErr(errorText(e)); }
    try { onDone(); } finally { setBusy(false); }
    if (ok) onClose();
  };
  return (
    <Dialog title={t("packs.install.title")} onClose={onClose}>
      <p><code>{pack.id}</code> · {pack.version} · {pack.official ? t("packs.official") : t("packs.thirdParty")}</p>
      {info.replacedVersion && <p>{t("packs.replaces", { version: info.replacedVersion })}</p>}
      {!pack.official && <Notice kind="warn">{t("packs.unsigned")}</Notice>}
      <Items pack={pack} playbookIds={playbookIds} scriptIds={scriptIds} isHidden={(x) => hide.has(x)}
        onToggle={(id, visible) => setHide((s) => { const n = new Set(s); if (visible) n.delete(id); else n.add(id); return n; })} />
      {err && <Notice kind="error">{err}</Notice>}
      <div className="actions"><button type="button" className="primary" disabled={busy} onClick={install}>{t("packs.install.go")}</button></div>
    </Dialog>
  );
}

// Ajustes → Paquetes (fase 32): lista, detalle con casillas por elemento, instalar con vista previa y quitar.
export function PacksSection({ core }: { core: CoreAPI }) {
  const t = useT();
  const lang = useLang();
  const [packs, setPacks] = useState<PackInfo[] | null>(null);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [showing, setShowing] = useState("");
  const [preview, setPreview] = useState<{ path: string; info: PackInspectResult } | null>(null);

  const refresh = useCallback(() => core.packList().then(setPacks, (e) => setErr(errorText(e))), [core]);
  useEffect(() => { void refresh(); }, [refresh]);

  const pick = async () => {
    setErr(""); setMsg("");
    const path = await core.pickPath({ title: t("packs.pick"), filters: [{ name: "MACUAHUITL", pattern: "*.mpack" }] });
    if (!path) return;
    try { setPreview({ path, info: await core.packInspect(path, true) }); } catch (e) { setErr(errorText(e)); }
  };
  const remove = async (id: string) => {
    setErr(""); setMsg("");
    try { const n = await core.packRemove(id); if (n > 0) setMsg(t("packs.removedFavs", { n })); } catch (e) { setErr(errorText(e)); }
    void refresh();
  };
  const merge = (p: PackInfo) => setPacks((l) => l && l.map((x) => (x.id === p.id ? p : x)));

  return (
    <div className="packs">
      <div className="actions"><button type="button" onClick={pick}>{t("packs.install")}</button></div>
      {err && <Notice kind="error">{err}</Notice>}
      {msg && <Notice kind="info">{msg}</Notice>}
      {packs?.length === 0 && <p className="hint">{t("packs.empty")}</p>}
      <ul className="pack-list">
        {packs?.map((p) => (
          <li key={p.id} className="pack-card">
            <h4>{lang === "en" ? p.nameEn : p.name}</h4>
            <p>{lang === "en" ? p.descriptionEn : p.description}</p>
            <p className="hint"><code>{p.id}</code> · {p.version} · <span>{p.official ? t("packs.official") : t("packs.thirdParty")}</span></p>
            <p className="hint">{t("packs.counts", { playbooks: p.playbookCount, scripts: p.scriptCount, hidden: p.hidden.length })}</p>
            {p.shadowed.length > 0 && <Notice kind="warn">{t("packs.shadowed", { ids: p.shadowed.join(", ") })}</Notice>}
            <div className="actions">
              <button type="button" aria-label={`${t("packs.show")} · ${p.id}`} onClick={() => setShowing(p.id)}>{t("packs.show")}</button>
              <ConfirmButton label={`${t("packs.remove")} ${p.id}`} confirmLabel={`${t("packs.remove.confirm")} ${p.id}`} onConfirm={() => remove(p.id)}>{t("packs.remove")}</ConfirmButton>
            </div>
          </li>
        ))}
      </ul>
      {showing && <PackDetailDialog core={core} id={showing} onChange={merge} onClose={() => setShowing("")} />}
      {preview && <InstallDialog core={core} path={preview.path} info={preview.info} onDone={refresh} onClose={() => setPreview(null)} />}
    </div>
  );
}
