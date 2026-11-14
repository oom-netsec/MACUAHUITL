import { useCallback, useEffect, useState } from "react";
import { scriptsChanged } from "../scripts/signal";
import type { CoreAPI, PackDetail, PackInfo, PackInspectResult } from "../../lib/core";
import { Check, ConfirmButton, Notice, errorText } from "../../components/Field";
import { Dialog } from "../../components/Dialog";
import { useLang, useT } from "../../lib/i18n";
import { ExportDialog, ImportDialog } from "./PackPersonal";
import type { PackImportResult } from "./api";
import "./packs.css";

// Todo texto del paquete (nombre, README, IDs) se dibuja como texto de React: sin HTML, imágenes ni enlaces (ADR 0010).
// El script derivado de un playbook, igual que libID en internal/service/scripts: los de ios-xe quedan «lib-<id>», los
// demás llevan la plataforma («ios/l2-stp» → «lib-ios-l2-stp») para no chocar.
export function libOf(playbookId: string): string {
  const [plat, ...rest] = playbookId.split("/");
  const id = rest.join("/");
  return `lib-${plat === "ios-xe" ? id : `${plat}-${id}`}`;
}

// Un playbook oculto oculta su lib-<id>, salvo que el playbook esté tapado (entonces no filtra nada).
export function hiddenState(pack: PackInfo, playbookIds: string[]) {
  const hidden = new Set(pack.hidden);
  const viaPlaybook = new Set(playbookIds.filter((p) => hidden.has(p) && !pack.shadowed.includes(p)).map(libOf));
  return { hidden, viaPlaybook };
}

// En inglés, el texto en inglés del paquete; si un paquete de terceros no lo trae, el que tenga.
const packName = (p: PackInfo, lang: string) => (lang === "en" && p.nameEn) || p.name;
const packDesc = (p: PackInfo, lang: string) => (lang === "en" && p.descriptionEn) || p.description;

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
      setD((x) => (x ? { ...x, pack } : x)); onChange(pack); scriptsChanged();
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
  const lang = useLang();
  const [hide, setHide] = useState(() => new Set(pack.hidden));
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const install = async () => {
    setBusy(true); setErr("");
    let ok = false;
    try {
      // Un playbook tapado no se oculta (su casilla queda marcada): no viaja en hide, que con replaceHidden es el conjunto exacto.
      await core.packInstallHiding(path, !pack.official, [...playbookIds, ...scriptIds].filter((x) => hide.has(x) && !pack.shadowed.includes(x)), true, info.sha256);
      ok = true;
    } catch (e) { setErr(errorText(e)); }
    scriptsChanged(); // también si falló: un error puede decir «el paquete quedó instalado»
    try { onDone(); } finally { setBusy(false); }
    if (ok) onClose();
  };
  return (
    <Dialog title={t("packs.install.title")} onClose={onClose}>
      <h4>{packName(pack, lang)}</h4>
      <p>{packDesc(pack, lang)}</p>
      <p><code>{pack.id}</code> · {pack.version} · {pack.official ? t("packs.official") : t("packs.thirdParty")}{pack.author && <> · {pack.author}</>}{pack.license && <> · {pack.license}</>}</p>
      {info.replacedVersion && <p>{t("packs.replaces", { version: info.replacedVersion })}</p>}
      {!pack.official && <Notice kind="warn">{t("packs.unsigned")}</Notice>}
      {/* Lo derivado (lib-<id> de un playbook desmarcado) sale de la selección actual, no de lo que ya estaba oculto. */}
      <Items pack={{ ...pack, hidden: [...hide] }} playbookIds={playbookIds} scriptIds={scriptIds} isHidden={(x) => hide.has(x)} busy={busy}
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

  const [exporting, setExporting] = useState(false);
  const [imp, setImp] = useState<{ path: string; preview: PackImportResult } | null>(null);

  const refresh = useCallback(() => core.packList().then(setPacks, (e) => setErr(errorText(e))), [core]);
  useEffect(() => { void refresh(); }, [refresh]);

  const pick = async () => {
    setErr(""); setMsg("");
    try {
      const path = await core.pickPath({ title: t("packs.pick"), filters: [{ name: "MACUAHUITL", pattern: "*.mpack" }] });
      if (path) setPreview({ path, info: await core.packInspect(path, true) });
    } catch (e) { setErr(errorText(e)); }
  };
  const pickImport = async () => {
    setErr(""); setMsg("");
    try {
      const path = await core.pickPath({ title: t("packs.pick"), filters: [{ name: "MACUAHUITL", pattern: "*.mpack" }] });
      if (path) setImp({ path, preview: await core.packImportPreview(path) });
    } catch (e) { setErr(errorText(e)); }
  };
  const remove = async (id: string) => {
    setErr(""); setMsg("");
    try { const n = await core.packRemove(id); scriptsChanged(); if (n > 0) setMsg(t("packs.removedFavs", { n })); } catch (e) { setErr(errorText(e)); }
    void refresh();
  };
  const merge = (p: PackInfo) => setPacks((l) => l && l.map((x) => (x.id === p.id ? p : x)));

  return (
    <div className="packs">
      <div className="actions"><button type="button" onClick={pick}>{t("packs.install")}</button>
        <button type="button" onClick={() => setExporting(true)}>{t("packs.export.open")}</button>
        <button type="button" onClick={pickImport}>{t("packs.import.open")}</button></div>
      {err && <Notice kind="error">{err}</Notice>}
      {msg && <Notice kind="info">{msg}</Notice>}
      {packs?.length === 0 && <p className="hint">{t("packs.empty")}</p>}
      <ul className="pack-list">
        {packs?.map((p) => (
          <li key={p.id} className="pack-card">
            <h4>{packName(p, lang)}</h4>
            <p>{packDesc(p, lang)}</p>
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
      {exporting && <ExportDialog core={core} onClose={() => setExporting(false)} />}
      {imp && <ImportDialog core={core} path={imp.path} preview={imp.preview} onDone={refresh} onClose={() => setImp(null)} />}
      {preview && <InstallDialog core={core} path={preview.path} info={preview.info} onDone={refresh} onClose={() => setPreview(null)} />}
    </div>
  );
}
