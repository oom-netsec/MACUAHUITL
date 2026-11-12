import { useEffect, useRef, useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { cleanOnFail } from "../../lib/cleanOnFail";
import { ConfirmButton, Field, Notice, Select, errorText } from "../../components/Field";
import { Icon } from "../../components/Icon";
import { Badge, EmptyState, ResultPanel } from "../../components/Page";
import { useT } from "../../lib/i18n";
import { FAVORITES_ID, type Collection, type ScriptItem } from "./api";
import { useScriptsVersion } from "./signal";
import { colName } from "./text";
import { useImportFlow } from "./useImportFlow";

const move = <T,>(l: T[], i: number, d: number): T[] => { const n = [...l]; [n[i], n[i + d]] = [n[i + d], n[i]]; return n; };

// Área de colecciones: crear, renombrar, borrar, ordenar, ver y ordenar sus scripts, agregar y quitar por ID (sin copias),
// exportar e importar. El orden se cambia con botones (teclado); el foco vuelve al botón que se pulsó.
export function CollectionsPanel({ core, onChanged }: { core: CoreAPI; onChanged: () => void }) {
  const t = useT();
  const [cols, setCols] = useState<Collection[] | null>(null);
  const [scripts, setScripts] = useState<ScriptItem[]>([]);
  const [ver, setVer] = useState(0);
  const [selId, setSelId] = useState("");
  const [form, setForm] = useState<{ id?: string; name: string; description: string } | null>(null);
  const [ferr, setFerr] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [addId, setAddId] = useState("");
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const focus = useRef("");
  const sv = useScriptsVersion(); // otra pantalla (p. ej. Ajustes → Datos) cambió los scripts o las colecciones
  const changed = () => { onChanged(); setVer((v) => v + 1); };
  const imp = useImportFlow(core, "colecciones", changed);

  useEffect(() => {
    let live = true;
    Promise.all([core.listCollections(), core.listScripts()]).then(([c, s]) => { if (live) { setCols(c); setScripts(s); } }, (e) => { if (live) setErr(errorText(e)); });
    return () => { live = false; };
  }, [core, ver, sv]);
  useEffect(() => {
    if (!focus.current) return;
    // Candidatos en orden; el primero que exista y no esté apagado recibe el foco. «add» es el selector de agregar un script.
    const els = focus.current.split("|").map((k) => { const el = document.querySelector<HTMLElement>(`[data-mv="${k}"]`); return k === "add" ? el?.querySelector<HTMLElement>("select") : el; });
    els.find((el) => el && !(el as HTMLButtonElement).disabled)?.focus();
    focus.current = "";
  }, [cols]);

  const run = async (f: () => Promise<void>) => { setErr(""); setMsg(""); try { await f(); } catch (e) { focus.current = ""; setErr(errorText(e)); } }; // si falló, no queda un foco pendiente
  const byId = new Map(scripts.map((s) => [s.id, s]));
  const sel = cols?.find((c) => c.id === selId);

  const moveCol = (i: number, d: number) => run(async () => {
    const id = cols![i].id;
    focus.current = `c-${id}-${d < 0 ? "up" : "down"}|c-${id}-${d < 0 ? "down" : "up"}`;
    await core.reorderCollections(move(cols!, i, d).map((c) => c.id));
    changed();
  });
  const setIds = (c: Collection, ids: string[], mv = "") => run(async () => {
    if (mv) focus.current = mv;
    await core.setCollectionScripts(c.id, ids);
    changed();
  });
  const moveScript = (c: Collection, i: number, d: number) => {
    const id = c.scriptIds[i];
    return setIds(c, move(c.scriptIds, i, d), `s-${id}-${d < 0 ? "up" : "down"}|s-${id}-${d < 0 ? "down" : "up"}`);
  };
  // Al quitar, el foco pasa al siguiente script (o al anterior si era el último); sin ninguno, al selector de agregar.
  const removeScript = (c: Collection, i: number) => {
    const next = c.scriptIds[i + 1] ?? c.scriptIds[i - 1];
    return setIds(c, c.scriptIds.filter((_, j) => j !== i), next ? `s-${next}-rm` : "add");
  };
  const save = async () => {
    if (!form) return;
    setFerr("");
    try {
      // «favoritos» se ve con el nombre del idioma elegido pero el núcleo no admite renombrarla: se manda el suyo.
      const name = form.id === FAVORITES_ID ? cols?.find((c) => c.id === FAVORITES_ID)?.name ?? form.name : form.name;
      const c = await core.saveCollection({ id: form.id, name, description: form.description });
      setForm(null); setSelId(c.id); changed();
    } catch (e) { setFerr(errorText(e)); }
  };
  const remove = (c: Collection) => run(async () => { await core.deleteCollection(c.id); setSelId(""); setPicked((p) => p.filter((x) => x !== c.id)); changed(); });
  const exportPicked = () => run(async () => {
    const path = await core.pickSavePath(t("scripts.col.exportName"));
    if (!path) return;
    const r = await cleanOnFail(core, path, core.exportCollections(picked, path, true)); // pickSavePath ya confirmó el reemplazo
    setMsg(t("scripts.col.exported", { c: r.collections, s: r.scripts, path }));
  });
  const nameOf = (id: string) => byId.get(id)?.name ?? id; // un «lib-*» que la biblioteca ya no trae se ve por su ID
  const addable = scripts.filter((s) => sel && !sel.scriptIds.includes(s.id));

  return (
    <>
      <p className="hint">{t("scripts.col.desc")}</p>
      <div className="actions">
        <button type="button" className="primary" onClick={() => { setFerr(""); setForm({ name: "", description: "" }); }}><Icon name="plus" />{t("scripts.col.new")}</button>
        <button type="button" onClick={() => void imp.start()}><Icon name="upload" />{t("scripts.col.import")}</button>
        <button type="button" disabled={picked.length === 0} onClick={exportPicked}><Icon name="download" />{t("scripts.col.export", { n: String(picked.length) })}</button>
      </div>
      {err && <Notice kind="error">{err}</Notice>}
      {msg && <Notice kind="ok">{msg}</Notice>}
      {imp.node}
      {form && (
        <form className="col-form" onSubmit={(e) => { e.preventDefault(); void save(); }}>
          <Field label={t("scripts.col.f.name")} value={form.name} onChange={(v) => setForm({ ...form, name: v })} error={ferr || undefined} w="lg" disabled={form.id === FAVORITES_ID} />
          <Field label={t("scripts.col.f.desc")} value={form.description} onChange={(v) => setForm({ ...form, description: v })} w="full" />
          <div className="actions">
            <button type="submit" className="primary">{t("scripts.col.f.save")}</button>
            <button type="button" onClick={() => setForm(null)}>{t("scripts.f.cancel")}</button>
          </div>
        </form>
      )}
      <div className="scr-layout">
        <div>
          {cols && cols.length > 0 && (
            <ul className="scr-list" aria-label={t("scripts.col.list")}>
              {cols.map((c, i) => (
                <li key={c.id} className="col-row" data-sel={c.id === selId}>
                  <input type="checkbox" aria-label={t("scripts.col.pick", { name: colName(t, c) })} checked={picked.includes(c.id)}
                    onChange={(e) => setPicked((p) => (e.target.checked ? [...p, c.id] : p.filter((x) => x !== c.id)))} />
                  <button type="button" className="quiet scr-name" aria-label={t("scripts.col.open", { name: colName(t, c) })} onClick={() => setSelId(c.id)}>{colName(t, c)}</button>
                  <Badge>{t("scripts.col.count", { n: String(c.scriptIds.length) })}</Badge>
                  <button type="button" className="quiet icon sm" data-mv={`c-${c.id}-up`} disabled={i === 0} aria-label={t("scripts.col.up", { name: colName(t, c) })} onClick={() => void moveCol(i, -1)}><Icon name="up" /></button>
                  <button type="button" className="quiet icon sm" data-mv={`c-${c.id}-down`} disabled={i === cols.length - 1} aria-label={t("scripts.col.down", { name: colName(t, c) })} onClick={() => void moveCol(i, 1)}><Icon name="down" /></button>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          {sel ? (
            <ResultPanel title={colName(t, sel)} pad
              actions={
                <>
                  <button type="button" className="sm" onClick={() => { setFerr(""); setForm({ id: sel.id, name: colName(t, sel), description: sel.description }); }}>{t("scripts.edit")}</button>
                  {sel.id !== FAVORITES_ID && <ConfirmButton label={t("scripts.col.deleteName", { name: sel.name })} confirmLabel={t("scripts.deleteConfirm", { name: sel.name })} onConfirm={() => void remove(sel)}>{t("scripts.delete")}</ConfirmButton>}
                </>
              }>
              {sel.description && <p>{sel.description}</p>}
              {sel.id === FAVORITES_ID && <p className="hint">{t("scripts.col.fixed")}</p>}
              {sel.scriptIds.length === 0
                ? <EmptyState icon="list" title={t("scripts.empty.title")}>{t("scripts.col.empty")}</EmptyState>
                : (
                  <ul className="scr-list" aria-label={t("scripts.col.scripts", { name: colName(t, sel) })}>
                    {sel.scriptIds.map((id, i) => (
                      <li key={id} className="col-row">
                        <span className="scr-name">{nameOf(id)}</span>
                        <button type="button" className="quiet icon sm" data-mv={`s-${id}-up`} disabled={i === 0} aria-label={t("scripts.col.sUp", { name: nameOf(id) })} onClick={() => void moveScript(sel, i, -1)}><Icon name="up" /></button>
                        <button type="button" className="quiet icon sm" data-mv={`s-${id}-down`} disabled={i === sel.scriptIds.length - 1} aria-label={t("scripts.col.sDown", { name: nameOf(id) })} onClick={() => void moveScript(sel, i, 1)}><Icon name="down" /></button>
                        <button type="button" className="quiet icon sm" data-mv={`s-${id}-rm`} aria-label={t("scripts.col.remove", { name: nameOf(id) })} onClick={() => void removeScript(sel, i)}><Icon name="close" /></button>
                      </li>
                    ))}
                  </ul>
                )}
              <div className="col-add" data-mv="add">
                <Select<string> label={t("scripts.col.add")} value={addId} onChange={setAddId} w="lg" placeholder={t("scripts.col.addPick")}
                  options={addable.map((s) => [s.id, `${s.name} · ${t(s.origin === "biblioteca" ? "scripts.tab.lib" : "scripts.tab.mine")}`] as [string, string])} />
                <button type="button" disabled={!addId} onClick={() => { void setIds(sel, [...sel.scriptIds, addId]); setAddId(""); }}>{t("scripts.col.addBtn")}</button>
              </div>
            </ResultPanel>
          ) : (
            <p className="hint">{t("scripts.col.none")}</p>
          )}
        </div>
      </div>
    </>
  );
}
