import { useEffect, useRef, useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { cleanOnFail } from "../../lib/cleanOnFail";
import { Check, ConfirmButton, Field, Notice, Select, errorText } from "../../components/Field";
import { CopyButton } from "../../components/Data";
import { Icon } from "../../components/Icon";
import { Badge, EmptyState, Page, ResultPanel, Tabs } from "../../components/Page";
import { useNav } from "../../app/activity";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { MAX_PINNED, type Collection, type ScriptDraft, type ScriptItem, type ScriptOrigin, type ScriptPlatform, type ScriptTech } from "./api";
import { CollectionMenu } from "./CollectionMenu";
import { CollectionsPanel } from "./CollectionsPanel";
import { PLATFORMS, ScriptForm, TECHS } from "./ScriptForm";
import { scriptsChanged, useScriptsVersion } from "./signal";
import { needsCopy, encodeInsert, isPinLimit, scriptText } from "./text";
import { useImportFlow } from "./useImportFlow";
import "./scripts.css";

// Bóveda de scripts: biblioteca de solo lectura más los del usuario. Nada se aplica a un equipo desde aquí (ADR 0007):
// «Enviar a la terminal» deja el texto en la sesión SSH activa sin Enter, y la persona decide si lo ejecuta.
export function ScriptsView({ core }: { core: CoreAPI }) {
  const t = useT();
  const go = useNav();
  const [origin, setOrigin] = useState<ScriptOrigin | "colecciones">("biblioteca");
  const [text, setText] = useState("");
  const [tech, setTech] = useState<ScriptTech | "">("");
  const [platform, setPlatform] = useState<ScriptPlatform | "">("");
  const [onlyFav, setOnlyFav] = useState(false);
  const [items, setItems] = useState<ScriptItem[] | null>(null);
  const [ver, setVer] = useState(0);
  const [selId, setSelId] = useState("");
  const [form, setForm] = useState<{ item?: ScriptItem } | null>(null);
  const back = useRef(""); // botón que abrió el formulario, para devolverle el foco al cerrarlo
  const [picked, setPicked] = useState<string[]>([]);
  const [cols, setCols] = useState<Collection[]>([]); // para el menú «Agregar a colección» de cada fila
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const seq = useRef(0);
  const sv = useScriptsVersion(); // otra pantalla (p. ej. Ajustes → Datos) cambió los scripts: volver a leer
  const reload = () => setVer((v) => v + 1);

  useEffect(() => {
    const n = ++seq.current; // solo cuenta la última consulta
    core.listScripts({ tech, platform, text, onlyFavorites: onlyFav }).then((l) => { if (n === seq.current) { setItems(l); setErr(""); } }, (e) => { if (n === seq.current) setErr(errorText(e)); });
  }, [core, tech, platform, text, onlyFav, ver, sv]);
  useEffect(() => { core.listCollections().then(setCols, () => setCols([])); }, [core, ver, sv]);

  const shown = (items ?? []).filter((s) => s.origin === origin); // en «colecciones» no se usa
  // La selección es solo de lo que se ve: al cambiar de pestaña o de filtro se quita lo demás (el contador es lo que se exporta).
  useEffect(() => {
    if (!items) return;
    const visible = new Set(items.filter((s) => s.origin === origin).map((s) => s.id));
    setPicked((p) => (p.every((id) => visible.has(id)) ? p : p.filter((id) => visible.has(id))));
  }, [items, origin]);
  useEffect(() => {
    if (form || !back.current) return;
    document.querySelector<HTMLElement>(`[data-back="${back.current}"]`)?.focus();
    back.current = "";
  }, [form]);
  const sel = shown.find((s) => s.id === selId);
  const filtered = text !== "" || tech !== "" || platform !== "" || onlyFav;
  const run = async (f: () => Promise<void>) => { setErr(""); setMsg(""); try { await f(); } catch (e) { setErr(errorText(e)); } };

  // El sexto fijado lo rechaza el núcleo con su motivo; se muestra en el idioma elegido.
  const togglePin = (s: ScriptItem) => run(async () => {
    try { await core.setScriptPinned(s.id, !s.pinned); } catch (e) {
      if (isPinLimit(e)) throw new Error(t("scripts.pin.max", { n: String(MAX_PINNED) }));
      throw e;
    }
    scriptsChanged(); reload();
  });
  const toggleCol = (s: ScriptItem, c: Collection, on: boolean) => run(async () => {
    const cur = (await core.getCollection(c.id)).scriptIds; // lista al día: otra pantalla pudo cambiarla
    await core.setCollectionScripts(c.id, on ? [...cur.filter((x) => x !== s.id), s.id] : cur.filter((x) => x !== s.id));
    scriptsChanged(); reload();
  });
  const toggleFav = (s: ScriptItem) => run(async () => { await core.setScriptFavorite(s.id, !s.favorite); scriptsChanged(); reload(); });
  const duplicate = (s: ScriptItem) => run(async () => { const c = await core.duplicateScript(s.id); scriptsChanged(); setOrigin("usuario"); setSelId(c.id); reload(); });
  const remove = (s: ScriptItem) => run(async () => { await core.deleteScript(s.id); scriptsChanged(); setSelId(""); setPicked((p) => p.filter((x) => x !== s.id)); reload(); });
  const save = async (d: ScriptDraft) => {
    const s = await core.saveScript(d); // un error vuelve al formulario, que lo pone junto a su campo
    scriptsChanged(); setForm(null); setOrigin("usuario"); setSelId(s.id); reload();
  };
  const exportPicked = () => run(async () => {
    const path = await core.pickSavePath(t("scripts.exportName"));
    if (!path) return;
    const n = await cleanOnFail(core, path, core.exportScripts(picked, path, true)); // pickSavePath ya confirmó el reemplazo y dejó el archivo vacío
    setMsg(t("scripts.exported", { n: String(n), path }));
  });
  const imp = useImportFlow(core, "scripts", () => { scriptsChanged(); reload(); });

  if (form) {
    return (
      <Page title={form.item ? t("scripts.edit") : t("scripts.new")}>
        <ScriptForm initial={form.item} onSave={save} onCancel={() => setForm(null)} />
      </Page>
    );
  }

  return (
    <Page title={t("nav.scripts")} description={t("scripts.desc")}
      tabs={<Tabs label={t("scripts.origin")} value={origin} onChange={setOrigin} tabs={[["biblioteca", t("scripts.tab.lib")], ["usuario", t("scripts.tab.mine")], ["colecciones", t("scripts.tab.cols")]]} />}
      actions={origin === "colecciones" ? undefined : (
        <>
          <button type="button" className="primary" data-back="new" onClick={() => { back.current = "new"; setForm({}); }}><Icon name="plus" />{t("scripts.new")}</button>
          <button type="button" onClick={() => void imp.start()}><Icon name="upload" />{t("scripts.import")}</button>
          <button type="button" disabled={picked.length === 0} onClick={exportPicked}><Icon name="download" />{t("scripts.export", { n: String(picked.length) })}</button>
        </>
      )}>
      {origin === "colecciones" ? <CollectionsPanel core={core} onChanged={() => { scriptsChanged(); reload(); }} /> : <>
      {err && <Notice kind="error">{err}</Notice>}
      {msg && <Notice kind="ok">{msg}</Notice>}
      {imp.node}
      <div className="field-row">
        <Field label={t("scripts.search")} hint={t("scripts.searchHint")} value={text} onChange={setText} w="lg" />
        <Select<ScriptTech | ""> label={t("scripts.tech")} value={tech} onChange={setTech} w="md" options={[["", t("scripts.any")], ...TECHS.map((x) => [x, t(`scripts.tech.${x}` as Key)] as [ScriptTech, string])]} />
        <Select<ScriptPlatform | ""> label={t("scripts.platform")} value={platform} onChange={setPlatform} w="md" options={[["", t("scripts.any")], ...PLATFORMS.map((x) => [x, t(`scripts.plat.${x}` as Key)] as [ScriptPlatform, string])]} />
      </div>
      <Check label={t("scripts.onlyFav")} checked={onlyFav} onChange={setOnlyFav} />
      <div className="scr-layout">
        <div>
          {items && shown.length === 0 && <EmptyState icon="list" title={t("scripts.empty.title")}>{t(origin === "usuario" && !filtered ? "scripts.empty.mine" : "scripts.empty.filter")}</EmptyState>}
          {shown.length > 0 && (
            <ul className="scr-list" aria-label={t("scripts.list")}>
              {shown.map((s) => (
                <li key={s.id} className="scr-row" data-sel={s.id === selId}>
                  <input type="checkbox" aria-label={t("scripts.pick", { name: s.name })} checked={picked.includes(s.id)}
                    onChange={(e) => setPicked((p) => (e.target.checked ? [...p, s.id] : p.filter((x) => x !== s.id)))} />
                  <button type="button" className="quiet scr-name" onClick={() => setSelId(s.id)}>{s.name}</button>
                  <span className="scr-meta">
                    <Badge>{t(`scripts.tech.${s.tech}` as Key)}</Badge>
                    <Badge>{t(`scripts.plat.${s.platform}` as Key)}</Badge>
                    {s.readOnly && <Badge tone="ok">{t("scripts.readOnly")}</Badge>}
                  </span>
                  <span className="scr-acts">
                    <button type="button" className="quiet icon sm scr-pin" aria-pressed={s.pinned} aria-label={t("scripts.pin", { name: s.name })} onClick={() => togglePin(s)}><Icon name="pin" /></button>
                    <CollectionMenu script={s} cols={cols} onToggle={(c, on) => void toggleCol(s, c, on)} />
                    <button type="button" className="quiet icon sm scr-star" aria-pressed={s.favorite} aria-label={t("scripts.fav", { name: s.name })} onClick={() => toggleFav(s)}><Icon name="star" /></button>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          {sel ? (
            <ResultPanel title={sel.name} pad
              actions={
                <>
                  {needsCopy(sel)
                    ? <button type="button" className="sm" onClick={() => run(async () => { await core.copyText(sel.commands.join("\n")); setMsg(t("common.copied")); })}><Icon name="copy" />{t("scripts.copy")}</button>
                    : <button type="button" className="sm" title={t("scripts.sendHint")} onClick={() => go("terminal", encodeInsert({ name: sel.name, text: scriptText(sel.commands), readOnly: sel.readOnly }), "terminal-insert")}><Icon name="terminal" />{t("scripts.send")}</button>}
                  <button type="button" className="sm" onClick={() => duplicate(sel)}>{t("scripts.dup")}</button>
                  {sel.origin === "usuario" && (
                    <>
                      <button type="button" className="sm" data-back="edit" onClick={() => { back.current = "edit"; setForm({ item: sel }); }}>{t("scripts.edit")}</button>
                      <ConfirmButton label={t("scripts.deleteName", { name: sel.name })} confirmLabel={t("scripts.deleteConfirm", { name: sel.name })} onConfirm={() => remove(sel)}>{t("scripts.delete")}</ConfirmButton>
                    </>
                  )}
                </>
              }>
              <div className="scr-meta">
                <Badge>{t(`scripts.tech.${sel.tech}` as Key)}</Badge>
                <Badge>{t(`scripts.plat.${sel.platform}` as Key)}</Badge>
                {sel.readOnly && <span title={t("scripts.readOnlyHint")}><Badge tone="ok">{t("scripts.readOnly")}</Badge></span>}
              </div>
              {needsCopy(sel) && <Notice kind="warn">{t("scripts.noSend")}</Notice>}
              {sel.description && <p>{sel.description}</p>}
              {sel.tags.length > 0 && <p className="scr-meta"><span className="hint">{t("scripts.tags")}</span>{sel.tags.map((x) => <Badge key={x}>{x}</Badge>)}</p>}
              <div className="scr-cmdhead"><strong>{t("scripts.commands")}</strong><CopyButton value={sel.commands.join("\n")} label={t("scripts.copyWhat", { name: sel.name })} /></div>
              <pre className="scr-cmds">{sel.commands.map((c, i) => <code key={i} className="scr-line">{c}</code>)}</pre>
              {sel.origin === "biblioteca" && <p className="hint">{t("scripts.libNote")}</p>}
            </ResultPanel>
          ) : (
            <p className="hint">{t("scripts.detail.none")}</p>
          )}
        </div>
      </div>
      </>}
    </Page>
  );
}
