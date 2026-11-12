import { useEffect, useId, useMemo, useRef, useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Icon } from "../../components/Icon";
import { useT } from "../../lib/i18n";
import { FAVORITES_ID, type Collection, type ScriptItem } from "../scripts/api";
import { needsCopy, colName, scriptText } from "../scripts/text";

const haystack = (s: ScriptItem) => [s.name, s.description, ...s.tags, ...s.commands].join("\n").toLowerCase();

// «Scripts ▾» de la terminal: menú con búsqueda agrupado por colección (favoritos primero), pensado para el teclado
// (patrón de ThemeMenu). Escribir filtra, las flechas recorren, Enter elige y Escape cierra devolviendo el foco al botón.
// Elegir un script no lo ejecuta aquí: lo entrega a `onPick`, que usa la misma ruta segura de inserción que el resto.
export function ScriptsMenu({ core, version, onPick }: { core: CoreAPI; version: number; onPick: (s: ScriptItem) => Promise<boolean> }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [data, setData] = useState<{ cols: Collection[]; byId: Map<string, ScriptItem> } | null>(null);
  const id = useId();
  const btn = useRef<HTMLButtonElement>(null);
  const box = useRef<HTMLSpanElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const items = () => [...(box.current?.querySelectorAll<HTMLElement>("input, [role=menuitem]") ?? [])];
  const close = (focus = true) => { setOpen(false); setQ(""); if (focus) btn.current?.focus(); };

  useEffect(() => {
    if (!open) return;
    let live = true;
    Promise.all([core.listCollections(), core.listScripts()]).then(
      ([cols, all]) => { if (live) setData({ cols: [...cols].sort((a, b) => Number(b.id === FAVORITES_ID) - Number(a.id === FAVORITES_ID) || a.order - b.order), byId: new Map(all.map((s) => [s.id, s])) }); },
      () => { if (live) setData({ cols: [], byId: new Map() }); },
    );
    return () => { live = false; };
  }, [core, open, version]);
  useEffect(() => {
    if (!open) return;
    search.current?.focus();
    const out = (e: PointerEvent) => { if (!box.current?.contains(e.target as Node)) close(false); };
    document.addEventListener("pointerdown", out);
    return () => document.removeEventListener("pointerdown", out);
  }, [open]);

  const groups = useMemo(() => {
    const f = q.trim().toLowerCase();
    return (data?.cols ?? [])
      .map((c) => ({ c, list: c.scriptIds.map((x) => data!.byId.get(x)).filter((s): s is ScriptItem => !!s && !!scriptText(s.commands) && (!f || haystack(s).includes(f))) }))
      .filter((g) => g.list.length > 0);
  }, [data, q]);

  // Si el script se envió, el foco ya lo lleva el emulador; en cualquier otro caso vuelve al botón «Scripts ▾».
  const pick = async (s: ScriptItem) => { close(false); if (!(await onPick(s))) btn.current?.focus(); };
  const onKey = (e: React.KeyboardEvent) => {
    const all = items();
    const i = all.indexOf(document.activeElement as HTMLElement);
    const go = (n: number) => { e.preventDefault(); all[(n + all.length) % all.length]?.focus(); };
    if (e.key === "ArrowDown") go(i + 1);
    else if (e.key === "ArrowUp") go(i - 1);
    else if (e.key === "Home" && document.activeElement !== search.current) go(0);
    else if (e.key === "End" && document.activeElement !== search.current) go(all.length - 1);
    else if (e.key === "Escape") { e.preventDefault(); close(); }
    else if (e.key === "Tab") close(); // sin preventDefault: el foco vuelve al botón y Tab sigue al siguiente control
    else if (e.key === "Enter" && document.activeElement === search.current) { e.preventDefault(); all[1]?.click(); }
    else if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey && document.activeElement !== search.current) search.current?.focus(); // escribir desde un elemento sigue filtrando
  };
  return (
    <span className="scripts-menu" ref={box} onKeyDown={onKey}>
      <button ref={btn} type="button" className="sm" aria-haspopup="menu" aria-expanded={open} aria-controls={open ? id : undefined} onClick={() => (open ? close() : setOpen(true))}>{t("ssh.scriptsMenu")}</button>
      {open && (
        <div className="popover menu scripts-pop" id={id}>
          <input ref={search} type="search" className="scripts-q" aria-label={t("ssh.scriptsFilter")} placeholder={t("ssh.scriptsFilter")} value={q} onChange={(e) => setQ(e.target.value)} />
          <div role="menu" aria-label={t("ssh.scriptsMenuLabel")}>
            {data && groups.length === 0 && <p className="hint scripts-none">{t(q.trim() ? "ssh.scriptsNone" : "ssh.scriptsEmpty")}</p>}
            {groups.map(({ c, list }) => (
              <div key={c.id} role="group" aria-label={colName(t, c)}>
                <div className="scripts-group" aria-hidden="true">{colName(t, c)}</div>
                {list.map((s) => (
                  <button key={s.id} type="button" role="menuitem" className="quiet" onClick={() => void pick(s)}>
                    {needsCopy(s) ? <><Icon name="copy" size={12} /><span>{t("ssh.scriptsItemCopy", { name: s.name })}</span></> : <span>{s.name}</span>}
                  </button>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}
    </span>
  );
}
