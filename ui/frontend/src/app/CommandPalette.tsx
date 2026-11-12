import { useEffect, useId, useMemo, useRef, useState } from "react";
import { groups, modules } from "../modules";
import { Icon, type IconName } from "../components/Icon";
import { useT } from "../lib/i18n";
import { es, type Key } from "../lib/i18n/es";
import { en } from "../lib/i18n/en";

export interface PaletteAction { id: string; labelKey: Key; icon: IconName; keys?: string; run: () => void }
interface Entry { id: string; label: string; detail: string; icon: IconName; keys?: string; run: () => void; hay: string }

const recentKey = "macuahuitl.recientes";
export function rememberRecent(id: string) {
  try {
    const prev = JSON.parse(localStorage.getItem(recentKey) ?? "[]") as string[];
    localStorage.setItem(recentKey, JSON.stringify([id, ...prev.filter((x) => x !== id)].slice(0, 5)));
  } catch { /* sin almacenamiento: sin recientes */ }
}
function recents(): string[] {
  try { return JSON.parse(localStorage.getItem(recentKey) ?? "[]") as string[]; } catch { return []; }
}

// Sin acentos ni mayúsculas: "boveda" encuentra "Bóveda".
const norm = (s: string) => s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();
// Se busca en los dos idiomas a la vez: un ingeniero puede pensar "credentials" con la app en español.
const both = (k: Key) => `${es[k]} ${en[k]}`;

// Paleta de comandos (Ctrl+K): ir a cualquier módulo o lanzar una acción. Patrón combobox + listbox (WAI-ARIA).
export function CommandPalette({ onGo, onClose, actions }: { onGo: (id: string) => void; onClose: () => void; actions: PaletteAction[] }) {
  const t = useT();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const listId = useId();
  const back = useRef<Element | null>(null);

  useEffect(() => {
    back.current = document.activeElement;
    input.current?.focus();
    return () => { (back.current as HTMLElement | null)?.focus?.(); };
  }, []);

  const mods: Entry[] = useMemo(() => modules.map((m) => {
    const g = m.group ? groups[m.group] : null;
    return {
      id: m.id, label: t(m.label), detail: g ? t(g.label) : "", icon: m.icon ?? g?.icon ?? "chevron",
      run: () => onGo(m.id), hay: norm(`${both(m.label)} ${g ? both(g.label) : ""} ${m.id}`),
    };
  }), [t, onGo]);
  const acts: Entry[] = useMemo(() => actions.map((a) => ({ id: a.id, label: t(a.labelKey), detail: "", icon: a.icon, keys: a.keys, run: a.run, hay: norm(both(a.labelKey)) })), [actions, t]);

  // Cada palabra debe aparecer; primero lo que empieza con la búsqueda.
  const sections: [Key, Entry[]][] = useMemo(() => {
    const words = norm(q).split(/\s+/).filter(Boolean);
    if (!words.length) {
      const rec = recents().map((id) => mods.find((m) => m.id === id)).filter((m): m is Entry => !!m);
      return ([["shell.palette.recent", rec], ["shell.palette.modules", mods.filter((m) => !rec.includes(m))], ["shell.palette.actions", acts]] as [Key, Entry[]][]).filter(([, l]) => l.length);
    }
    const match = (e: Entry) => words.every((w) => e.hay.includes(w));
    const rank = (a: Entry, b: Entry) => Number(norm(b.label).startsWith(words[0])) - Number(norm(a.label).startsWith(words[0]));
    return ([["shell.palette.modules", mods.filter(match).sort(rank)], ["shell.palette.actions", acts.filter(match).sort(rank)]] as [Key, Entry[]][]).filter(([, l]) => l.length);
  }, [q, mods, acts]);
  const flat = sections.flatMap(([, l]) => l);
  const cur = Math.min(sel, Math.max(0, flat.length - 1));
  const choose = (e?: Entry) => { if (!e) return; onClose(); e.run(); };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (flat.length) setSel((cur + (e.key === "ArrowDown" ? 1 : -1) + flat.length) % flat.length);
    } else if (e.key === "Enter") {
      e.preventDefault();
      choose(flat[cur]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    } else if (e.key === "Tab") {
      e.preventDefault(); // el foco se queda en la búsqueda mientras la paleta está abierta
    }
  };

  let i = -1;
  return (
    <div className="scrim" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="palette" role="dialog" aria-modal="true" aria-label={t("shell.palette")} onKeyDown={onKey}>
        <div className="palette-input">
          <Icon name="search" />
          <input ref={input} role="combobox" aria-expanded="true" aria-controls={listId} aria-autocomplete="list"
            aria-activedescendant={flat.length ? `${listId}-${cur}` : undefined} aria-label={t("shell.palette.placeholder")}
            placeholder={t("shell.palette.placeholder")} value={q} spellCheck={false} autoComplete="off"
            onChange={(e) => { setQ(e.target.value); setSel(0); }} />
        </div>
        <ul className="palette-list" role="listbox" id={listId} aria-label={t("shell.palette")}>
          {sections.map(([title, list]) => (
            <li key={title} role="presentation">
              <div className="palette-group" role="presentation">{t(title)}</div>
              <ul role="group" aria-label={t(title)}>
                {list.map((e) => {
                  i++;
                  const n = i;
                  return (
                    <li key={e.id} id={`${listId}-${n}`} role="option" aria-selected={n === cur} className="palette-item"
                      onMouseMove={() => setSel(n)} onClick={() => choose(e)}>
                      <Icon name={e.icon} />{e.label}{e.detail && <small>{e.detail}</small>}{e.keys && <kbd>{e.keys}</kbd>}
                    </li>
                  );
                })}
              </ul>
            </li>
          ))}
        </ul>
        {!flat.length && <p className="palette-empty">{t("shell.palette.empty", { q })}</p>}
        <div className="palette-foot" aria-hidden="true">
          <span><kbd>↑</kbd> <kbd>↓</kbd> {t("shell.palette.move")}</span>
          <span><kbd>↵</kbd> {t("shell.palette.open")}</span>
          <span><kbd>Esc</kbd> {t("shell.palette.close")}</span>
        </div>
      </div>
    </div>
  );
}
