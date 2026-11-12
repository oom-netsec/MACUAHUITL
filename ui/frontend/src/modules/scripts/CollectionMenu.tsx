import { useEffect, useId, useRef, useState } from "react";
import { Icon } from "../../components/Icon";
import { useT } from "../../lib/i18n";
import type { Collection, ScriptItem } from "./api";
import { colName } from "./text";

// «Agregar a colección»: menú de selección múltiple (patrón de ThemeMenu). Cada opción agrega o quita el script de esa
// colección y el menú sigue abierto para marcar varias; Escape lo cierra y devuelve el foco al botón.
export function CollectionMenu({ script, cols, onToggle }: { script: ScriptItem; cols: Collection[]; onToggle: (c: Collection, on: boolean) => void }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const id = useId();
  const btn = useRef<HTMLButtonElement>(null);
  const box = useRef<HTMLSpanElement>(null);
  const items = () => [...(box.current?.querySelectorAll<HTMLButtonElement>("[role=menuitemcheckbox]") ?? [])];
  const close = (focus = true) => { setOpen(false); if (focus) btn.current?.focus(); };
  useEffect(() => {
    if (!open) return;
    items()[0]?.focus();
    const out = (e: PointerEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("pointerdown", out);
    return () => document.removeEventListener("pointerdown", out);
  }, [open]);
  const onKey = (e: React.KeyboardEvent) => {
    const all = items();
    const i = all.indexOf(document.activeElement as HTMLButtonElement);
    const go = (n: number) => { e.preventDefault(); all[(n + all.length) % all.length]?.focus(); };
    if (e.key === "ArrowDown") go(i + 1);
    else if (e.key === "ArrowUp") go(i - 1);
    else if (e.key === "Home") go(0);
    else if (e.key === "End") go(all.length - 1);
    else if (e.key === "Escape") { e.preventDefault(); close(); }
    else if (e.key === "Tab") close();
  };
  return (
    <span className="col-menu" ref={box} onKeyDown={onKey}>
      <button ref={btn} type="button" className="quiet icon sm" aria-haspopup="menu" aria-expanded={open} aria-controls={open ? id : undefined}
        aria-label={t("scripts.col.addTo", { name: script.name })} onClick={() => setOpen((o) => !o)}><Icon name="folderPlus" /></button>
      {open && (
        <div className="popover menu col-list" role="menu" id={id} aria-label={t("scripts.col.menu", { name: script.name })}>
          {cols.map((c) => {
            const on = script.collections.includes(c.id);
            return (
              <button key={c.id} role="menuitemcheckbox" aria-checked={on} className="quiet" onClick={() => onToggle(c, !on)}>
                <span className="col-check" aria-hidden="true">{on ? "✓" : ""}</span>
                <span className="col-name">{colName(t, c)}</span>
              </button>
            );
          })}
        </div>
      )}
    </span>
  );
}
