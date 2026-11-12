import { useEffect, useId, useRef, useState } from "react";
import { PaletteSwatch, paletteName } from "../../components/Terminal";
import { useT } from "../../lib/i18n";
import { PALETTES } from "../../lib/termHighlight";
import { setTermPrefs, useTermPrefs } from "../../lib/termPrefs";


// «Cambiar tema» de la terminal: menú de selección única con una muestra de cada paleta (patrón de DeviceMenu).
export function ThemeMenu() {
  const t = useT();
  const { palette } = useTermPrefs();
  const [open, setOpen] = useState(false);
  const id = useId();
  const btn = useRef<HTMLButtonElement>(null);
  const box = useRef<HTMLSpanElement>(null);
  const items = () => [...(box.current?.querySelectorAll<HTMLButtonElement>("[role=menuitemradio]") ?? [])];
  const close = (focus = true) => { setOpen(false); if (focus) btn.current?.focus(); };
  useEffect(() => {
    if (!open) return;
    (box.current?.querySelector<HTMLButtonElement>("[aria-checked=true]") ?? items()[0])?.focus();
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
    else if (e.key === "Tab") close(); // sin preventDefault: el foco vuelve al botón y Tab sigue al siguiente control
  };
  return (
    <span className="theme-menu" ref={box} onKeyDown={onKey}>
      <button ref={btn} type="button" className="sm" aria-haspopup="menu" aria-expanded={open} aria-controls={open ? id : undefined} onClick={() => setOpen((o) => !o)}>{t("ssh.theme")}</button>
      {open && (
        <div className="popover menu theme-list" role="menu" id={id} aria-label={t("ssh.theme")}>
          {PALETTES.map((p) => (
            <button key={p.id} role="menuitemradio" aria-checked={p.id === palette} className="quiet" onClick={() => { setTermPrefs({ palette: p.id }); close(); }}>
              <PaletteSwatch p={p} />
              <span className="theme-name">{paletteName(t, p)}</span>
              <span className="theme-check" aria-hidden="true">{p.id === palette ? "✓" : ""}</span>
            </button>
          ))}
        </div>
      )}
    </span>
  );
}
