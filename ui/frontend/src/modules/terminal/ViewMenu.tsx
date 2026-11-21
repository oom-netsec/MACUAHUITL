import { useEffect, useId, useRef, useState } from "react";
import { PaletteSwatch, paletteName } from "../../components/Terminal";
import { useT } from "../../lib/i18n";
import { PALETTES } from "../../lib/termHighlight";
import { setTermPrefs, useTermPrefs } from "../../lib/termPrefs";


// Menú «Vista» de la terminal (patrón de DeviceMenu): resaltado, paleta (selección única, con muestra) y, con varias pestañas, dividir.
export function ViewMenu({ split }: { split?: { checked: boolean; onChange: (v: boolean) => void } }) {
  const t = useT();
  const { palette, hl } = useTermPrefs();
  const [open, setOpen] = useState(false);
  const id = useId();
  const btn = useRef<HTMLButtonElement>(null);
  const box = useRef<HTMLSpanElement>(null);
  const items = () => [...(box.current?.querySelectorAll<HTMLButtonElement>("[role^=menuitem]") ?? [])];
  const close = (focus = true) => { setOpen(false); if (focus) btn.current?.focus(); };
  useEffect(() => {
    if (!open) return;
    (box.current?.querySelector<HTMLButtonElement>("[role=menuitemradio][aria-checked=true]") ?? items()[0])?.focus();
    const out = (e: PointerEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("pointerdown", out);
    return () => document.removeEventListener("pointerdown", out);
  }, [open]);
  const onKey = (e: React.KeyboardEvent) => {
    if (!open) return; // con el menú cerrado las teclas siguen su camino
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
      <button ref={btn} type="button" className="sm" aria-haspopup="menu" aria-expanded={open} aria-controls={open ? id : undefined} onClick={() => setOpen((o) => !o)}>{t("ssh.view")}</button>
      {open && (
        <div className="popover menu theme-list" role="menu" id={id} aria-label={t("ssh.view")}>
          <button role="menuitemcheckbox" aria-checked={hl} className="quiet" onClick={() => setTermPrefs({ hl: !hl })}>
            <span className="theme-name">{t("ssh.hl")}</span>
            <span className="theme-check" aria-hidden="true">{hl ? "✓" : ""}</span>
          </button>
          <div role="group" aria-label={t("ssh.theme")}>
          {PALETTES.map((p) => (
            <button key={p.id} role="menuitemradio" aria-checked={p.id === palette} className="quiet" onClick={() => { setTermPrefs({ palette: p.id }); close(); }}>
              <PaletteSwatch p={p} />
              <span className="theme-name">{paletteName(t, p)}</span>
              <span className="theme-check" aria-hidden="true">{p.id === palette ? "✓" : ""}</span>
            </button>
          ))}
          </div>
          {split && (
            <button role="menuitemcheckbox" aria-checked={split.checked} className="quiet" onClick={() => split.onChange(!split.checked)}>
              <span className="theme-name">{t("ssh.split")}</span>
              <span className="theme-check" aria-hidden="true">{split.checked ? "✓" : ""}</span>
            </button>
          )}
        </div>
      )}
    </span>
  );
}
