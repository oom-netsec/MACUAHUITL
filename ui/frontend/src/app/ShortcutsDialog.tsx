import { useEffect, useRef } from "react";
import { useT } from "../lib/i18n";
import type { Key } from "../lib/i18n/es";

const list: [string, Key][] = [
  ["Ctrl K", "shortcut.palette"],
  ["Ctrl B", "shortcut.sidebar"],
  ["Ctrl ↵", "shortcut.run"],
  ["Alt ← / →", "shortcut.history"],
  ["Esc", "shortcut.close"],
  ["Ctrl /", "shortcut.help"],
  ["Ctrl Shift K", "shortcut.termLeave"],
  ["Ctrl Shift C / V", "shortcut.termCopy"],
];

export function ShortcutsDialog({ onClose }: { onClose: () => void }) {
  const t = useT();
  const close = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const back = document.activeElement as HTMLElement | null;
    close.current?.focus();
    return () => back?.focus?.();
  }, []);
  return (
    <div className="scrim" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      onKeyDown={(e) => { if (e.key === "Escape") { e.preventDefault(); onClose(); } }}>
      <div className="palette shortcuts" role="dialog" aria-modal="true" aria-labelledby="shortcuts-h">
        <div className="panel-head">
          <h3 id="shortcuts-h">{t("shell.shortcuts")}</h3>
          <div className="panel-actions"><button ref={close} className="quiet sm" onClick={onClose}>{t("dialog.close")}</button></div>
        </div>
        <dl className="shortcut-list">
          {list.map(([k, d]) => <div key={k}><dt><kbd>{k}</kbd></dt><dd>{t(d)}</dd></div>)}
        </dl>
      </div>
    </div>
  );
}
