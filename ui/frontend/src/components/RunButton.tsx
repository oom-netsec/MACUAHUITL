import type { ReactNode } from "react";
import { useId } from "react";
import { useT } from "../lib/i18n";

type Miss = string | false | null | undefined;

// Botón de acción que dice qué falta: `missing` junta los datos pedidos (los falsos se descartan) y, si hay alguno, el botón queda
// deshabilitado y lo nombra debajo (aria-describedby). `disabled` es para condiciones que no son «falta un dato».
// `quiet`: el motivo solo para lector de pantalla (barras de cabecera, o un segundo botón con el mismo motivo que el primario).
export function RunButton({ missing, busy, disabled, onClick, primary, kbd, quiet, type = "button", className, children }: {
  missing: Miss[]; busy?: boolean; quiet?: boolean; disabled?: boolean; onClick?: () => void; primary?: boolean; kbd?: boolean; type?: "button" | "submit"; className?: string; children: ReactNode;
}) {
  const t = useT();
  const id = useId();
  const need = missing.filter(Boolean) as string[];
  const explain = need.length > 0 && !busy;
  return (
    <>
      <button type={type} className={[primary && "primary", className].filter(Boolean).join(" ") || undefined} disabled={busy || need.length > 0 || disabled} aria-busy={busy || undefined}
        aria-describedby={explain ? id : undefined} onClick={onClick}>
        {children}{kbd && <kbd aria-hidden="true">Ctrl ↵</kbd>}
      </button>
      {explain && <p id={id} className={quiet ? "sr" : "hint need"}>{t("need.list", { list: need.join(", ") })}</p>}
    </>
  );
}
