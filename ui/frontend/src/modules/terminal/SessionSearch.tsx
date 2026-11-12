import { Field } from "../../components/Field";
import { useT } from "../../lib/i18n";

// Búsqueda en la sesión (addon-search de xterm): la caja escribe la consulta y los botones o Enter saltan entre coincidencias.
// El conteo lo informa el addon: index es la coincidencia actual (-1 si no hay) y count el total.
export function SessionSearch({ q, onQ, onStep, index, count }: { q: string; onQ: (q: string) => void; onStep: (dir: 1 | -1) => void; index: number; count: number }) {
  const t = useT();
  return (
    <div className="ssh-find" onKeyDown={(e) => { if (e.key === "Enter" && e.target instanceof HTMLInputElement) { e.preventDefault(); onStep(e.shiftKey ? -1 : 1); } }}>
      <Field label={t("ssh.find.label")} type="search" value={q} onChange={onQ} w="md" />
      <button className="sm" aria-label={t("ssh.find.prev")} disabled={!count} onClick={() => onStep(-1)}>↑</button>
      <button className="sm" aria-label={t("ssh.find.next")} disabled={!count} onClick={() => onStep(1)}>↓</button>
      <span role="status" aria-label={t("ssh.find.status")} className="meta">{q ? (count ? t("ssh.find.pos", { n: index + 1, total: count }) : t("ssh.find.none")) : ""}</span>
    </div>
  );
}
