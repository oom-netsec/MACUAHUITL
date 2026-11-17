import { useState } from "react";
import { CopyButton } from "../../components/Data";
import { Bars } from "./CalcBars";
import type { CalcResult, CoreAPI } from "../../lib/core";
import { EmptyState, ResultPanel, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";

export const words = (s: string) => s.split(/[\s,;]+/).filter(Boolean);
export const num = (s: string) => (s.trim() === "" ? undefined : Number(s));
export const kbd = <kbd aria-hidden="true">Ctrl ↵</kbd>;

// Dirección, máscara, wildcard o prefijo con dirección: se puede copiar con un clic.
const ADDR = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:]*:[0-9a-f:.]*)(\/\d{1,3})?$/i;

// Tablas y notas del núcleo dentro de un panel de resultado, con las barras de reparto de Subred y VLSM.
function ResultView({ r, kind }: { r: CalcResult; kind: string }) {
  return (
    <>
      <Bars kind={kind} r={r} />
      {r.tables.map((t, i) => (
        <div key={i} className="table-wrap flat" role="region" aria-label={t.title} tabIndex={0}>
          <table>
            <caption>{t.title}</caption>
            <thead><tr>{t.head.map((h) => <th key={h} scope="col">{h}</th>)}</tr></thead>
            <tbody>{t.rows.map((row, j) => (
              <tr key={j}>{row.map((c, k) => (
                <td key={k} className={k > 0 ? "mono" : undefined}>
                  {c}{k > 0 && ADDR.test(c) && <CopyButton value={c} label={(t.columns ? t.columns[0].key === "calc.col.field" : ["Campo", "Field"].includes(t.head[0])) ? row[0] : t.head[k]} />}
                </td>
              ))}</tr>
            ))}</tbody>
          </table>
        </div>
      ))}
      {r.notes.length > 0 && <div className="panel-body"><ul className="notes">{r.notes.map((n, i) => <li key={i}>{n}</li>)}</ul></div>}
    </>
  );
}

// Pide un cálculo al núcleo; `view` es el panel de resultado, o qué hacer primero si todavía no hay uno.
export function useCalc(core: CoreAPI) {
  const t = useT();
  const r = useResult<CalcResult>();
  const [kind, setKind] = useState("");
  const run = (k: string, req: object) => { setKind(k); return r.run(() => core.calc(k, req)); };
  const view = (
    <div aria-live="polite">
      {!r.data && !r.error && !r.busy && <EmptyState icon="tools" title={t("calc.empty.title")}>{t("calc.empty")}</EmptyState>}
      {(r.data || r.error) && <ResultPanel title={t("calc.result")} error={r.error}>{r.data && <ResultView r={r.data} kind={kind} />}</ResultPanel>}
    </div>
  );
  return { run, busy: r.busy, view };
}
