// Mapa de calor equipo × métrica: tabla real (encabezados de fila y columna) con el valor en texto dentro de cada celda;
// el color solo refuerza el nivel. La leyenda dice qué significa cada tono.
import { useT } from "../../lib/i18n";

export type Level = "bad" | "warn" | "info" | "low";
export interface HeatCell { text: string; level: Level }

export function Heatmap({ label, corner, cols, rows, cell, legend }: {
  label: string; corner: string; cols: { id: string; label: string }[]; rows: string[];
  cell: (row: string, col: string) => HeatCell | undefined; legend: { level: Level | "none"; text: string }[];
}) {
  const t = useT();
  return (
    <div className="heat-wrap">
      <div className="table-wrap heat-scroll">
        <table className="heat" aria-label={label}>
          <thead><tr><th scope="col">{corner}</th>{cols.map((c) => <th key={c.id} scope="col">{c.label}</th>)}</tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r}>
                <th scope="row" className="mono">{r}</th>
                {cols.map((c) => {
                  const x = cell(r, c.id);
                  return <td key={c.id} data-level={x?.level ?? "none"}>{x ? x.text : "—"}</td>;
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ul className="heat-legend" aria-label={t("fleet.heat.legend")}>
        {legend.map((l) => <li key={l.level}><span className="swatch" data-level={l.level} aria-hidden="true" />{l.text}</li>)}
      </ul>
    </div>
  );
}
