// Series de tiempo con uPlot (MIT): rápido con miles de puntos y sin React por dentro. Se carga bajo demanda
// (LazyTimeChart): solo las vistas con gráficas pagan su peso.
// Un solo eje vertical, líneas de 2 px, umbrales y marcas de ronda, cursor sincronizado entre las gráficas
// de una vista (syncKey), zoom con arrastre y doble clic para volver. Resumen en texto y tabla equivalentes.
import { useContext, useEffect, useId, useRef, useState } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import { CoreContext } from "../../app/activity";
import { useLang, useT } from "../../lib/i18n";
import { useTheme } from "../../lib/theme";
import { csvCell } from "../../lib/tableExport";

export interface Series { label: string; values: (number | null)[] }
export interface TimeChartProps {
  title: string;
  times: number[]; // segundos Unix
  series: Series[];
  unit?: string;
  thresholds?: { value: number; label: string }[];
  marks?: { at: number; label: string }[];
  syncKey?: string;
  height?: number;
  fileName: string;
}

// Familia para el canvas (no admite variables CSS).
const FAMILY = "Inter,system-ui,sans-serif";
// Pasos del eje X en segundos desde 1 s: con menos, un rango de pocos segundos repite la misma hora en cada marca.
export const TIME_INCRS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800, 2419200, 31536000]; // hasta 4 semanas y 1 año: series largas no se quedan sin marcas
const fmt = (n: number) => (Number.isInteger(n) ? String(n) : n.toFixed(1));

export function toCSV(times: number[], series: Series[]): string {
  const head = ["hora", ...series.map((s) => csvCell(s.label))].join(",");
  return [head, ...times.map((t, i) => [new Date(t * 1000).toISOString(), ...series.map((s) => (s.values[i] ?? "") + "")].join(","))].join("\n");
}

// Las variables con light-dark() no se resuelven con getPropertyValue: se leen como color de un elemento sonda.
function resolve(el: HTMLElement, vars: string[]): string[] {
  const probe = document.createElement("span");
  el.appendChild(probe);
  const out = vars.map((v) => { probe.style.color = `var(${v})`; return getComputedStyle(probe).color; });
  probe.remove();
  return out;
}

// Con huecos, un valor aislado no forma línea: se dibujan los puntos para que no desaparezca.
export const hasGaps = (v: (number | null)[]) => v.some((x) => x == null);

export default function TimeChart({ title, times, series, unit = "", thresholds = [], marks = [], syncKey, height = 220, fileName }: TimeChartProps) {
  const t = useT();
  const lang = useLang();
  const theme = useTheme();
  const core = useContext(CoreContext);
  const h = useId();
  const box = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  const [dark, setDark] = useState(() => window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false);
  useEffect(() => {
    const m = window.matchMedia?.("(prefers-color-scheme: dark)");
    const f = () => setDark(m.matches);
    m?.addEventListener?.("change", f);
    return () => m?.removeEventListener?.("change", f);
  }, []);
  const empty = !times.length || !series.length;

  // Con la misma estructura (series, unidad, umbrales, marcas) solo cambian los datos: setData en vez de rehacer la gráfica.
  const shape = JSON.stringify([series.map((s) => s.label), unit, thresholds, marks, syncKey, height, theme, dark, lang]);
  const data = [times, ...series.map((s) => s.values)] as uPlot.AlignedData;
  const dataRef = useRef(data);
  dataRef.current = data;
  useEffect(() => { plot.current?.setData(data); }, [times, series]); // data se deriva de times y series

  useEffect(() => {
    const el = box.current;
    if (!el || empty) return;
    const [text3, hairline, warning, ...palette] = resolve(el, ["--text-3", "--hairline", "--warning", ...series.map((_, i) => `--chart-${(i % 8) + 1}`)]);
    const clock = (v: number, secs = false) => new Date(v * 1000).toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit", ...(secs && { second: "2-digit" }) });
    const axis = { stroke: text3, grid: { stroke: hairline, width: 1 }, ticks: { stroke: hairline, width: 1 }, font: `12px ${FAMILY}` };
    const opts: uPlot.Options = {
      width: el.clientWidth || 640,
      height,
      cursor: { sync: syncKey ? { key: syncKey } : undefined, drag: { x: true, y: false } } as uPlot.Cursor,
      legend: { live: true },
      scales: { x: { time: true } },
      padding: [marks.length ? 18 : null, null, null, null] as uPlot.Padding, // franja superior para las etiquetas de ronda
      axes: [{ ...axis, incrs: TIME_INCRS, values: (_u: uPlot, vals: number[], _ax: number, _sp: number, incr: number) => vals.map((v) => clock(v, incr < 60)) }, { ...axis, values: (_u, vals) => vals.map((v) => `${fmt(v)}${unit ? ` ${unit}` : ""}`), size: unit.length > 2 ? 88 : 64 }],
      series: [{ label: t("chart.time"), value: (_u: uPlot, v: number | null) => (v == null ? "—" : clock(v)) }, ...series.map((s, i) => ({ label: s.label, stroke: palette[i], width: 2, points: { show: (u: uPlot, si: number) => hasGaps(u.data[si] as (number | null)[]), size: 6 }, value: (_u: uPlot, v: number | null) => (v == null ? "—" : `${fmt(v)}${unit ? ` ${unit}` : ""}`) }))],
      hooks: {
        draw: [(u: uPlot) => {
          const c = u.ctx;
          c.save();
          c.font = `${12 * devicePixelRatio}px ${FAMILY}`;
          c.lineWidth = devicePixelRatio;
          for (const th of thresholds) {
            const y = u.valToPos(th.value, "y", true);
            c.strokeStyle = warning; c.setLineDash([4 * devicePixelRatio, 4 * devicePixelRatio]);
            c.beginPath(); c.moveTo(u.bbox.left, y); c.lineTo(u.bbox.left + u.bbox.width, y); c.stroke();
            c.fillStyle = text3; c.textAlign = "right";
            c.fillText(th.label, u.bbox.left + u.bbox.width - 4 * devicePixelRatio, y + 14 * devicePixelRatio);
            c.textAlign = "left";
          }
          c.setLineDash([]);
          for (const m of marks) {
            const x = u.valToPos(m.at, "x", true);
            c.strokeStyle = hairline; c.beginPath(); c.moveTo(x, u.bbox.top - 14 * devicePixelRatio); c.lineTo(x, u.bbox.top + u.bbox.height); c.stroke();
            // La etiqueta va en la franja sobre el área (sin líneas encima): a la izquierda de la marca si no cabe a la derecha.
            const w = c.measureText(m.label).width, right = u.bbox.left + u.bbox.width;
            const tx = x + 4 * devicePixelRatio + w > right ? x - 4 * devicePixelRatio - w : x + 4 * devicePixelRatio;
            c.fillStyle = text3; c.fillText(m.label, Math.max(u.bbox.left + 2, tx), u.bbox.top - 4 * devicePixelRatio);
          }
          c.restore();
        }],
      },
    };
    try {
      plot.current = new uPlot(opts, dataRef.current, el);
    } catch { plot.current = null; } // sin canvas (pruebas): quedan el resumen y la tabla
    const ro = typeof ResizeObserver !== "undefined" ? new ResizeObserver(() => plot.current?.setSize({ width: el.clientWidth, height })) : null;
    ro?.observe(el);
    return () => { ro?.disconnect(); plot.current?.destroy(); plot.current = null; };
  }, [shape, empty]); // shape resume todo lo que cambia la gráfica salvo los datos

  const summary = series.map((s) => {
    const v = s.values.filter((x): x is number => x != null);
    if (!v.length) return `${s.label}: —`;
    const u = unit ? ` ${unit}` : "";
    return t("chart.summary", { label: s.label, min: fmt(Math.min(...v)) + u, avg: fmt(v.reduce((a, b) => a + b, 0) / v.length) + u, max: fmt(Math.max(...v)) + u, last: fmt(v[v.length - 1]) + u });
  });
  const save = async (name: string, data: string, enc: "utf8" | "base64") => { await core?.saveFile(name, data, enc).catch(() => ""); };

  return (
    <figure className="chart" aria-labelledby={h}>
      <figcaption>
        <span id={h} className="chart-title">{title}</span>
        {!empty && (
          <span className="chart-actions">
            <button className="quiet sm" onClick={() => save(`${fileName}.csv`, toCSV(times, series), "utf8")}>{t("chart.csv")}</button>
            <button className="quiet sm" onClick={() => { const url = plot.current?.ctx.canvas.toDataURL("image/png"); if (url) void save(`${fileName}.png`, url.split(",")[1], "base64"); }}>{t("chart.png")}</button>
          </span>
        )}
      </figcaption>
      {empty ? <p className="empty">{t("chart.empty")}</p> : (
        <>
          <div ref={box} className="chart-canvas" />
          <ul className="chart-summary">{summary.map((s, i) => <li key={i}>{s}</li>)}</ul>
          <details className="chart-data">
            <summary>{t("chart.table")}</summary>
            <div className="table-wrap">
              <table>
                <thead><tr><th scope="col">{t("chart.time")}</th>{series.map((s) => <th key={s.label} scope="col">{unit ? `${s.label} (${unit})` : s.label}</th>)}</tr></thead>
                <tbody>{times.map((tm, i) => (
                  <tr key={tm}><td className="mono">{new Date(tm * 1000).toLocaleTimeString(lang)}</td>{series.map((s) => <td key={s.label} className="mono">{s.values[i] ?? "—"}</td>)}</tr>
                ))}</tbody>
              </table>
            </div>
          </details>
        </>
      )}
    </figure>
  );
}
