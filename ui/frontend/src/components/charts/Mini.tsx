// Gráficas pequeñas en SVG propio, sin librería: tendencia en una celda y barra con umbrales.
import { useT } from "../../lib/i18n";

const fmt = (n: number) => (Number.isInteger(n) ? String(n) : n.toFixed(1));

export function Sparkline({ values, label, unit = "", width = 96, height = 24 }: { values: number[]; label: string; unit?: string; width?: number; height?: number }) {
  const t = useT();
  if (!values.length) return null;
  const min = Math.min(...values), max = Math.max(...values), span = max - min || 1;
  const x = (i: number) => (values.length === 1 ? width / 2 : (i / (values.length - 1)) * (width - 2) + 1);
  const y = (v: number) => height - 2 - ((v - min) / span) * (height - 4);
  const d = values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const last = values[values.length - 1];
  return (
    <svg className="spark" width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img"
      aria-label={t("chart.spark", { label, min: fmt(min), max: fmt(max), last: fmt(last), unit })}>
      <path d={d} fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinejoin="round" />
      <circle cx={x(values.length - 1)} cy={y(last)} r={2} fill="currentColor" />
    </svg>
  );
}

// Barra con umbrales: el nivel también va en texto (valor y unidad) y en data-level para el color.
export function Meter({ value, max = 100, warn, crit, label, unit = "" }: { value: number; max?: number; warn?: number; crit?: number; label: string; unit?: string }) {
  const level = crit !== undefined && value >= crit ? "crit" : warn !== undefined && value >= warn ? "warn" : "ok";
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  return (
    <span className="meter-wrap">
      <span className="meter" role="meter" aria-label={label} aria-valuenow={value} aria-valuemin={0} aria-valuemax={max} data-level={level}>
        <span className="meter-fill" style={{ width: `${pct}%` }} />
      </span>
      <span className="mono meter-value">{fmt(value)}{unit && ` ${unit}`}</span>
    </span>
  );
}
