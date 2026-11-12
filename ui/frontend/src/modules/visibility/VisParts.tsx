import { useId, useMemo } from "react";
import { CopyButton, SeverityBadge } from "../../components/Data";
import { DataTable, type Column } from "../../components/DataTable";
import { formatBytes } from "../../components/Files";
import { LazyTimeChart } from "../../components/charts/LazyTimeChart";
import { useLang, useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";

// Piezas visuales de Visibilidad: gráficas por interfaz, barras de top talkers y bitácora de traps.

export interface IfRow { Name: string; Oper: string; InBps?: number | null; OutBps?: number | null; InErrors?: number; OutErrors?: number }
export interface Sample { Time: string; System?: Record<string, string>; Interfaces?: IfRow[]; CPU?: { Index: string; FiveSec: number; OneMin: number; FiveMin: number }[]; Memory?: { Name: string; UsedPct: number }[]; Errors?: string[] }

const mbps = (v?: number | null) => (v == null ? null : +(v / 1e6).toFixed(3));
const at = (hist: Sample[], name: string, f: "InBps" | "OutBps") => hist.map((s) => mbps(s.Interfaces?.find((i) => i.Name === name)?.[f]));

/** Tendencia de entrada de una interfaz (para la minigráfica de su fila), en Mb/s. */
export const trend = (hist: Sample[], name: string) => at(hist, name, "InBps").filter((v): v is number => v != null);

/** Las dos interfaces con más tráfico en la última muestra: las que se grafican si nadie eligió otras. */
export function busiest(hist: Sample[], n = 2): string[] {
  const last = hist[hist.length - 1]?.Interfaces ?? [];
  return last.map((i) => [i.Name, (i.InBps ?? 0) + (i.OutBps ?? 0)] as const).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]).slice(0, n).map(([k]) => k);
}

function IfaceChart({ hist, name, syncKey }: { hist: Sample[]; name: string; syncKey: string }) {
  const t = useT();
  const times = useMemo(() => hist.map((s) => Math.floor(Date.parse(s.Time) / 1000)), [hist]);
  const series = useMemo(() => [{ label: t("visibility.col.in"), values: at(hist, name, "InBps") }, { label: t("visibility.col.out"), values: at(hist, name, "OutBps") }], [hist, name, t]);
  return <LazyTimeChart title={t("visibility.chart.title", { name })} unit="Mb/s" times={times} series={series} syncKey={syncKey} height={180} fileName={`snmp-${name.replace(/\W+/g, "-")}`} />;
}

export function IfaceCharts({ hist, names, syncKey }: { hist: Sample[]; names: string[]; syncKey: string }) {
  return <div className="panel-body iface-charts">{names.map((n) => <IfaceChart key={n} hist={hist} name={n} syncKey={syncKey} />)}</div>;
}

export interface Counter { Key: string; Bytes: number; Packets: number; Flows: number }

/** Barras horizontales ordenadas por bytes; cada fila lleva el valor y su parte del total en texto. */
export function TalkerBars({ title, rows, total }: { title: string; rows: Counter[]; total: number }) {
  const t = useT();
  const h = useId();
  const sorted = [...rows].sort((a, b) => b.Bytes - a.Bytes);
  const max = sorted[0]?.Bytes || 1;
  return (
    <div className="panel-body">
      <h4 id={h}>{title}</h4>
      <ol className="bars" aria-labelledby={h}>
        {sorted.map((r) => {
          const pct = total > 0 ? Math.round((r.Bytes / total) * 100) : 0;
          return (
            <li key={r.Key}>
              <span className="mono bar-key">{r.Key}<CopyButton value={r.Key} label={t("visibility.copyIp", { ip: r.Key })} /></span>
              <span className="bar" role="meter" aria-label={r.Key} aria-valuemin={0} aria-valuemax={max} aria-valuenow={r.Bytes} aria-valuetext={formatBytes(r.Bytes)}>
                <span className="bar-fill" style={{ width: `${(r.Bytes / max) * 100}%` }} />
              </span>
              <span className="mono bar-value">{formatBytes(r.Bytes)} · {pct} % {t("visibility.flows.share")}</span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

export interface TrapMsg { From?: string; Name?: string; Summary?: string; Version?: string; Error?: string }
export interface TrapRow extends TrapMsg { id: number; at: string }

// El trap no trae severidad: se deduce de su nombre (los de enlace y autenticación pesan más).
export function trapSeverity(m: TrapMsg): number {
  if (m.Error) return 4;
  switch (m.Name) {
    case "linkDown": return 3;
    case "authenticationFailure": return 4;
    case "coldStart": case "warmStart": return 5;
    default: return 6;
  }
}
const host = (from?: string) => (from ?? "").replace(/^\[(.*)\]:\d+$/, "$1").replace(/^([^:]+):\d+$/, "$1");

/** Resumen de la fila: un v3 sin decodificar lleva su etiqueta traducida; el motivo del núcleo (en español) solo con la app en español. */
export function trapSummary(r: TrapMsg, t: (k: Key, v?: Record<string, string | number>) => string, lang: string): string {
  if (r.Summary) return r.Summary;
  const m = /^v3 sin decodificar \((\d+) bytes\): (.*)$/s.exec(r.Error ?? "");
  if (!m) return r.Error ?? "";
  const label = t("visibility.traps.v3", { bytes: m[1] });
  return lang === "es" ? `${label}: ${m[2]}` : label;
}

export function TrapsTable({ rows }: { rows: TrapRow[] }) {
  const t = useT();
  const lang = useLang();
  const cols: Column<TrapRow>[] = useMemo(() => [
    { id: "at", header: t("visibility.traps.col.time"), value: (r) => r.at, width: 96, mono: true, render: (r) => new Date(r.at).toLocaleTimeString(lang) },
    { id: "sev", header: t("visibility.traps.col.sev"), value: (r) => trapSeverity(r), width: 150, render: (r) => <SeverityBadge sev={trapSeverity(r)} /> },
    { id: "from", header: t("visibility.traps.col.from"), value: (r) => host(r.From), width: 170, mono: true, render: (r) => <>{host(r.From)}{r.From && <CopyButton value={host(r.From)} label={t("visibility.copyIp", { ip: host(r.From) })} />}</> },
    { id: "name", header: t("visibility.traps.col.trap"), value: (r) => r.Name ?? "", width: 150 },
    { id: "summary", header: t("visibility.traps.col.summary"), value: (r) => trapSummary(r, t, lang), mono: true },
  ], [t, lang]);
  // Lo más reciente arriba.
  const newest = useMemo(() => [...rows].reverse(), [rows]);
  return <DataTable label={t("visibility.events")} columns={cols} rows={newest} rowKey={(r) => String(r.id)} exportName={t("file.traps")} height={360} />;
}
