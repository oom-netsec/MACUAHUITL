import { useEffect, useMemo, useState } from "react";
import type { CoreAPI, Job } from "../../lib/core";
import { Check, Notice, Select, errorText } from "../../components/Field";
import { EmptyState, Section, Tabs } from "../../components/Page";
import { LazyTimeChart } from "../../components/charts/LazyTimeChart";
import type { Series } from "../../components/charts/TimeChart";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { cpuPeak, fromJob, growing, ifaceValue, perRound, roundTimes, topInterfaces, ifaceNames, type DeviceMetrics, type PatrolMetrics } from "./metrics";

const MiB = 1024 * 1024;
const MBPS = 1_000_000;
const CPU_THRESHOLD = 80;

// Métricas del trabajo (todos los equipos); se piden de nuevo cuando termina una ronda o cambia el estado.
export function useMetrics(core: CoreAPI, job: Job) {
  const [m, setM] = useState<PatrolMetrics | null>(null);
  const [err, setErr] = useState("");
  const wanted = job.state !== "created";
  useEffect(() => {
    if (!wanted) return;
    let stale = false;
    core.jobMetrics({ job: job.id, maxInterfaces: 64 }).then((r) => { if (!stale) { setM(fromJob(r)); setErr(""); } }).catch((e) => { if (!stale) setErr(errorText(e)); });
    return () => { stale = true; };
  }, [core, job.id, job.round, job.state, wanted]);
  return { metrics: m, error: err };
}

type Tab = "summary" | "cpu" | "ifaces" | "errors";
type Spec = { key: string; title: string; unit: string; series: Series[]; thresholds?: { value: number; label: string }[]; none?: boolean };
type T = (k: Key, v?: Record<string, string | number>) => string;

const pct = (a: number, b: number) => (b > 0 ? Math.round((a / b) * 1000) / 10 : null);

function cpuSpecs(d: DeviceMetrics, m: PatrolMetrics, t: T): Spec[] {
  const name = d.name;
  const cpu: Spec = {
    key: "cpu", title: t("patrol.metrics.cpu.title", { device: name }), unit: "%", thresholds: [{ value: CPU_THRESHOLD, label: t("patrol.metrics.cpu.threshold", { n: CPU_THRESHOLD }) }],
    series: [
      { label: t("patrol.metrics.cpu.5s"), values: perRound(d, m, (s) => s.cpu?.fiveSec) },
      { label: t("patrol.metrics.cpu.1m"), values: perRound(d, m, (s) => s.cpu?.oneMin) },
      { label: t("patrol.metrics.cpu.5m"), values: perRound(d, m, (s) => s.cpu?.fiveMin) },
    ],
  };
  const pools = [...new Set(d.samples.flatMap((s) => s.memory?.map((p) => p.pool) ?? []))];
  const mem = pools.map((pool): Spec => {
    const of = (f: "usedBytes" | "freeBytes") => perRound(d, m, (s) => s.memory?.find((p) => p.pool === pool)?.[f]).map((v) => (v == null ? null : Math.round((v / MiB) * 10) / 10));
    return { key: `mem-${pool}`, title: t("patrol.metrics.mem.title", { pool, device: name }), unit: "MiB", series: [{ label: t("patrol.metrics.mem.used"), values: of("usedBytes") }, { label: t("patrol.metrics.mem.free"), values: of("freeBytes") }] };
  });
  return [cpu, ...mem];
}

function ifaceSpecs(d: DeviceMetrics, m: PatrolMetrics, names: string[], t: T): Spec[] {
  const rate = (f: (i: { inBps?: number; outBps?: number }) => number | undefined): Series[] =>
    names.map((n) => ({ label: n, values: perRound(d, m, ifaceValue(n, f)).map((v) => (v == null ? null : Math.round((v / MBPS) * 100) / 100)) }));
  const util: Series[] = names.map((n) => ({
    label: n,
    values: perRound(d, m, (s) => { const i = s.interfaces?.find((x) => x.name === n); return i && i.inBps != null && i.outBps != null ? pct(Math.max(i.inBps, i.outBps), i.bandwidthBps) ?? undefined : undefined; }),
  }));
  return [
    { key: "in", title: t("patrol.metrics.if.in", { device: d.name }), unit: "Mbps", series: rate((i) => i.inBps) },
    { key: "out", title: t("patrol.metrics.if.out", { device: d.name }), unit: "Mbps", series: rate((i) => i.outBps) },
    { key: "util", title: t("patrol.metrics.if.util", { device: d.name }), unit: "%", series: util },
  ];
}

function errorSpecs(d: DeviceMetrics, m: PatrolMetrics, t: T): Spec[] {
  const sum = (a?: number, b?: number) => (a == null || b == null ? undefined : a + b); // sin diferencia válida: sin dato
  const counters: [string, Key, (i: NonNullable<DeviceMetrics["samples"][number]["interfaces"]>[number]) => number | undefined][] = [
    ["errors", "patrol.metrics.err.errors", (i) => sum(i.inErrors, i.outErrors)],
    ["drops", "patrol.metrics.err.drops", (i) => sum(i.inDrops, i.outDrops)],
    ["crc", "patrol.metrics.err.crc", (i) => i.crc],
    ["resets", "patrol.metrics.err.resets", (i) => i.resets],
  ];
  return counters.map(([key, title, pick]) => {
    const names = growing(d, m, pick).slice(0, 8);
    return { key, title: t(title, { device: d.name }), unit: "", none: !names.length, series: names.map((n) => ({ label: n, values: perRound(d, m, ifaceValue(n, pick)) })) };
  });
}

export function MetricsPanel({ metrics, error, jobId }: { metrics: PatrolMetrics | null; error: string; jobId: string }) {
  const t = useT();
  const [tab, setTab] = useState<Tab>("summary");
  const [devId, setDevId] = useState("");
  const [picked, setPicked] = useState<Record<string, string[]>>({});
  const d = metrics?.devices.find((x) => x.deviceId === devId) ?? metrics?.devices[0];
  const times = useMemo(() => (metrics ? roundTimes(metrics) : []), [metrics]);
  const marks = useMemo(() => times.map((at, i) => {
    const n = metrics?.rounds[i].round ?? i + 1;
    return { at, label: d?.reboots.includes(n) ? t("patrol.metrics.reboot", { n }) : t("patrol.metrics.round", { n }) };
  }), [times, metrics, d, t]);
  const selected = d ? picked[d.deviceId] ?? topInterfaces(d) : [];
  const specs = useMemo(() => {
    if (!metrics || !d) return [];
    if (tab === "cpu") return cpuSpecs(d, metrics, t);
    if (tab === "ifaces") return ifaceSpecs(d, metrics, ifaceNames(d).filter((n) => selected.includes(n)), t);
    if (tab === "errors") return errorSpecs(d, metrics, t);
    return [];
  }, [metrics, d, tab, selected.join("|"), t]);

  if (error && !metrics) return <Notice kind="error">{error}</Notice>;
  if (!metrics) return null;
  if (!metrics.rounds.length || !d) return <EmptyState icon="patrol" title={t("patrol.metrics.empty")} />;

  const lastMem = [...d.samples].reverse().find((s) => s.memory?.length)?.memory?.[0];
  const peak = cpuPeak(d);
  const count = (pick: Parameters<typeof growing>[2]) => growing(d, metrics, pick).length;
  const avg5 = d.samples.filter((s) => s.interfaces?.some((i) => i.avg5min)).map((s) => s.round);
  const stats: [string, string][] = [
    peak ? [t("patrol.metrics.stat.cpuPeak"), t("patrol.metrics.stat.cpuPeakAt", { value: peak.value, round: peak.round })] : null,
    lastMem ? [t("patrol.metrics.stat.mem", { pool: lastMem.pool }), `${pct(lastMem.usedBytes, lastMem.usedBytes + lastMem.freeBytes)} %`] : null,
    [t("patrol.metrics.stat.crc"), String(count((i) => i.crc))],
    [t("patrol.metrics.stat.drops"), String(count((i) => (i.inDrops == null || i.outDrops == null ? undefined : i.inDrops + i.outDrops)))],
    [t("patrol.metrics.stat.rounds"), `${d.samples.length} / ${metrics.rounds.length}`],
  ].filter((x): x is [string, string] => !!x);
  const toggle = (n: string) => setPicked({ ...picked, [d.deviceId]: selected.includes(n) ? selected.filter((x) => x !== n) : [...selected, n] });

  return (
    <div className="metrics">
      <div className="metrics-bar">
        <Tabs label={t("patrol.metrics.tabs")} value={tab} onChange={setTab}
          tabs={[["summary", t("patrol.metrics.tab.summary")], ["cpu", t("patrol.metrics.tab.cpu")], ["ifaces", t("patrol.metrics.tab.ifaces")], ["errors", t("patrol.metrics.tab.errors")]]} />
        <Select label={t("patrol.metrics.device")} value={d.deviceId} onChange={setDevId} w="md" options={metrics.devices.map((x) => [x.deviceId, x.address && x.name !== x.address ? `${x.name} (${x.address})` : x.name])} />
      </div>
      {error && <Notice kind="error">{error}</Notice>}
      {[...metrics.warnings, ...d.warnings].map((w) => <Notice key={w} kind="warn">{w}</Notice>)}
      {tab === "summary" && (
        <Section title={t("patrol.metrics.summary", { device: d.name })}>
          <dl className="stats">{stats.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>
        </Section>
      )}
      {tab !== "summary" && d.ifaceTotal > d.ifaceShown && <p className="meta">{t("patrol.metrics.if.capped", { n: d.ifaceShown, total: d.ifaceTotal })}</p>}
      {tab === "ifaces" && avg5.length > 0 && <p className="meta">{t("patrol.metrics.if.avg5", { rounds: avg5.join(", ") })}</p>}
      {tab === "ifaces" && (
        <fieldset className="if-pick">
          <legend>{t("patrol.metrics.if.pick")}</legend>
          {ifaceNames(d).map((n) => <Check key={n} label={n} checked={selected.includes(n)} onChange={() => toggle(n)} />)}
        </fieldset>
      )}
      {tab === "errors" && <p className="meta">{t("patrol.metrics.err.note")}</p>}
      {specs.map((s) => s.none
        ? <figure key={s.key} className="chart" aria-label={s.title}><figcaption><span className="chart-title">{s.title}</span></figcaption><p className="empty">{t("patrol.metrics.err.none")}</p></figure>
        : <LazyTimeChart key={s.key} title={s.title} unit={s.unit} times={times} series={s.series} thresholds={s.thresholds} marks={marks} syncKey={`patrol-${jobId}`} fileName={`${d.name}-${s.key}`} />)}
    </div>
  );
}
