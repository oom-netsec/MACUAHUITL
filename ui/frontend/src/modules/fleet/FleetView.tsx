import { useEffect, useMemo, useState } from "react";
import { vocab } from "../../lib/vocab";
import type { CapacityResult, CoreAPI, FindResult, HealthResult, InventoryResult, PathResult, SummaryResult, TraceResult } from "../../lib/core";
import { Field, Notice } from "../../components/Field";
import { EmptyState, Page, ResultPanel, Tabs, useResult } from "../../components/Page";
import { useLang, useT } from "../../lib/i18n";
import { useInbox } from "../../app/activity";
import { formatDateTime } from "../../components/Data";
import { DataTable, type Column } from "../../components/DataTable";
import { HopChain } from "./HopChain";
import { Heatmap, type Level } from "./Heatmap";
import { healthMatrix, summaryMatrix } from "./heat";
import "./fleet.css";

const subs = ["result", "trace", "path", "health", "summary", "capacity", "inventory"] as const;
type Sub = (typeof subs)[number];

// Antigüedad de la evidencia: el dato viejo se nota.
type T = ReturnType<typeof useT>;
export function age(at: string, t: T, now = Date.now()): string {
  const ms = now - Date.parse(at);
  if (!Number.isFinite(ms)) return t("fleet.age.unknown");
  const m = Math.floor(ms / 60000);
  if (m < 1) return t("fleet.age.now");
  if (m < 60) return t("fleet.age.min", { n: m });
  if (m < 2880) return t("fleet.age.h", { n: Math.floor(m / 60) });
  return t("fleet.age.d", { n: Math.floor(m / 1440) });
}

function When({ at, source }: { at: string; source?: string }) {
  const t = useT();
  const lang = useLang();
  const old = Date.now() - Date.parse(at) > 24 * 3600 * 1000;
  return <span className={old ? "stale" : "meta"} data-stale={old || undefined} title={at}>{source ? `${vocab(t, "source", source)} · ` : ""}{formatDateTime(at, lang)} ({age(at, t)}){old ? ` · ${t("fleet.stale")}` : ""}</span>;
}

function Warnings({ list }: { list: string[] | null | undefined }) {
  const t = useT();
  if (!list?.length) return null;
  return <Notice kind="warn"><ul className="fleet-warnings">{list.map((w, i) => <li key={i}>{t("fleet.warning", { w })}</li>)}</ul></Notice>;
}

const runKbd = <kbd aria-hidden="true">Ctrl ↵</kbd>;
const gib = (n: number) => (n >= 1 << 30 ? `${(n / (1 << 30)).toFixed(1)} GiB` : `${(n / (1 << 20)).toFixed(0)} MiB`);
const dash = (v?: string | number | null) => v ?? "—";
// Anchos de columna de siempre (px) y alto de la tabla según sus filas.
const W = { xs: 64, sm: 100, md: 140, lg: 220 } as const;
const WRAP_ROW = 56; // filas que envuelven el texto: hasta 3 líneas
const tableH = (n: number) => Math.min(420, 40 + 32 * n);
// Cada fila necesita una clave única aunque dos coincidencias sean idénticas.
const keyer = <R,>(rows: R[]) => { const m = new Map(rows.map((r, i) => [r, String(i)])); return (r: R) => m.get(r)!; };
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
const whenText = (at: string, source?: string) => `${source ? `${source} · ` : ""}${at}`;
const srcOf = (t: Parameters<typeof vocab>[0], s?: string) => (s ? vocab(t, "source", s) : s);

// Encabezado de los resultados: el título de la sección y, debajo, qué se está mostrando.
function Caption({ children }: { children: string }) {
  return <p className="meta fleet-caption">{children}</p>;
}

function Found({ core, q, setQ }: { core: CoreAPI; q: string; setQ: (v: string) => void }) {
  const t = useT();
  const f = useResult<FindResult>();
  const search = (e: React.FormEvent) => {
    e.preventDefault();
    if (q.trim()) void f.run(() => core.fleetFind(q.trim()));
  };
  const hits = f.data?.hits ?? [];
  const cols: Column<(typeof hits)[number]>[] = [
    { id: "device", header: t("fleet.col.device"), value: (h) => h.device, width: W.md },
    { id: "port", header: t("fleet.col.port"), value: (h) => dash(h.port ?? h.name), mono: true, width: W.md },
    { id: "vlan", header: "VLAN", value: (h) => dash(h.vlan), mono: true, width: W.xs },
    { id: "mac", header: "MAC", value: (h) => dash(h.mac), mono: true, width: W.md },
    { id: "ip", header: "IP", value: (h) => dash(h.ip), mono: true, width: W.md },
    { id: "kind", header: t("fleet.col.type"), value: (h) => vocab(t, "hit", h.kind), width: W.sm },
    { id: "at", header: t("fleet.col.evidence"), value: (h) => whenText(h.at, srcOf(t, h.source)), render: (h) => <When at={h.at} source={h.source} /> },
  ];
  return (
    <>
      <form role="search" onSubmit={search}>
        <Field label={t("fleet.searchLabel")} hint={t("fleet.searchPlaceholder")} type="search" value={q} onChange={setQ} w="lg" mono />
        <div className="actions">
          <button type="submit" className="primary" disabled={!q.trim() || f.busy} aria-busy={f.busy}>{t("fleet.search")}{runKbd}</button>
        </div>
      </form>
      {f.error && <Notice kind="error">{f.error}</Notice>}
      {!f.data && !f.error && <EmptyState icon="search" title={t("fleet.find.empty")}>{t("fleet.find.prompt")}</EmptyState>}
      {f.data && (
        <ResultPanel title={t("fleet.sub.result")} status={hits.length ? { tone: "info", label: t("fleet.find.count", { n: hits.length }) } : { tone: "warn", label: t("fleet.find.none") }}>
          <Caption>{t("fleet.find.caption", { n: hits.length, q: f.data.query, mode: f.data.mode, d: f.data.devices })}</Caption>
          {hits.length > 0 && <DataTable label={t("fleet.sub.result")} columns={cols} rows={hits} rowKey={keyer(hits)} exportName={t("file.busqueda")} height={tableH(hits.length)} />}
        </ResultPanel>
      )}
      <Warnings list={f.data?.warnings} />
    </>
  );
}

function Trace({ core, initial }: { core: CoreAPI; initial: string }) {
  const t = useT();
  const [q, setQ] = useState(initial);
  const tr = useResult<TraceResult>();
  const r = tr.data;
  const hops = r?.hops ?? [];
  const cols: Column<(typeof hops)[number]>[] = [
    { id: "n", header: "#", value: (h) => hops.indexOf(h) + 1, mono: true, width: W.xs },
    { id: "device", header: t("fleet.col.device"), value: (h) => h.device, width: W.md },
    { id: "port", header: t("fleet.col.port"), value: (h) => h.port, mono: true, width: W.md },
    { id: "vlan", header: "VLAN", value: (h) => dash(h.vlan), mono: true, width: W.xs },
    { id: "neighbor", header: t("fleet.col.neighbor"), value: (h) => (h.neighbor ? `${h.neighbor} ${h.neighbor_port ?? ""}` : dash(h.note)), width: W.md },
    { id: "at", header: t("fleet.col.evidence"), value: (h) => whenText(h.at, srcOf(t, h.source)), render: (h) => <When at={h.at} source={h.source} /> },
  ];
  return (
    <>
      <div className="field-row">
        <Field label={t("fleet.trace.label")} value={q} onChange={setQ} w="lg" mono />
      </div>
      <div className="actions"><button className="primary" disabled={!q.trim() || tr.busy} aria-busy={tr.busy} onClick={() => tr.run(() => core.fleetTrace(q.trim()))}>{t("fleet.trace.btn")}{runKbd}</button></div>
      {tr.error && <Notice kind="error">{tr.error}</Notice>}
      {!r && !tr.error && <EmptyState icon="search" title={t("fleet.trace.empty.title")}>{t("fleet.trace.empty")}</EmptyState>}
      {r && (
        <>
          {r.end === "access" && r.access
            ? <Notice kind="ok">{t("fleet.trace.access", { device: r.access.device, port: r.access.port, vlan: r.access.vlan ?? "—" })}</Notice>
            : <Notice kind="warn">{t("fleet.trace.noAccess", { end: r.end })}</Notice>}
          <ResultPanel title={t("fleet.sub.trace")}>
            <Caption>{t("fleet.trace.caption", { x: `${r.mac ?? r.query}${r.ip ? ` (${r.ip})` : ""}` })}</Caption>
            {hops.length > 0 && <DataTable label={t("fleet.sub.trace")} columns={cols} rows={hops} rowKey={keyer(hops)} exportName={t("file.rastreo")} height={tableH(hops.length)} />}
          </ResultPanel>
          <Warnings list={r.warnings} />
        </>
      )}
    </>
  );
}

function Path({ core }: { core: CoreAPI }) {
  const t = useT();
  const [src, setSrc] = useState("");
  const [dst, setDst] = useState("");
  const p = useResult<{ result: PathResult; svg: string }>();
  const r = p.data?.result;
  const hops = r?.hops ?? [];
  const depth = (id: number): number => { let n = 0; let h = r?.hops?.[id]; while (h && h.parent >= 0) { n++; h = r?.hops?.[h.parent]; } return n; };
  const hopText = (h: (typeof hops)[number]) => `${h.device}${h.via ? ` (${t("fleet.path.via", { via: h.via })}${h.out_if ? ` ${t("fleet.path.outIf", { x: h.out_if })}` : ""}${h.ecmp ? `, ${t("fleet.path.ecmp")}` : ""})` : ""}`;
  const statusText = (h: (typeof hops)[number]) => (h.status === "cut" ? t("fleet.path.cut", { reason: h.reason ?? "" }) : h.status === "arrived" ? t("fleet.path.arrivedStatus", { reason: h.reason ?? "" }) : t("fleet.path.continues"));
  const known = (h: (typeof hops)[number]) => !!h.at && !h.at.startsWith("0001");
  const cols: Column<(typeof hops)[number]>[] = [
    { id: "hop", header: t("fleet.col.hop"), width: 300, value: hopText, render: (h) => (
      <>{Array.from({ length: depth(h.id) }, (_, i) => <span key={i} className="indent" aria-hidden="true" />)}{hopText(h)}</>
    ) },
    { id: "route", header: t("fleet.col.route"), value: (h) => dash(h.route), mono: true, width: W.md },
    { id: "segment", header: t("fleet.col.segment"), mono: true, width: W.lg, value: (h) => (h.segment ? `${h.segment.interface}${h.segment.vlan ? ` VLAN ${h.segment.vlan}` : ""}${(h.segment.l2 ?? []).map((x) => ` > ${x.device} ${x.port}`).join("")}` : "—") },
    { id: "status", header: t("fleet.col.status"), width: W.lg, value: statusText },
    { id: "at", header: t("fleet.col.evidence"), value: (h) => (known(h) ? whenText(h.at, srcOf(t, h.source)) : "—"), render: (h) => (known(h) ? <When at={h.at} source={h.source} /> : "—") },
  ];
  return (
    <>
      <div className="field-row">
        <Field label={t("fleet.path.src")} value={src} onChange={setSrc} w="lg" mono />
        <Field label={t("fleet.path.dst")} value={dst} onChange={setDst} w="lg" mono />
      </div>
      <div className="actions"><button className="primary" disabled={!src.trim() || !dst.trim() || p.busy} aria-busy={p.busy} onClick={() => p.run(() => core.fleetPath(src.trim(), dst.trim()))}>{t("fleet.path.btn")}{runKbd}</button></div>
      {p.error && <Notice kind="error">{p.error}</Notice>}
      {!r && !p.error && <EmptyState icon="search" title={t("fleet.path.empty.title")}>{t("fleet.path.empty")}</EmptyState>}
      {r && (
        <>
          <Notice kind={r.arrived ? "ok" : "warn"}>{t(r.arrived ? "fleet.path.arrived" : "fleet.path.cutMsg")}</Notice>
          {hops.length > 0 && <HopChain hops={hops} />}
          <ResultPanel title={t("fleet.path.hops")}>
            {hops.length > 0 && <DataTable label={t("fleet.path.hops")} columns={cols} rows={hops} rowKey={(h) => String(h.id)} exportName={t("file.camino")} height={tableH(hops.length)} />}
          </ResultPanel>
          {p.data?.svg && <img className="topo" src={"data:image/svg+xml;charset=utf-8," + encodeURIComponent(p.data.svg)} alt={t("fleet.path.graphAlt")} />}
          <Warnings list={r.warnings} />
        </>
      )}
    </>
  );
}

function Health({ core }: { core: CoreAPI }) {
  const t = useT();
  const q = useResult<HealthResult>();
  useEffect(() => { void q.run(() => core.fleetHealth()); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const issues = q.data?.issues ?? [];
  const cols: Column<(typeof issues)[number]>[] = [
    { id: "sev", header: t("fleet.col.severity"), value: (i) => cap(t(`fleet.sev.${i.severity}`)), width: W.sm },
    { id: "device", header: t("fleet.col.device"), value: (i) => i.device, width: W.md },
    { id: "port", header: t("fleet.col.iface"), value: (i) => i.port, mono: true, width: W.md },
    { id: "problems", header: t("fleet.col.problems"), width: 320, wrap: true, value: (i) => i.problems.map((p) => `${vocab(t, "problem", p.kind)}${p.value ? ` ${p.value}` : ""} ${p.evidence}`).join(" · "),
      render: (i) => i.problems.map((p) => <span key={p.kind}>{vocab(t, "problem", p.kind)}{p.value ? ` ${p.value}` : ""} <span className="meta">{p.evidence}</span> </span>) },
    { id: "at", header: t("fleet.col.evidence"), value: (i) => whenText(i.at, srcOf(t, i.source)), render: (i) => <When at={i.at} source={i.source} />, wrap: true },
  ];
  const heat = useMemo(() => healthMatrix(issues), [issues]);
  const sevLevel: Record<string, Level> = { critica: "bad", alta: "warn", media: "info", baja: "low" };
  return (
    <>
      <div className="actions"><button className="primary" disabled={q.busy} aria-busy={q.busy} onClick={() => q.run(() => core.fleetHealth())}>{t("fleet.refresh")}{runKbd}</button></div>
      {q.error && <Notice kind="error">{q.error}</Notice>}
      {q.data && (
        <>
          <ResultPanel title={t("fleet.sub.health")} status={issues.length ? { tone: "warn", label: t("fleet.health.count", { n: issues.length }) } : { tone: "ok", label: t("fleet.health.none") }}>
            <Caption>{t("fleet.health.caption", { n: issues.length })}</Caption>
            {issues.length > 0 && (
              <>
                <Heatmap label={t("fleet.heat.health")} corner={t("fleet.col.device")} rows={heat.rows} cols={heat.cols.map((c) => ({ id: c, label: vocab(t, "problem", c) }))}
                  cell={(r, c) => { const x = heat.cells.get(`${r}|${c}`); return x && { level: sevLevel[x.sev], text: t("fleet.heat.cell", { ports: t("fleet.heat.ports", { n: x.count }), sev: t(`fleet.sev.${x.sev}`) }) }; }}
                  legend={[...(["critica", "alta", "media", "baja"] as const).map((s) => ({ level: sevLevel[s], text: t(`fleet.sev.${s}`) })), { level: "none" as const, text: t("fleet.heat.none") }]} />
                <DataTable label={t("fleet.sub.health")} columns={cols} rows={issues} rowKey={keyer(issues)} exportName={t("file.salud")} height={Math.min(420, 40 + WRAP_ROW * issues.length)} rowHeight={WRAP_ROW} />
              </>
            )}
          </ResultPanel>
          <Warnings list={q.data.warnings} />
        </>
      )}
    </>
  );
}

const checks = ["cpu", "ntp", "reboot", "memory", "flash"] as const;

function Summary({ core }: { core: CoreAPI }) {
  const t = useT();
  const q = useResult<SummaryResult>();
  useEffect(() => { void q.run(() => core.fleetSummary()); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const rows = q.data?.rows ?? [];
  const cols: Column<(typeof rows)[number]>[] = [
    { id: "device", header: t("fleet.col.device"), value: (x) => x.device, width: W.md },
    { id: "check", header: t("fleet.col.alert"), value: (x) => ((checks as readonly string[]).includes(x.check) ? t(`fleet.check.${x.check as (typeof checks)[number]}`) : x.check), width: W.md },
    { id: "value", header: t("fleet.col.value"), value: (x) => x.value, mono: true, width: W.md },
    { id: "detail", header: t("fleet.col.detail"), value: (x) => x.detail ?? "", width: W.lg },
    { id: "at", header: t("fleet.col.dataAge"), value: (x) => whenText(x.at, srcOf(t, x.source)), render: (x) => <When at={x.at} source={x.source} /> },
  ];
  const heat = useMemo(() => summaryMatrix(rows, checks), [rows]);
  return (
    <>
      <div className="actions"><button className="primary" disabled={q.busy} aria-busy={q.busy} onClick={() => q.run(() => core.fleetSummary())}>{t("fleet.refresh")}{runKbd}</button></div>
      {q.error && <Notice kind="error">{q.error}</Notice>}
      {q.data && (
        <>
          <ResultPanel title={t("fleet.summary.caption")} status={rows.length ? { tone: "warn", label: t("fleet.summary.count", { n: rows.length }) } : { tone: "ok", label: t("fleet.summary.none") }}>
            <Caption>{t("fleet.summary.meta", { n: q.data.devices, list: checks.map((k) => `${t(`fleet.checkShort.${k}`)} ${q.data!.checked[k] ?? 0}`).join(" · ") })}</Caption>
            {rows.length > 0 && (
              <>
                <Heatmap label={t("fleet.heat.summary")} corner={t("fleet.col.device")} rows={heat.rows}
                  cols={heat.cols.map((c) => ({ id: c, label: (checks as readonly string[]).includes(c) ? t(`fleet.checkShort.${c as (typeof checks)[number]}`) : c }))}
                  cell={(r, c) => { const v = heat.cells.get(`${r}|${c}`); return v === undefined ? undefined : { level: "warn" as const, text: v }; }}
                  legend={[{ level: "warn", text: t("fleet.heat.alert") }, { level: "none", text: t("fleet.heat.none") }]} />
                <DataTable label={t("fleet.summary.caption")} columns={cols} rows={rows} rowKey={keyer(rows)} exportName={t("file.tablero")} height={tableH(rows.length)} />
              </>
            )}
          </ResultPanel>
          <Warnings list={q.data.warnings} />
        </>
      )}
    </>
  );
}

function Capacity({ core }: { core: CoreAPI }) {
  const t = useT();
  const [need, setNeed] = useState("");
  const q = useResult<CapacityResult>();
  useEffect(() => { void q.run(() => core.fleetCapacity("")); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const flash = q.data?.flash ?? [];
  const dram = q.data?.dram ?? [];
  const flashCols: Column<(typeof flash)[number]>[] = [
    { id: "device", header: t("fleet.col.device"), value: (x) => x.device, width: W.md },
    { id: "fs", header: t("fleet.col.system"), value: (x) => x.fs, mono: true, width: W.sm },
    { id: "free", header: t("fleet.col.free"), value: (x) => x.free, render: (x) => gib(x.free), mono: true, width: W.sm },
    { id: "total", header: t("fleet.col.total"), value: (x) => x.total, render: (x) => gib(x.total), mono: true, width: W.sm },
    { id: "used", header: t("fleet.col.used"), value: (x) => x.used_pct, render: (x) => `${x.used_pct.toFixed(0)} %`, mono: true, width: W.xs },
    { id: "fits", header: t("fleet.col.fits"), value: (x) => (x.fits === undefined ? "—" : t(x.fits ? "fleet.yes" : "fleet.no")), width: W.xs },
    { id: "at", header: t("fleet.col.evidence"), value: (x) => whenText(x.at, `dir ${x.fs}`), render: (x) => <When at={x.at} source={`dir ${x.fs}`} /> },
  ];
  const dramCols: Column<(typeof dram)[number]>[] = [
    { id: "device", header: t("fleet.col.device"), value: (x) => x.device, width: W.md },
    { id: "total", header: t("fleet.col.total"), value: (x) => x.total, render: (x) => gib(x.total), mono: true, width: W.sm },
    { id: "pool", header: t("fleet.col.poolFree"), value: (x) => (x.pool_free ? t("fleet.capacity.poolUsed", { size: gib(x.pool_free), pct: (x.pool_used_pct ?? 0).toFixed(0) }) : "—"), mono: true, width: W.lg },
    { id: "at", header: t("fleet.col.evidence"), value: (x) => whenText(x.at, "show version"), render: (x) => <When at={x.at} source="show version" /> },
  ];
  return (
    <>
      <div className="field-row">
        <Field label={t("fleet.capacity.need")} value={need} onChange={setNeed} w="md" mono />
      </div>
      <div className="actions"><button className="primary" disabled={q.busy} aria-busy={q.busy} onClick={() => q.run(() => core.fleetCapacity(need.trim()))}>{t("fleet.capacity.btn")}{runKbd}</button></div>
      {q.error && <Notice kind="error">{q.error}</Notice>}
      {q.data && (
        <>
          <ResultPanel title="Flash">
            {flash.length > 0 ? <DataTable label="Flash" columns={flashCols} rows={flash} rowKey={keyer(flash)} exportName={t("file.flash")} height={tableH(flash.length)} /> : <div className="panel-body"><p className="meta">{t("fleet.capacity.none")}</p></div>}
          </ResultPanel>
          <ResultPanel title="DRAM">
            {dram.length > 0 ? <DataTable label="DRAM" columns={dramCols} rows={dram} rowKey={keyer(dram)} exportName={t("file.dram")} height={tableH(dram.length)} /> : <div className="panel-body"><p className="meta">{t("fleet.capacity.none")}</p></div>}
          </ResultPanel>
          <Warnings list={q.data.warnings} />
        </>
      )}
    </>
  );
}

function Inventory({ core }: { core: CoreAPI }) {
  const t = useT();
  const q = useResult<{ result: InventoryResult; csv: string; markdown: string }>();
  useEffect(() => { void q.run(() => core.fleetInventory()); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const d = q.data;
  const rows = d?.result.rows ?? [];
  const cols: Column<(typeof rows)[number]>[] = [
    { id: "device", header: t("fleet.col.device"), value: (x) => x.device, width: W.md },
    { id: "kind", header: t("fleet.col.type"), value: (x) => vocab(t, "inv", x.kind), width: W.sm },
    { id: "name", header: t("fleet.col.name"), value: (x) => dash(x.name), width: W.md },
    { id: "pid", header: "PID", value: (x) => dash(x.pid), mono: true, width: W.md },
    { id: "serial", header: t("fleet.col.serial"), value: (x) => dash(x.serial), mono: true, width: W.md },
    { id: "model", header: t("fleet.col.model"), value: (x) => dash(x.model), mono: true, width: W.md },
    { id: "version", header: t("fleet.col.version"), value: (x) => dash(x.version), mono: true, width: W.sm },
    { id: "at", header: t("fleet.col.evidence"), value: (x) => whenText(x.at, srcOf(t, x.source)), render: (x) => <When at={x.at} source={x.source} /> },
  ];
  return (
    <>
      {q.error && <Notice kind="error">{q.error}</Notice>}
      {d && (
        <>
          <ResultPanel title={t("fleet.sub.inventory")}
            actions={<>
              <a href={"data:text/csv;charset=utf-8," + encodeURIComponent(d.csv)} download={`${t("file.inventario")}.csv`}>{t("fleet.inv.csv")}</a>
              <a href={"data:text/markdown;charset=utf-8," + encodeURIComponent(d.markdown)} download={`${t("file.inventario")}.md`}>{t("fleet.inv.md")}</a>
            </>}>
            <Caption>{t("fleet.inv.caption", { n: rows.length, d: d.result.devices })}</Caption>
            {rows.length > 0 && <DataTable label={t("fleet.sub.inventory")} columns={cols} rows={rows} rowKey={keyer(rows)} exportName={t("file.inventario")} height={tableH(rows.length)} />}
          </ResultPanel>
          <Warnings list={d.result.warnings} />
        </>
      )}
    </>
  );
}

export function FleetView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sub, setSub] = useState<Sub>("result");
  const [q, setQ] = useState(""); // lo buscado también precarga el rastreo L2
  useInbox("fleet", (d) => { setQ(d); setSub("result"); }); // desde el menú de equipo
  return (
    <Page title={t("fleet.title")} description={t("fleet.intro")}
      tabs={<Tabs label={t("fleet.nav")} value={sub} onChange={setSub} tabs={subs.map((s) => [s, t(`fleet.sub.${s}`)])} />}>
      {sub === "result" && <Found core={core} q={q} setQ={setQ} />}
      {sub === "trace" && <Trace core={core} initial={q} />}
      {sub === "path" && <Path core={core} />}
      {sub === "health" && <Health core={core} />}
      {sub === "summary" && <Summary core={core} />}
      {sub === "capacity" && <Capacity core={core} />}
      {sub === "inventory" && <Inventory core={core} />}
    </Page>
  );
}
