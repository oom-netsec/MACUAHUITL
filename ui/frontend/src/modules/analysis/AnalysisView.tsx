import { useState, type ReactNode } from "react";
import { Terminal } from "../../components/Terminal";
import { CopyButton, RelativeTime } from "../../components/Data";
import { DataTable, type Column } from "../../components/DataTable";
import { ExportMenu } from "../../components/Files";
import { tableCsv, tableMarkdown } from "../../lib/tableExport";
import type { AnalysisReport, AnalysisWarning, CoreAPI, DiffReport, Severity, TimelineEvent, TimelineReport } from "../../lib/core";
import { Field, Notice } from "../../components/Field";
import { EmptyState, Page, ResultPanel, Section, Tabs, useResult } from "../../components/Page";
import { useNav } from "../../app/activity";
import { useT } from "../../lib/i18n";
import { vocab } from "../../lib/vocab";
import type { Key } from "../../lib/i18n/es";
import "./analysis.css";

type Sub = "findings" | "diff" | "timeline";
const subs: [Sub, Key][] = [["findings", "analysis.sub.findings"], ["diff", "analysis.sub.diff"], ["timeline", "analysis.sub.timeline"]];
const sevs: [Severity, Key][] = [["critica", "analysis.sev.critica"], ["alta", "analysis.sev.alta"], ["media", "analysis.sev.media"], ["baja", "analysis.sev.baja"], ["info", "analysis.sev.info"]];
const sevName = Object.fromEntries(sevs) as Record<Severity, Key>;

const runKbd = <kbd aria-hidden="true">Ctrl ↵</kbd>;

// Antes de la primera consulta: las corridas salen de un trabajo de Patrol terminado.
function NoRun() {
  const t = useT();
  const go = useNav();
  return (
    <EmptyState icon="layers" title={t("analysis.empty.title")} action={<button className="sm" onClick={() => go("patrol")}>{t("analysis.empty.patrol")}</button>}>
      {t("analysis.empty")}
    </EmptyState>
  );
}

function Warnings({ list }: { list: AnalysisWarning[] | null }) {
  const t = useT();
  if (!list?.length) return null;
  return (
    <Notice kind="warn">
      <ul className="warnings">
        {list.map((w, i) => <li key={i}>{t("analysis.warning", { text: [w.device, w.round ? t("analysis.roundN", { n: w.round }) : "", w.command].filter(Boolean).join(" · ") + (w.device || w.command ? ": " : "") + w.msg })}</li>)}
      </ul>
    </Notice>
  );
}

function Findings({ core, job, device, head }: { core: CoreAPI; job: string; device: string; head: ReactNode }) {
  const t = useT();
  const [round, setRound] = useState("0");
  const q = useResult<AnalysisReport>();
  const r = q.data;
  const exportHead = [t("analysis.col.sev"), t("analysis.tl.device"), t("analysis.col.round"), t("analysis.col.title"), t("analysis.col.rule"), t("analysis.col.detail"), t("analysis.col.command"), t("analysis.col.action")];
  const exportRows = () => (r?.findings ?? []).map((x) => [t(sevName[x.severity]), x.device, String(x.round), x.title, x.rule, x.detail, x.command, x.action]);
  return (
    <>
      <Section title={t("analysis.section.run")}>
        {head}
        <div className="field-row">
          <Field label={t("analysis.round")} type="number" value={round} onChange={setRound} w="sm" />
        </div>
      </Section>
      <div className="actions"><button className="primary" disabled={!job || q.busy} aria-busy={q.busy} onClick={() => q.run(() => core.analysisRun(job, Number(round) || 0, device))}>{t("analysis.run")}{runKbd}</button></div>
      {q.error && <Notice kind="error">{q.error}</Notice>}
      {!r && !q.error && <NoRun />}
      {r && (
        <ResultPanel title={t("analysis.sub.findings")} status={r.findings.length ? { tone: "warn", label: t("analysis.count", { n: r.findings.length }) } : { tone: "ok", label: t("analysis.noFindings") }}
          actions={r.findings.length > 0 && <ExportMenu name={t("file.hallazgos")} formats={[{ fmt: "csv", data: () => tableCsv(exportHead, exportRows()) }, { fmt: "md", data: () => tableMarkdown(exportHead, exportRows()) }]} />}>
          <div className="panel-body">
            <p className="meta">{t("analysis.summary", { dir: r.dir, devices: (r.devices ?? []).join(", ") || t("analysis.noDevices"), rounds: (r.rounds ?? []).join(", "), n: r.findings.length })}</p>
            {sevs.map(([sev, k]) => {
              const label = t(k);
              const list = r.findings.filter((x) => x.severity === sev);
              if (!list.length) return null;
              return (
                <section key={sev} aria-label={`${label} (${list.length})`} className="sev" data-sev={sev}>
                  <h4>{label} ({list.length})</h4>
                  {list.map((x, i) => (
                    <details key={i} className="finding">
                      <summary>{t("analysis.finding", { title: x.title, device: x.device, round: x.round, detail: x.detail })}</summary>
                      <p className="meta">{x.rule} · {x.at} · <code>{x.command}</code><CopyButton value={x.command} label={x.command} /></p>
                      <Terminal text={x.evidence.join("\n")} />
                      <p><strong>{t("analysis.why")}</strong> {x.explanation}</p>
                      <p><strong>{t("analysis.what")}</strong> {x.action}</p>
                    </details>
                  ))}
                </section>
              );
            })}
            {r.missing.length > 0 && <p className="meta">{t("analysis.missing", { list: r.missing.join(", ") })}</p>}
            <Warnings list={r.warnings} />
          </div>
        </ResultPanel>
      )}
    </>
  );
}

function Diff({ core, job, device, head }: { core: CoreAPI; job: string; device: string; head: ReactNode }) {
  const t = useT();
  const [from, setFrom] = useState("1");
  const [to, setTo] = useState("2");
  const q = useResult<DiffReport>();
  return (
    <>
      <Section title={t("analysis.section.run")}>
        {head}
        <div className="field-row">
          <Field label={t("analysis.roundA")} type="number" value={from} onChange={setFrom} w="sm" />
          <Field label={t("analysis.roundB")} type="number" value={to} onChange={setTo} w="sm" />
        </div>
      </Section>
      <div className="actions"><button className="primary" disabled={!job || q.busy} aria-busy={q.busy} onClick={() => q.run(() => core.analysisDiff(job, Number(from), Number(to), device))}>{t("analysis.compare")}{runKbd}</button></div>
      {q.error && <Notice kind="error">{q.error}</Notice>}
      {!q.data && !q.error && <NoRun />}
      {q.data?.devices.map((d) => (
        <ResultPanel key={d.device} title={d.device}>
          <div className="panel-body">
            {d.uptime && (d.uptime.reset
              ? <Notice kind="warn">{t("analysis.reloaded", { from: d.uptime.from, to: d.uptime.to })}</Notice>
              : <p className="meta">{t("analysis.uptime", { from: d.uptime.from, to: d.uptime.to })}</p>)}
            {d.counters.length > 0 && (
              <h4>{t("analysis.counters")}</h4>
            )}
            {d.counters.length > 0 && (
              <div className="table-wrap diff-counters">
                <table aria-label={t("analysis.counters")}>
                  <thead><tr><th>{t("analysis.col.iface")}</th><th>{t("analysis.col.counter")}</th><th>{t("analysis.roundA")}</th><th>{t("analysis.roundB")}</th><th>{t("analysis.col.change")}</th></tr></thead>
                  <tbody>
                    {d.counters.map((c, i) => (
                      <tr key={i}><td className="mono">{c.interface}</td><td>{c.counter}</td><td className="mono">{c.from}</td><td className="mono">{c.to}</td><td className="mono">{c.delta > 0 ? `+${c.delta}` : c.delta}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {d.neighbors.length > 0 && (
              <ul>{d.neighbors.map((n, i) => <li key={i}>{n.protocol.toUpperCase()} {n.id} {n.change}{n.from || n.to ? ` (${[n.from, n.to].filter(Boolean).join(" → ")})` : ""}</li>)}</ul>
            )}
            {d.prefixes.length > 0 && (
              <ul>{d.prefixes.map((p, i) => <li key={i}>{t("analysis.prefixes", { neighbor: p.neighbor, from: p.from, to: p.to })}</li>)}</ul>
            )}
            {d.text.map((x, i) => (
              <details key={i}>
                <summary><code>{x.command}</code>{x.note ? ` — ${x.note}` : ` — ${t("analysis.linesN", { n: x.lines.length })}`}</summary>
                {x.lines.length > 0 && <Terminal text={x.lines.join("\n")} />}
              </details>
            ))}
          </div>
        </ResultPanel>
      ))}
      {q.data && q.data.devices.length === 0 && <Notice kind="info">{t("analysis.noDiffDevices")}</Notice>}
      <Warnings list={q.data?.warnings ?? null} />
    </>
  );
}

function Timeline({ core, job, device, head }: { core: CoreAPI; job: string; device: string; head: ReactNode }) {
  const t = useT();
  const [around, setAround] = useState("");
  const [win, setWin] = useState("30");
  const [pcap, setPcap] = useState("");
  const q = useResult<TimelineReport>();
  const load = (at: string) => q.run(() => core.analysisTimeline(job, at, Number(win) || 30, device, pcap));
  const focus = (at: string) => { setAround(at); load(at); };
  const w = Number(win) || 30;
  const cols = (events: TimelineEvent[]): Column<TimelineEvent>[] => [
    { id: "at", header: t("analysis.tl.time"), width: 350, value: (e) => Date.parse(e.at) || 0, mono: true,
      render: (e) => <>{e.at} <span className="meta">(<RelativeTime iso={e.at} />)</span></> },
    { id: "source", header: t("analysis.tl.source"), width: 120, value: (e) => vocab(t, "source", e.source) },
    { id: "device", header: t("analysis.tl.device"), width: 160, value: (e) => e.device ?? "—", mono: true },
    { id: "event", header: t("analysis.tl.event"), value: (e) => `${e.severity ? `[${t(sevName[e.severity])}] ` : ""}${e.text}${e.note ? ` (${e.note})` : ""}${e.kb ? ` [${t("analysis.tl.kb", { kb: e.kb })}]` : ""}`,
      render: (e) => <span data-sev={e.severity}>{e.severity ? `[${t(sevName[e.severity])}] ` : ""}{e.text}{e.note && <span className="meta"> ({e.note})</span>}{e.kb && <span className="meta"> [{t("analysis.tl.kb", { kb: e.kb })}]</span>}</span> },
    { id: "around", header: t("analysis.tl.correlate"), width: 110, value: (e) => events.indexOf(e),
      render: (e) => <button className="quiet sm" onClick={() => focus(e.at)} aria-label={t("analysis.tl.aroundAria", { w, at: e.at })}>{t("analysis.tl.aroundBtn", { w })}</button> },
  ];
  const keyOf = (events: TimelineEvent[]) => (e: TimelineEvent) => String(events.indexOf(e));
  return (
    <>
      <Section title={t("analysis.section.run")}>
        {head}
        <div className="field-row">
          <Field label={t("analysis.around")} value={around} onChange={setAround} w="lg" mono />
          <Field label={t("analysis.window")} type="number" value={win} onChange={setWin} w="sm" />
        </div>
        <Field label={t("analysis.tl.pcap")} hint={t("analysis.tl.note")} value={pcap} onChange={setPcap} w="full" mono />
      </Section>
      <div className="actions"><button className="primary" disabled={!job || q.busy} aria-busy={q.busy} onClick={() => load(around)}>{t("analysis.tl.view")}{runKbd}</button></div>
      {q.error && <Notice kind="error">{q.error}</Notice>}
      {!q.data && !q.error && <NoRun />}
      {q.data && (
        <ResultPanel title={t("analysis.sub.timeline")} meta={`${t("analysis.tl.caption", { n: q.data.events.length })}${q.data.around ? ` · ${q.data.around} ± ${q.data.window}` : ""}`}>
          <DataTable label={t("analysis.sub.timeline")} columns={cols(q.data.events)} rows={q.data.events} rowKey={keyOf(q.data.events)} exportName={t("file.linea-de-tiempo")}
            height={Math.min(520, 40 + 32 * q.data.events.length)} />
        </ResultPanel>
      )}
      <Warnings list={q.data?.warnings ?? null} />
    </>
  );
}

export function AnalysisView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sub, setSub] = useState<Sub>("findings");
  const [job, setJob] = useState("");
  const [device, setDevice] = useState("");
  const head = (
    <div className="field-row">
      <Field label={t("analysis.job")} value={job} onChange={setJob} w="lg" mono />
      <Field label={t("analysis.device")} value={device} onChange={setDevice} w="md" mono />
    </div>
  );
  return (
    <Page title={t("analysis.title")} description={t("analysis.desc")}
      tabs={<Tabs label={t("analysis.view")} value={sub} onChange={setSub} tabs={subs.map(([s, k]) => [s, t(k)])} />}>
      {sub === "findings" && <Findings core={core} job={job} device={device} head={head} />}
      {sub === "diff" && <Diff core={core} job={job} device={device} head={head} />}
      {sub === "timeline" && <Timeline core={core} job={job} device={device} head={head} />}
    </Page>
  );
}
