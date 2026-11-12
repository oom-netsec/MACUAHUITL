import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Field, Notice } from "../../components/Field";
import { ResultPanel, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { LeakRow, LeaksReport } from "./api";
import { FirstRun, Intro, Warnings, runKbd } from "./shared";
import { DataTable, type Column } from "../../components/DataTable";
import { Sparkline } from "../../components/charts/Mini";

const mib = (b: number) => `${(b / (1 << 20)).toFixed(1)} MiB`;

// Fugas de memoria por proceso: show processes memory sorted entre las rondas de un trabajo de Patrol.
export function LeakSection({ core }: { core: CoreAPI }) {
  const t = useT();
  const [job, setJob] = useState("");
  const [device, setDevice] = useState("");
  const [rounds, setRounds] = useState("3");
  const [growth, setGrowth] = useState("1024");
  const q = useResult<LeaksReport>();
  const rep = q.data;
  const cols: Column<LeakRow>[] = [
    { id: "host", header: t("forensic.leak.col.host"), value: (l) => l.host, mono: true, width: 190 },
    { id: "process", header: t("forensic.leak.col.process"), value: (l) => `${l.process} ${t("forensic.leak.pid", { pid: l.pid })}`, render: (l) => <>{l.process} <span className="meta">{t("forensic.leak.pid", { pid: l.pid })}</span></>, width: 170 },
    { id: "rounds", header: t("forensic.leak.col.rounds"), value: (l) => `${l.from_round} → ${l.to_round}`, mono: true, width: 100 },
    { id: "growth", header: t("forensic.leak.col.growth"), value: (l) => l.growth, render: (l) => `+${mib(l.growth)}`, mono: true, width: 110 },
    { id: "perHour", header: t("forensic.leak.col.perHour"), value: (l) => l.per_hour ?? 0, render: (l) => (l.per_hour ? mib(l.per_hour) : "—"), mono: true, width: 110 },
    // Curva por ronda: la serie no trae hora, solo el número de ronda.
    { id: "curve", header: t("forensic.leak.col.curve"), value: (l) => l.growth, render: (l) => <Sparkline values={l.series.map((v) => v / (1 << 20))} label={`${l.process} ${t("forensic.leak.pid", { pid: l.pid })}`} unit="MiB" width={120} />, width: 150 },
    { id: "series", header: t("forensic.leak.col.series"), value: (l) => l.series.map(mib).join(" → "), render: (l) => <code>{l.series.map(mib).join(" → ")}</code> },
  ];
  return (
    <>
      <Intro text={t("forensic.leak.intro")} />
      <div className="field-row">
        <Field label={t("forensic.leak.job")} value={job} onChange={setJob} w="lg" mono />
        <Field label={t("forensic.leak.device")} value={device} onChange={setDevice} w="md" mono />
      </div>
      <div className="field-row">
        <Field label={t("forensic.leak.rounds")} type="number" value={rounds} onChange={setRounds} w="sm" />
        <Field label={t("forensic.leak.growth")} type="number" value={growth} onChange={setGrowth} w="sm" />
      </div>
      <div className="actions">
        <button className="primary" disabled={!job.trim() || q.busy} aria-busy={q.busy}
          onClick={() => q.run(() => core.forensicLeaks(job.trim(), device.trim(), Number(rounds) || 0, Number(growth) || 0))}>{t("forensic.leak.btn")}{runKbd}</button>
      </div>
      {q.error && <Notice kind="error">{q.error}</Notice>}
      {!rep && !q.error && <FirstRun what="forensic.empty.leak" />}
      {rep && (
        <>
          <p className="meta">{t("forensic.leak.summary", { n: rep.processes })}</p>
          <Warnings list={rep.warnings} />
          {rep.leaks.length === 0 ? <Notice kind="info">{t("forensic.leak.none")}</Notice> : (
            <ResultPanel title={t("forensic.leak.caption")}>
              <DataTable label={t("forensic.leak.caption")} columns={cols} rows={rep.leaks} rowKey={(l) => `${l.host}|${l.process}|${l.pid}`} exportName={t("file.memoria")} height={Math.min(420, 40 + 32 * rep.leaks.length)} />
            </ResultPanel>
          )}
        </>
      )}
    </>
  );
}
