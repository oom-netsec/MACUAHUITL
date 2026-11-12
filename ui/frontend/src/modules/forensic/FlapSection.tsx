import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Field, Notice } from "../../components/Field";
import { ResultPanel, Section, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { CounterJump, FlapRow, FlappingReport } from "./api";
import { FirstRun, Intro, SourcePicker, Warnings, emptySource, runKbd, toSource, type SourceState } from "./shared";
import { DataTable, type Column } from "../../components/DataTable";
import { FlapLanes } from "./FlapLanes";

// Detector de flapping: transiciones de interfaz en una ventana corta (aunque cada caída dure milisegundos) y,
// con un trabajo de Patrol, saltos de los contadores de show interfaces entre rondas.
export function FlapSection({ core }: { core: CoreAPI }) {
  const t = useT();
  const [src, setSrc] = useState<SourceState>({ ...emptySource, kind: "job" });
  const [count, setCount] = useState("3");
  const [win, setWin] = useState("60");
  const [delta, setDelta] = useState("3");
  const q = useResult<FlappingReport>();
  const rep = q.data;
  const source = toSource(src);
  const run = () => { if (source) void q.run(() => core.forensicFlapping(source, Number(count) || 0, Number(win) || 0, Number(delta) || 0)); };
  const flapCols: Column<FlapRow>[] = [
    { id: "host", header: t("forensic.flap.col.host"), value: (f) => f.host || "—", mono: true, width: 220 },
    { id: "iface", header: t("forensic.flap.col.iface"), value: (f) => f.interface, mono: true, width: 140 },
    { id: "peak", header: t("forensic.flap.col.peak"), value: (f) => (f.no_time ? t("forensic.flap.noTime") : f.peak), mono: true, width: 170 },
    { id: "total", header: t("forensic.flap.col.total"), value: (f) => f.total, mono: true, width: 80 },
    { id: "seq", header: t("forensic.flap.col.sequence"), value: (f) => f.sequence, render: (f) => <code>{f.sequence}</code>, width: 220 },
    { id: "action", header: t("forensic.flap.col.action"), value: (f) => (f.mnemonic && rep?.kb?.[f.mnemonic]?.action) || "" },
  ];
  const jumpCols: Column<CounterJump>[] = [
    { id: "host", header: t("forensic.flap.col.host"), value: (j) => j.host, mono: true, width: 220 },
    { id: "iface", header: t("forensic.flap.col.iface"), value: (j) => j.interface, mono: true, width: 140 },
    { id: "counter", header: t("forensic.flap.col.counter"), value: (j) => j.counter, width: 140 },
    { id: "rounds", header: t("forensic.flap.col.rounds"), value: (j) => `${j.from_round} → ${j.to_round}`, mono: true, width: 100 },
    { id: "change", header: t("forensic.flap.col.change"), value: (j) => `${j.from} → ${j.to} (+${j.delta})`, mono: true, width: 160 },
    { id: "perHour", header: t("forensic.flap.col.perHour"), value: (j) => (j.per_hour ? j.per_hour.toFixed(1) : "—"), mono: true },
  ];
  return (
    <>
      <Intro text={t("forensic.flap.intro")} />
      <Section title={t("forensic.section.source")}>
        <SourcePicker value={src} onChange={setSrc} />
      </Section>
      <Section title={t("forensic.section.thresholds")}>
        <div className="field-row">
          <Field label={t("forensic.flap.count")} type="number" value={count} onChange={setCount} w="sm" />
          <Field label={t("forensic.flap.win")} type="number" value={win} onChange={setWin} w="sm" />
          <Field label={t("forensic.flap.delta")} type="number" value={delta} onChange={setDelta} w="sm" />
        </div>
      </Section>
      <div className="actions"><button className="primary" disabled={!source || q.busy} aria-busy={q.busy} onClick={run}>{t("forensic.flap.btn")}{runKbd}</button></div>
      {q.error && <Notice kind="error">{q.error}</Notice>}
      {!rep && !q.error && <FirstRun what="forensic.empty.flap" />}
      {rep && (
        <>
          <p className="meta">{t("forensic.flap.summary", { n: rep.interfaces, tr: rep.transitions, src: rep.source })}</p>
          <Warnings list={rep.warnings} />
          {rep.flaps.length === 0 ? <Notice kind="info">{t("forensic.flap.none")}</Notice> : (
            <ResultPanel title={t("forensic.flap.caption")}>
              <FlapLanes flaps={rep.flaps} />
              <DataTable label={t("forensic.flap.caption")} columns={flapCols} rows={rep.flaps} rowKey={(f) => `${f.host}|${f.interface}|${f.layer}`} exportName={t("file.flapping")} height={Math.min(420, 40 + 32 * rep.flaps.length)} />
            </ResultPanel>
          )}
          {rep.counter_jumps.length > 0 && (
            <ResultPanel title={t("forensic.flap.jumps")}>
              <DataTable label={t("forensic.flap.jumps")} columns={jumpCols} rows={rep.counter_jumps} rowKey={(j) => `${j.host}|${j.interface}|${j.counter}|${j.from_round}`} exportName={t("file.saltos")} height={Math.min(420, 40 + 32 * rep.counter_jumps.length)} />
            </ResultPanel>
          )}
        </>
      )}
    </>
  );
}
