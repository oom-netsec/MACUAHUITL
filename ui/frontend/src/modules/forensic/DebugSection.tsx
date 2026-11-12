import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Field, Notice, TextArea } from "../../components/Field";
import { ResultPanel, Section, useResult } from "../../components/Page";
import { Terminal } from "../../components/Terminal";
import { useT } from "../../lib/i18n";
import type { DebugGroup, DebugReport } from "./api";
import { FirstRun, Intro, Warnings, runKbd } from "./shared";
import { DataTable, type Column } from "../../components/DataTable";

// Filtro de debugs: agrupa las líneas repetidas, oculta el ruido y marca las anomalías. Solo texto o archivo: sin conexión en vivo.
export function DebugSection({ core }: { core: CoreAPI }) {
  const t = useT();
  const [text, setText] = useState("");
  const [path, setPath] = useState("");
  const [noise, setNoise] = useState("");
  const [famMin, setFamMin] = useState("20");
  const [rareMax, setRareMax] = useState("2");
  const q = useResult<DebugReport>();
  const rep = q.data;
  const run = () => {
    const terms = noise.split("\n").map((l) => l.trim()).filter(Boolean);
    return q.run(() => core.forensicDebugs(path.trim() ? "" : text, path.trim(), terms, Number(famMin) || 0, Number(rareMax) || 0, 0));
  };
  const cols: Column<DebugGroup>[] = [
    { id: "count", header: t("forensic.debug.times"), value: (g) => g.count, mono: true, width: 100 },
    { id: "pattern", header: t("forensic.debug.pattern"), value: (g) => g.pattern, mono: true },
  ];
  return (
    <>
      <Intro text={t("forensic.debug.intro")} />
      <Section title={t("forensic.section.input")}>
        <TextArea label={t("forensic.debug.text")} value={text} onChange={setText} rows={10} />
        <div className="field-row">
          <Field label={t("forensic.orPath")} value={path} onChange={setPath} w="full" mono />
        </div>
      </Section>
      <Section title={t("forensic.section.filters")}>
        <TextArea label={t("forensic.debug.noise")} value={noise} onChange={setNoise} rows={3} />
        <div className="field-row">
          <Field label={t("forensic.debug.famMin")} type="number" value={famMin} onChange={setFamMin} w="sm" />
          <Field label={t("forensic.debug.rareMax")} type="number" value={rareMax} onChange={setRareMax} w="sm" />
        </div>
      </Section>
      <div className="actions"><button className="primary" disabled={(!text.trim() && !path.trim()) || q.busy} aria-busy={q.busy} onClick={run}>{t("forensic.debug.btn")}{runKbd}</button></div>
      {q.error && <Notice kind="error">{q.error}</Notice>}
      {!rep && !q.error && <FirstRun what="forensic.empty.debug" />}
      {rep && (
        <>
          <p className="meta">{t("forensic.debug.summary", { lines: rep.lines, hidden: rep.hidden, blank: rep.blank, groups: rep.groups_total })}</p>
          <Warnings list={rep.warnings} />
          <ResultPanel title={t("forensic.debug.anomalies")}>
            <div className="panel-body">
              {rep.anomalies.length === 0 ? <p className="meta">{t("forensic.debug.noAnomalies")}</p> : (
                <ul className="forensic-anomalies">
                  {rep.anomalies.map((a) => (
                    <li key={a.line}>
                      <p><strong>{t("forensic.debug.line", { n: a.line })}</strong> — {a.reason}:</p>
                      <Terminal text={a.text} />
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </ResultPanel>
          {rep.groups.length > 0 && (
            <ResultPanel title={t("forensic.debug.caption")}>
              <DataTable label={t("forensic.debug.caption")} columns={cols} rows={rep.groups} rowKey={(g) => g.pattern} exportName={t("file.debug-patrones")} height={Math.min(420, 40 + 32 * rep.groups.length)} />
            </ResultPanel>
          )}
        </>
      )}
    </>
  );
}
