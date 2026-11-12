import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Field, Notice, TextArea } from "../../components/Field";
import { ResultPanel, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { CrashReport } from "./api";
import { FirstRun, Intro, MsgCard, Warnings, runKbd } from "./shared";

// Analizador de crashinfo de IOS e IOS-XE (texto). Un core binario solo se identifica.
export function CrashSection({ core }: { core: CoreAPI }) {
  const t = useT();
  const [text, setText] = useState("");
  const [path, setPath] = useState("");
  const q = useResult<CrashReport>();
  const rep = q.data;
  const row = (k: string, v?: string | number) => (v ? <tr><th scope="row">{k}</th><td className="mono">{v}</td></tr> : null);
  return (
    <>
      <Intro text={t("forensic.crash.intro")} />
      <TextArea label={t("forensic.crash.text")} value={text} onChange={setText} rows={10} />
      <div className="field-row">
        <Field label={t("forensic.orPath")} value={path} onChange={setPath} w="full" mono />
      </div>
      <div className="actions">
        <button className="primary" disabled={(!text.trim() && !path.trim()) || q.busy} aria-busy={q.busy}
          onClick={() => q.run(() => core.forensicCrashinfo(path.trim() ? "" : text, path.trim()))}>{t("forensic.crash.btn")}{runKbd}</button>
      </div>
      {q.error && <Notice kind="error">{q.error}</Notice>}
      {!rep && !q.error && <FirstRun what="forensic.empty.crash" />}
      {rep && (
        <>
          {rep.hint && <Notice kind="warn">{rep.hint}</Notice>}
          {rep.truncated && <Notice kind="warn">{t("forensic.crash.truncated")}</Notice>}
          <Warnings list={rep.warnings} />
          {rep.kind === "crashinfo" && (
            <ResultPanel title={t("forensic.crash.summary")}>
              <div className="table-wrap forensic-kv">
                <table aria-label={t("forensic.crash.summary")}>
                  <tbody>
                    {row(t("forensic.crash.reason"), rep.reason)}
                    {row("PC", rep.pc)}
                    {row(t("forensic.crash.process"), rep.process ? `${rep.process}${rep.pid ? ` (pid ${rep.pid})` : ""}` : "")}
                    {row(t("forensic.crash.host"), [rep.host, rep.model].filter(Boolean).join(" "))}
                    {row(t("forensic.crash.version"), rep.version)}
                    {row(t("forensic.crash.uptime"), rep.uptime)}
                    {row("Traceback", rep.traceback?.join(" "))}
                    {row(t("forensic.crash.cpu"), rep.cpu ? `${rep.cpu.five_sec}% (5 s), ${rep.cpu.one_min}% (1 min), ${rep.cpu.five_min}% (5 min)` : "")}
                    {row(t("forensic.crash.mem"), rep.memory ? t("forensic.crash.memFree", { pct: rep.memory.free_pct.toFixed(1) }) : "")}
                  </tbody>
                </table>
              </div>
            </ResultPanel>
          )}
          {rep.messages.map((m) => <MsgCard key={m.id} e={m} />)}
        </>
      )}
    </>
  );
}
