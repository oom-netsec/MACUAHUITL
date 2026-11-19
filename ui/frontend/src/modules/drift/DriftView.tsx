import { Advanced } from "../../components/Advanced";
import { RunButton } from "../../components/RunButton";
import { useState } from "react";
import { showHidden } from "../../lib/safeText";
import type { CoreAPI, DriftReport } from "../../lib/core";
import { Field, Notice } from "../../components/Field";
import { EmptyState, Page, ResultPanel, Warnings, useResult } from "../../components/Page";
import { Hl, Terminal } from "../../components/Terminal";
import { useNav } from "../../app/activity";
import { useT } from "../../lib/i18n";
import "./drift.css";

// Deriva: running-config de la ronda N contra la anterior, por equipo. Solo lee la carpeta del trabajo.
export function DriftView({ core }: { core: CoreAPI }) {
  const t = useT();
  const go = useNav();
  const [job, setJob] = useState("");
  const [round, setRound] = useState("0");
  const [device, setDevice] = useState("");
  const q = useResult<DriftReport>();
  const rep = q.data;

  return (
    <Page title={t("drift.title")} description={t("drift.intro")}>
      <div className="field-row">
        <Field label={t("drift.job")} value={job} onChange={setJob} w="lg" mono />
      </div>
      <Advanced changed={Number(round !== "0") + Number(device !== "")}>
        <div className="field-row">
          <Field label={t("drift.round")} type="number" value={round} onChange={setRound} w="sm" />
          <Field label={t("drift.device")} value={device} onChange={setDevice} w="md" mono />
        </div>
      </Advanced>
      <div className="actions">
        <RunButton primary kbd busy={q.busy} missing={[!job.trim() && t("need.job")]}
          onClick={() => q.run(() => core.driftRun(job.trim(), Number(round) || 0, device.trim()))}>{t("drift.btn")}</RunButton>
      </div>
      {q.error && <Notice kind="error">{q.error}</Notice>}
      {!rep && !q.error && (
        <EmptyState icon="layers" title={t("drift.empty.title")} action={<button className="sm" onClick={() => go("patrol")}>{t("drift.empty.patrol")}</button>}>
          {t("drift.empty")}
        </EmptyState>
      )}
      {rep && (
        <>
          {rep.masked && <Notice kind="warn">{t("drift.masked")}</Notice>}
          {rep.unmasked && <Notice kind="warn">{t("evidence.unmasked")}</Notice>}
          {rep.devices.map((d) => (
            <ResultPanel key={d.device} title={showHidden(d.device)} meta={t("drift.rounds", { to: d.to, from: d.from })}
              status={d.changes.length ? { tone: "warn", label: t("drift.status.changed") } : { tone: "ok", label: t("drift.none") }}>
              {(d.changes.length > 0 || d.ignored.length > 0) && (
                <div className="panel-body">
                  {d.changes.length > 0 && (
                    <>
                      <p>{t("drift.changes", { n: d.changes.length, added: d.added, removed: d.removed })}</p>
                      <div className="drift-changes">
                        <Terminal as="ul" aria-label={t("drift.changes.aria", { device: d.device })}>
                          {d.changes.map((c, i) => (
                            <li key={i} data-op={c.op}><Hl text={`${c.op} ${c.path ? `${c.path} › ` : ""}${c.line}${c.op === "~" ? ` ${t("drift.maskedChanged")}` : ""}`} /></li>
                          ))}
                        </Terminal>
                      </div>
                    </>
                  )}
                  {d.ignored.length > 0 && <p className="meta">{t("drift.ignored", { list: d.ignored.join("; ") })}</p>}
                </div>
              )}
            </ResultPanel>
          ))}
          <Warnings list={rep.warnings} />
        </>
      )}
    </Page>
  );
}
