import { useEffect, useMemo, useState } from "react";
import type { ArmResult, CoreAPI, Job, JobPhase, LoginResult } from "../../lib/core";
import { Check, ConfirmButton, Notice, errorText } from "../../components/Field";
import { Badge, EmptyState, Section } from "../../components/Page";
import { CopyButton } from "../../components/Data";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { DeviceGrid, type Row } from "./DeviceGrid";
import { MetricsPanel, useMetrics } from "./MetricsPanel";
import { perRound } from "./metrics";
import { tones, useStateLabel } from "./JobsPanel";
import { clock, elapsed, when } from "./format";

// Detalle de un trabajo: cifras, línea de fases, Login Test y armado, y la grilla en vivo.
export function JobDetail({ core, job, phases, onChanged }: { core: CoreAPI; job: Job; phases: JobPhase[]; onChanged: () => void }) {
  const t = useT();
  const stateLabel = useStateLabel();
  const [login, setLogin] = useState<LoginResult[]>([]);
  const [trusted, setTrusted] = useState<Set<string>>(new Set());
  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  const [armed, setArmed] = useState<ArmResult | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState<"" | "login" | "arm">("");
  const [grid, setGrid] = useState<{ devices: string[]; initial?: Record<string, Row> } | null>(null);

  const { metrics, error: metricsErr } = useMetrics(core, job);
  // CPU de 1 min por ronda y por dirección, para las filas de la grilla.
  const cpu = useMemo(() => Object.fromEntries((metrics?.devices ?? []).map((d) => [d.address, perRound(d, metrics!, (s) => s.cpu?.oneMin).filter((v): v is number => v != null)])), [metrics]);

  // Un trabajo ya armado reconstruye su grilla con el estado de la ronda actual.
  useEffect(() => {
    if (job.state !== "armed") return;
    core.getRun(job.id, job.round || 1).then((run) => setGrid({
      devices: run.map((d) => d.target),
      initial: Object.fromEntries(run.map((d) => [d.target, { state: d.state, progress: "", detail: d.detail }])),
    })).catch(() => {});
  }, [core, job.id]);

  const runLogin = async () => {
    setErr(""); setBusy("login"); setTrusted(new Set()); setExcluded(new Set());
    try {
      setLogin(await core.loginTest(job.id));
    } catch (e) {
      setLogin([]);
      setErr(errorText(e));
    } finally {
      setBusy("");
      onChanged();
    }
  };
  const arm = async () => {
    setErr(""); setBusy("arm");
    try {
      const r = await core.armJob(job.id, [...trusted], [...excluded]);
      setArmed(r);
      await core.subscribe([job.id]);
      setGrid({ devices: login.filter((l) => !excluded.has(l.target)).map((l) => l.target) });
      onChanged();
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy("");
    }
  };
  const cancel = async () => {
    try {
      await core.cancelJob(job.id);
      onChanged();
    } catch (e) {
      setErr(errorText(e));
    }
  };
  const toggle = (set: Set<string>, setter: (s: Set<string>) => void, v: string) => {
    const n = new Set(set);
    if (n.has(v)) n.delete(v); else n.add(v);
    setter(n);
  };
  const step = (s: string) => {
    const k = s.replace("LOGIN_TEST_STEP_", "");
    return ["TCP", "HOST_KEY", "AUTH", "PRIVILEGE", "PROMPT", "PLATFORM"].includes(k) ? t(`patrol.login.step.${k}` as Key) : k;
  };
  const live = ["created", "arming", "armed"].includes(job.state);
  const showLogin = job.state === "created" && !armed;

  return (
    <section aria-labelledby="job-h" className="job-detail">
      <header className="job-head">
        <h3 id="job-h">{job.name}</h3>
        {live && <ConfirmButton label={t("patrol.cancel")} confirmLabel={t("patrol.cancel.confirm")} onConfirm={cancel} />}
      </header>

      <dl className="stats">
        <div><dt>{t("patrol.stat.state")}</dt><dd><Badge tone={tones[job.state]}>{stateLabel(job.state)}</Badge></dd></div>
        {job.armedAt && <div><dt>{t("patrol.stat.elapsed")}</dt><dd>{elapsed(Date.now() - Date.parse(job.armedAt))}</dd></div>}
        {!!job.round && <div><dt>{t("patrol.stat.round")}</dt><dd>{job.rounds ? t("patrol.round", { n: job.round, total: job.rounds }) : job.round}</dd></div>}
        {job.rounds !== undefined && <div><dt>{t("patrol.stat.rounds")}</dt><dd>{job.rounds || t("patrol.untilWindow")}</dd></div>}
        {!!job.round && !!job.devicesTotal && <div data-wide><dt>{t("patrol.stat.devices")}</dt><dd>{t("patrol.devices", { ok: job.devicesOk ?? 0, failed: job.devicesFailed ?? 0, total: job.devicesTotal })}</dd></div>}
        {job.nextRoundAt && Date.parse(job.nextRoundAt) > Date.now() && <div><dt>{t("patrol.stat.next")}</dt><dd>{when(job.nextRoundAt)}</dd></div>}
        {job.windowEndsAt && <div><dt>{t("patrol.stat.windowEnds")}</dt><dd>{when(job.windowEndsAt)}</dd></div>}
      </dl>

      {err && <Notice kind="error">{err}</Notice>}
      {showLogin && (
        <Section title={t("patrol.login.title")} description={t("patrol.login.intro")}>
          {login.length > 0 && (
            <>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>{t("patrol.login.col.device")}</th><th>{t("patrol.login.col.result")}</th><th>{t("patrol.login.col.decision")}</th></tr></thead>
                  <tbody>
                    {login.map((l) => (
                      <tr key={l.target} data-state={l.passed ? "ok" : "bad"}>
                        <td className="mono">{l.target}</td>
                        <td>{l.passed ? t("patrol.login.ok", { platform: l.platform }) : t("patrol.login.fail", { step: step(l.failedStep), detail: l.detail })}</td>
                        <td>
                          {!l.passed && l.fingerprint && <Check label={t("patrol.login.trust", { fp: l.fingerprint })} checked={trusted.has(l.fingerprint)} onChange={() => toggle(trusted, setTrusted, l.fingerprint)} />}
                          {!l.passed && !l.fingerprint && <Check label={t("patrol.login.exclude", { target: l.target })} checked={excluded.has(l.target)} onChange={() => toggle(excluded, setExcluded, l.target)} />}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Notice kind="warn">{t("patrol.login.keyWarning")}</Notice>
            </>
          )}
          <div className="actions">
            {login.length > 0 && <button className="primary" onClick={arm} disabled={!!busy} aria-busy={busy === "arm"}>{t("patrol.arm")}</button>}
            <button className={login.length ? "" : "primary"} onClick={runLogin} disabled={!!busy} aria-busy={busy === "login"}>{t("patrol.login.run")}</button>
          </div>
        </Section>
      )}
      {armed && (
        <Notice kind={armed.missingInhibitors?.length ? "warn" : "ok"}>
          {t("patrol.armed", { ends: when(armed.windowEndsAt) })}
          {armed.missingInhibitors?.length ? ` ${t("patrol.inhibitors", { list: armed.missingInhibitors.join(", ") })}` : ""}
        </Notice>
      )}

      {job.state !== "created" && <MetricsPanel metrics={metrics} error={metricsErr} jobId={job.id} />}

      {!live && !showLogin && job.outputDir && (
        <Section title={t("patrol.package.title")} description={t("patrol.package.desc")}>
          <p><code className="mono">{job.outputDir}</code> <CopyButton value={job.outputDir} label={t("patrol.package.copy")} /></p>
        </Section>
      )}

      <Phases phases={phases} />

      {grid && grid.devices.length > 0 && (
        <Section title={t("patrol.grid.title")}>
          <DeviceGrid core={core} jobId={job.id} devices={grid.devices} initial={grid.initial} cpu={cpu} />
        </Section>
      )}
    </section>
  );
}

function Phases({ phases }: { phases: JobPhase[] }) {
  const t = useT();
  const label = (p: JobPhase) => {
    const k = p.kind.replace("JOB_PHASE_KIND_", "");
    const key = `patrol.phase.${k}` as Key;
    return key in phaseKeys ? t(key, { round: p.round ?? 0 }) : k;
  };
  return (
    <Section title={t("patrol.phases")}>
      {phases.length ? (
        <ol className="timeline" aria-label={t("patrol.phases")}>
          {phases.map((p, i) => (
            <li key={`${p.at}-${p.kind}-${p.round ?? 0}-${i}`} data-kind={p.kind.replace("JOB_PHASE_KIND_", "")}>
              <time dateTime={p.at}>{clock(p.at)}</time>
              <span className="phase-label">{label(p)}</span>
              {p.detail && <span className="meta">{p.detail}</span>}
            </li>
          ))}
        </ol>
      ) : <EmptyState icon="patrol" title={t("patrol.phases.empty")} />}
    </Section>
  );
}

const phaseKeys = Object.fromEntries(
  ["CREATED", "LOGIN_TEST_DONE", "ARMED", "ROUND_STARTED", "ROUND_FINISHED", "ROUND_SKIPPED", "PACKAGED", "COMPLETED", "CANCELLED", "FAILED"].map((k) => [`patrol.phase.${k}`, true]),
);
