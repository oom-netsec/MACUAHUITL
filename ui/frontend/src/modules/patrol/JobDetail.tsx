import { useEffect, useMemo, useRef, useState } from "react";
import type { ArmResult, CoreAPI, Job, JobPhase, LoginResult } from "../../lib/core";
import { Check, ConfirmButton, Notice, errorText } from "../../components/Field";
import { Badge, EmptyState, Section } from "../../components/Page";
import { CopyButton } from "../../components/Data";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { DeviceGrid, type EarlyEvents, type Row } from "./DeviceGrid";
import { MetricsPanel, useMetrics } from "./MetricsPanel";
import { perRound } from "./metrics";
import { tones, useStateLabel } from "./JobsPanel";
import { RemoveDialog } from "./RemoveDialog";
import { armFailed, isRemovable } from "./states";
import { devicesText, activeMs, clock, elapsed, when } from "./format";

// Detalle de un trabajo: cifras, línea de fases, Login Test y armado, y la grilla en vivo.
export function JobDetail({ core, job, phases, onChanged, onRemoved, subscribe }: { core: CoreAPI; job: Job; phases: JobPhase[]; onChanged: () => void; onRemoved: () => void; subscribe: (ids: string[], force?: boolean) => Promise<void> }) {
  const t = useT();
  const stateLabel = useStateLabel();
  const [login, setLogin] = useState<LoginResult[]>([]);
  // trusted: equipos (target del Login Test) cuya huella el ingeniero confirmó; la huella viaja atada a su equipo.
  const [trusted, setTrusted] = useState<Set<string>>(new Set());
  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  const [armed, setArmed] = useState<ArmResult | null>(null);
  const [err, setErr] = useState("");
  const [removing, setRemoving] = useState(false);
  const [busy, setBusy] = useState<"" | "login" | "arm">("");
  const [grid, setGrid] = useState<{ devices: string[]; initial?: Record<string, Row> } | null>(null);

  // Eventos de equipos que llegan mientras la grilla se arma (GetRun en curso, o justo después de armar): la grilla los aplica al montar.
  const early = useRef<EarlyEvents>({ events: [], live: false }).current;
  useEffect(() => core.onEvent((e) => {
    if (early.live || e.jobId !== job.id || !(e.deviceStateChanged || e.commandProgress)) return;
    early.events.push(e);
    // shortcut: tope de 5000 eventos (de sobra para el hueco de un GetRun); se quedan los más nuevos, que son los que valen.
    if (early.events.length > 5000) early.events.shift();
  }), [core, job.id, early]);

  const { metrics, error: metricsErr } = useMetrics(core, job);
  // CPU de 1 min por ronda y por dirección, para las filas de la grilla.
  const cpu = useMemo(() => Object.fromEntries((metrics?.devices ?? []).map((d) => [d.address, perRound(d, metrics!, (s) => s.cpu?.oneMin).filter((v): v is number => v != null)])), [metrics]);

  // Un trabajo ya armado sin grilla (p. ej. al abrir la app) la reconstruye una vez; nunca pisa una grilla viva.
  // El núcleo solo lista los equipos que ya terminaron la ronda: si la actual va vacía, la lista sale de la anterior.
  useEffect(() => {
    if (job.state !== "armed" || grid) return;
    const r = job.round || 1;
    let off = false;
    const rebuild = async () => {
      const cur = await core.getRun(job.id, r);
      // La ronda en curso solo trae los equipos que ya terminaron: la lista completa es la unión con la anterior.
      const prev = r > 1 ? await core.getRun(job.id, r - 1) : [];
      const devices = [...new Set([...prev, ...cur].map((d) => d.target))];
      if (off) return; // ronda 1 sin equipos terminados: grilla vacía; DeviceGrid agrega cada equipo con su primer evento
      setGrid((g) => g ?? {
        devices,
        initial: cur.length ? Object.fromEntries(cur.map((d) => [d.target, { state: d.state, progress: "", detail: d.detail, cut: d.cutCommands ?? 0, reconnects: d.reconnects ?? 0, first: d.args?.first ?? "" }])) : undefined,
      });
    };
    rebuild().catch(() => {});
    return () => { off = true; };
  }, [core, job.id, job.state, job.round, grid]);

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
      const r = await core.armJob(job.id, [], login.filter((l) => !l.passed && l.fingerprint && trusted.has(l.target)).map((l) => ({ host: l.target, fingerprint: l.fingerprint })), [...excluded]);
      setArmed(r);
      await subscribe([job.id], true);
      // Sin Login Test previo (reintento de un arranque fallido) no hay lista: la reconstruye el efecto al quedar armado.
      if (login.length) setGrid({ devices: login.filter((l) => !excluded.has(l.target)).map((l) => l.target) });
      onChanged();
    } catch (e) {
      setErr(errorText(e));
      onChanged(); // el núcleo anotó ARM_FAILED: la lista trae la fase con su motivo traducido
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
  const failedStart = !armed && armFailed(job, phases) ? phases[phases.length - 1] : undefined;
  const failedReason = failedStart && phaseDetail(t, failedStart);

  return (
    <section aria-labelledby="job-h" className="job-detail">
      <header className="job-head">
        <h3 id="job-h">{job.name}</h3>
        {isRemovable(job) && <button onClick={() => setRemoving(true)}>{t("patrol.history.removeOne")}</button>}
        {live && <ConfirmButton label={t("patrol.cancel")} confirmLabel={t("patrol.cancel.confirm")} onConfirm={cancel} />}
      </header>

      {removing && <RemoveDialog title={t("patrol.history.removeOne.title")} body={`${t("patrol.history.removeOne.body", { name: job.name })}${job.outputDir ? ` ${t("patrol.history.removeOne.folder")}` : ""}`} jobs={[job]}
        onConfirm={async () => { const r = await core.removeJobs({ jobIds: [job.id] }); if (r.skipped?.length) onChanged(); return r; }} onDone={onRemoved} onClose={() => setRemoving(false)} />}

      <dl className="stats">
        <div><dt>{t("patrol.stat.state")}</dt><dd>{failedStart ? <Badge tone="bad">{t("patrol.state.armFailed")}</Badge> : <Badge tone={tones[job.state]}>{stateLabel(job.state)}</Badge>}</dd></div>
        {job.armedAt && <div><dt>{t("patrol.stat.elapsed")}</dt><dd>{elapsed(activeMs(job.armedAt, job.state, phases))}</dd></div>}
        {!!job.round && <div><dt>{t("patrol.stat.round")}</dt><dd>{job.rounds ? t("patrol.round", { n: job.round, total: job.rounds }) : job.round}</dd></div>}
        {job.rounds !== undefined && <div><dt>{t("patrol.stat.rounds")}</dt><dd>{job.rounds || t("patrol.untilWindow")}</dd></div>}
        {!!job.round && !!job.devicesTotal && <div data-wide><dt>{t("patrol.stat.devices")}</dt><dd>{devicesText(t, job)}</dd></div>}
        {job.nextRoundAt && Date.parse(job.nextRoundAt) > Date.now() && <div><dt>{t("patrol.stat.next")}</dt><dd>{when(job.nextRoundAt)}</dd></div>}
        {job.windowEndsAt && <div><dt>{t("patrol.stat.windowEnds")}</dt><dd>{when(job.windowEndsAt)}</dd></div>}
      </dl>

      {err && <Notice kind="error">{err}</Notice>}
      {/* Estado del trabajo, no un error nuevo: role=status; se oculta mientras se reintenta o hay un error más reciente. */}
      {failedStart && !err && !busy && <Notice kind="warn">{failedReason ? t("patrol.armFailed", { reason: failedReason }) : t("patrol.armFailed.noReason")} {t("patrol.armFailed.help")}</Notice>}
      {showLogin && (
        <Section title={t("patrol.login.title")} description={t("patrol.login.intro")}>
          {login.length > 0 && (
            <>
              <div className="table-wrap login-test">
                <table>
                  <thead><tr><th>{t("patrol.login.col.device")}</th><th>{t("patrol.login.col.result")}</th><th>{t("patrol.login.col.decision")}</th></tr></thead>
                  <tbody>
                    {login.map((l) => (
                      <tr key={l.target} data-state={l.passed ? "ok" : "bad"}>
                        <td className="mono">{l.target}</td>
                        <td>{l.passed ? t("patrol.login.ok", { platform: l.platform }) : t("patrol.login.fail", { step: step(l.failedStep), detail: l.detail })}</td>
                        <td>
                          {!l.passed && l.fingerprint && <Check label={t("patrol.login.trust", { fp: l.fingerprint })} checked={trusted.has(l.target)} onChange={() => toggle(trusted, setTrusted, l.target)} />}
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
            {(login.length > 0 || failedStart) && <button className="primary" onClick={arm} disabled={!!busy} aria-busy={busy === "arm"}>{t("patrol.arm")}</button>}
            <button className={login.length || failedStart ? "" : "primary"} onClick={runLogin} disabled={!!busy} aria-busy={busy === "login"}>{t("patrol.login.run")}</button>
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

      {grid && (
        <Section title={t("patrol.grid.title")}>
          <DeviceGrid core={core} jobId={job.id} devices={grid.devices} initial={grid.initial} cpu={cpu} early={early} />
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
  const detail = (p: JobPhase) => phaseDetail(t, p);
  return (
    <Section title={t("patrol.phases")}>
      {phases.length ? (
        <ol className="timeline" aria-label={t("patrol.phases")}>
          {phases.map((p, i) => (
            <li key={`${p.at}-${p.kind}-${p.round ?? 0}-${i}`} data-kind={p.kind.replace("JOB_PHASE_KIND_", "")}>
              <time dateTime={p.at}>{clock(p.at)}</time>
              <span className="phase-label">{label(p)}</span>
              {detail(p) && <span className="meta">{detail(p)}</span>}
            </li>
          ))}
        </ol>
      ) : <EmptyState icon="patrol" title={t("patrol.phases.empty")} />}
    </Section>
  );
}

// Con reason conocido el detalle sale de i18n; las fases viejas o un reason nuevo muestran el texto del núcleo
// (para los reasons del catálogo del núcleo, el puente ya lo trae traducido).
function phaseDetail(t: ReturnType<typeof useT>, p: JobPhase) {
  const key = `patrol.phaseReason.${p.reason}` as Key;
  if (!p.reason || !(key in phaseReasonKeys)) return p.detail;
  const a = p.args ?? {};
  return t(key, { ...a, n: Number(a.n), ok: t("patrol.phaseReason.ok", { n: Number(a.ok) }), excl: t("patrol.phaseReason.excluded", { n: Number(a.excluded) }), partial: t("patrol.partialCount", { n: Number(a.partial) }) });
}

const phaseReasonKeys = Object.fromEntries(
  ["devices", "devices_excluded", "ok_failed", "ok_partial_failed", "rounds", "packaged", "round_zip_failed", "close_failed", "before_arming", "core_stopped"].map((r) => [`patrol.phaseReason.phase.${r}`, true]),
);
const phaseKeys = Object.fromEntries(
  ["CREATED", "LOGIN_TEST_DONE", "ARMED", "ROUND_STARTED", "ROUND_FINISHED", "ROUND_SKIPPED", "PACKAGED", "COMPLETED", "CANCELLED", "FAILED", "ARM_CHECK_DONE", "ARM_FAILED"].map((k) => [`patrol.phase.${k}`, true]),
);
