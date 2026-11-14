import { useCallback, useEffect, useRef, useState } from "react";
import type { CoreAPI, Credential, Job, JobPhase, VaultState } from "../../lib/core";
import { Notice, errorText } from "../../components/Field";
import { Page } from "../../components/Page";
import { useBusy, useNav } from "../../app/activity";
import { useT } from "../../lib/i18n";
import { errInfo } from "../../lib/coreError";
import { NewJobForm } from "./NewJobForm";
import { JobsPanel } from "./JobsPanel";
import { JobDetail } from "./JobDetail";
import "./patrol.css";
import { useVaultVersion } from "../../lib/vaultSignal";

export { parseTargets } from "./NewJobForm";

const active = (j: Job) => j.state === "armed" || j.state === "arming";
// El núcleo no garantiza orden: activos, luego creados, luego terminados; dentro, lo más reciente arriba.
const rank = (j: Job) => (active(j) ? 0 : j.state === "created" ? 1 : 2);
const lastActivity = (j: Job) => Math.max(0, ...(j.phases ?? []).map((p) => Date.parse(p.at)), j.armedAt ? Date.parse(j.armedAt) : 0);
const sortJobs = (js: Job[]) => [...js].sort((a, b) => rank(a) - rank(b) || lastActivity(b) - lastActivity(a) || a.name.localeCompare(b.name));
const samePhase = (a: JobPhase, b: JobPhase) => a.at === b.at && a.kind === b.kind && (a.round ?? 0) === (b.round ?? 0);

export function PatrolView({ core }: { core: CoreAPI }) {
  const t = useT();
  const go = useNav();
  const [vault, setVault] = useState<VaultState | null>(null);
  const [creds, setCreds] = useState<Credential[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  // Fases que llegaron en vivo y que el núcleo aún no devolvió en ListJobs.
  const [livePhases, setLivePhases] = useState<Record<string, JobPhase[]>>({});
  const [err, setErr] = useState("");
  const subscribed = useRef(new Set<string>());
  const autoSelected = useRef(false);
  const listSeq = useRef(0); // solo la última consulta de trabajos aplica: una respuesta vieja no pisa a la nueva
  useBusy(jobs.some(active));

  // Un stream por trabajo, una sola vez (el núcleo lo cierra solo tras `closed`). Se pide id por id: un trabajo borrado
  // entre listJobs y subscribe (patrol.err.job_missing) se descarta sin afectar a los demás.
  const subscribeJobs = useCallback(async (ids: string[]) => {
    const fresh = ids.filter((id) => !subscribed.current.has(id));
    fresh.forEach((id) => subscribed.current.add(id));
    const res = await Promise.allSettled(fresh.map((id) => core.subscribe([id])));
    let fail: unknown;
    res.forEach((r, i) => {
      if (r.status === "fulfilled") return;
      subscribed.current.delete(fresh[i]); // sin stream: se reintenta en la próxima consulta (si el trabajo sigue ahí)
      if (errInfo(r.reason)?.reason !== "patrol.err.job_missing") fail ??= r.reason;
    });
    if (fail !== undefined) throw fail;
  }, [core]);

  const refreshJobs = useCallback(async () => {
    const n = ++listSeq.current;
    try {
      const js = await core.listJobs();
      if (n !== listSeq.current) return;
      setJobs(sortJobs(js));
      await subscribeJobs(js.filter(active).map((j) => j.id));
      // Al abrir, si hay un trabajo armado, se muestra ese en lugar del formulario.
      if (!autoSelected.current) {
        autoSelected.current = true;
        const first = js.find(active);
        if (first) setSelected(first.id);
      }
    } catch (e) {
      if (n === listSeq.current) setErr(errorText(e)); // el error de una consulta vieja no pisa a una nueva
    }
  }, [core, subscribeJobs]);

  const vv = useVaultVersion(); // la bóveda cambió: volver a listar credenciales
  useEffect(() => {
    core.vaultStatus().then(async (s) => {
      setVault(s.state);
      if (s.state === "unlocked") setCreds(await core.listCredentials());
    }).catch((e) => setErr(errorText(e)));
    refreshJobs();
  }, [core, vv, refreshJobs]);

  useEffect(() => core.onEvent((e) => {
    if (e.phaseAdded) {
      const p = e.phaseAdded;
      setLivePhases((l) => (l[e.jobId] ?? []).some((q) => samePhase(p, q)) ? l : { ...l, [e.jobId]: [...(l[e.jobId] ?? []), p] }); // la suscripción reabierta repite eventos
    }
    if (e.phaseAdded || e.jobStateChanged) refreshJobs();
  }), [core, refreshJobs]);

  const job = jobs.find((j) => j.id === selected);
  const phases = job ? [...(job.phases ?? []), ...(livePhases[job.id] ?? []).filter((p) => !(job.phases ?? []).some((q) => samePhase(p, q)))] : [];

  return (
    <Page title={t("patrol.title")} description={t("patrol.desc")}>
      <div className="patrol">
        <div className="patrol-main">
          {err && <Notice kind="error">{err}</Notice>}
          {(vault === "absent" || vault === "locked") && (
            <Notice kind="info">
              {t(vault === "absent" ? "patrol.vault.absent" : "patrol.vault.locked")}
              <button className="inline" onClick={() => go("vault")}>{t(vault === "absent" ? "vault.create" : "vault.unlock")}</button>
            </Notice>
          )}
          {job
            ? <JobDetail key={job.id} core={core} job={job} phases={phases} onChanged={refreshJobs} subscribe={subscribeJobs} />
            : <NewJobForm core={core} creds={creds} onCreated={async (id) => { await refreshJobs(); setSelected(id); }} />}
        </div>
        <JobsPanel jobs={jobs} selected={job ? job.id : null} onSelect={setSelected} onNew={() => setSelected(null)} />
      </div>
    </Page>
  );
}
