import { useEffect, useState } from "react";
import type { Job } from "../../lib/core";
import { Badge, EmptyState, type Tone } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { Segmented } from "../../components/Segmented";
import { elapsed } from "./format";

export const tones: Record<string, Tone> = { armed: "ok", arming: "ok", completed: "", cancelled: "", failed: "bad", created: "warn" };

export function useStateLabel() {
  const t = useT();
  return (s: string) => (s in tones ? t(`patrol.state.${s}` as Key) : s);
}

// Lista de trabajos con lo esencial a la vista; elegir uno abre su detalle.
export function JobsPanel({ jobs, selected, onSelect, onNew }: { jobs: Job[]; selected: string | null; onSelect: (id: string) => void; onNew: () => void }) {
  const t = useT();
  const stateLabel = useStateLabel();
  // El tiempo activo se refresca cada 30 s solo si hay trabajos armados.
  const [, tick] = useState(0);
  const [kind, setKind] = useState("");
  const kinds = [...new Set(jobs.map((j) => j.kind).filter((k): k is string => !!k))];
  const shown = kind ? jobs.filter((j) => j.kind === kind) : jobs;
  const kindLabel = (k: string) => (["adhoc", "backup", "patrol", "change"].includes(k) ? t(`patrol.kind.${k}` as Key) : k);
  const live = jobs.some((j) => j.state === "armed");
  useEffect(() => {
    if (!live) return;
    const id = window.setInterval(() => tick((n) => n + 1), 30_000);
    return () => window.clearInterval(id);
  }, [live]);

  return (
    <section aria-labelledby="jobs-h" className="jobs-panel">
      <header className="jobs-head">
        <h3 id="jobs-h">{t("patrol.jobs")}</h3>
        <button className="sm" aria-pressed={selected === null} onClick={onNew}>{t("patrol.newJob")}</button>
      </header>
      {kinds.length > 1 && <Segmented legend={t("patrol.filter.kind")} value={kinds.includes(kind) ? kind : ""} onChange={setKind} options={[["", t("patrol.kind.all")], ...kinds.map((k): [string, string] => [k, kindLabel(k)])]} />}
      {!jobs.length && <EmptyState icon="patrol" title={t("patrol.jobs.empty")}>{t("patrol.jobs.empty.hint")}</EmptyState>}
      <ul className="job-list">
        {shown.map((j) => (
          <li key={j.id}>
            <button className="job-item" aria-current={selected === j.id ? "true" : undefined} onClick={() => onSelect(j.id)}>
              <span className="job-top">
                <span className="job-name">{j.name}</span>
                <Badge tone={tones[j.state]}>{stateLabel(j.state)}</Badge>
              </span>
              {j.state === "armed" && j.armedAt && <span className="meta">{t("patrol.activeFor", { t: elapsed(Date.now() - Date.parse(j.armedAt)) })}</span>}
              {!!j.round && (
                <span className="meta">{j.rounds ? t("patrol.round", { n: j.round, total: j.rounds }) : t("patrol.roundOpen", { n: j.round })}</span>
              )}
              {!!j.round && !!j.devicesTotal && (
                <span className="meta">{t("patrol.devices", { ok: j.devicesOk ?? 0, failed: j.devicesFailed ?? 0, total: j.devicesTotal, n: j.devicesTotal })}</span>
              )}
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
