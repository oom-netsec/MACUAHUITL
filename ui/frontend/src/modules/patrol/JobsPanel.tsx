import { useEffect, useState } from "react";
import type { Job } from "../../lib/core";
import { Badge, EmptyState, type Tone } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { Segmented } from "../../components/Segmented";
import { Check } from "../../components/Field";
import { RemoveDialog } from "./RemoveDialog";
import { devicesText, elapsed } from "./format";

// Terminado = ya no corre; solo estos se pueden quitar del historial.
export const isFinished = (j: Job) => ["completed", "cancelled", "failed"].includes(j.state);
export const tones: Record<string, Tone> = { armed: "ok", arming: "ok", completed: "", cancelled: "", failed: "bad", created: "warn" };

export function useStateLabel() {
  const t = useT();

  return (s: string) => (s in tones ? t(`patrol.state.${s}` as Key) : s);
}

// Lista de trabajos con lo esencial a la vista; elegir uno abre su detalle.
export function JobsPanel({ jobs, selected, onSelect, onNew, onClearFinished }: { jobs: Job[]; selected: string | null; onSelect: (id: string) => void; onNew: () => void; onClearFinished: () => Promise<void> }) {
  const t = useT();
  const stateLabel = useStateLabel();
  // El tiempo activo se refresca cada 30 s solo si hay trabajos armados.
  const [, tick] = useState(0);
  const [kind, setKind] = useState("");
  const kinds = [...new Set(jobs.map((j) => j.kind).filter((k): k is string => !!k))];
  const k = kinds.length > 1 && kinds.includes(kind) ? kind : ""; // si el tipo elegido desaparece, el filtro se suelta
  const [onlyActive, setOnlyActive] = useState(false);
  const [clearing, setClearing] = useState(false);
  const shown = jobs.filter((j) => (!k || j.kind === k) && (!onlyActive || !isFinished(j)));
  // `past` lo calcula el núcleo (día local de finishedAt): la UI no recalcula «hoy».
  const recent = shown.filter((j) => !j.past), past = shown.filter((j) => j.past);
  const finished = jobs.filter(isFinished);
  const kindLabel = (k: string) => (["adhoc", "backup", "patrol", "change"].includes(k) ? t(`patrol.kind.${k}` as Key) : k);
  const live = jobs.some((j) => j.state === "armed");
  useEffect(() => {
    if (!live) return;
    const id = window.setInterval(() => tick((n) => n + 1), 30_000);
    return () => window.clearInterval(id);
  }, [live]);

  const item = (j: Job) => (
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
          <span className="meta">{devicesText(t, j)}</span>
        )}
      </button>
    </li>
  );

  return (
    <section aria-labelledby="jobs-h" className="jobs-panel">
      <header className="jobs-head">
        <h3 id="jobs-h">{t("patrol.jobs")}</h3>
        <button className="sm" aria-pressed={selected === null} onClick={onNew}>{t("patrol.newJob")}</button>
        <button className="sm" onClick={() => setClearing(true)} disabled={!finished.length}>{t("patrol.history.clear", { n: finished.length })}</button>
      </header>
      <Check label={t("patrol.history.onlyActive")} checked={onlyActive} onChange={setOnlyActive} />
      {kinds.length > 1 && <Segmented legend={t("patrol.filter.kind")} value={k} onChange={setKind} options={[["", t("patrol.kind.all")], ...kinds.map((k): [string, string] => [k, kindLabel(k)])]} />}
      {!jobs.length && <EmptyState icon="patrol" title={t("patrol.jobs.empty")}>{t("patrol.jobs.empty.hint")}</EmptyState>}
      <ul className="job-list">
        {recent.map(item)}
      </ul>
      {past.length > 0 && (
        // Cerrada por omisión: los días anteriores no estorban la lista del día.
        <details className="jobs-past">
          <summary>{t("patrol.history.past", { n: past.length })}</summary>
          <p className="hint">{t("patrol.history.pastHelp")}</p>
          <ul className="job-list">{past.map(item)}</ul>
        </details>
      )}
      {clearing && <RemoveDialog title={t("patrol.history.clear.title")} body={t("patrol.history.clear.body", { n: finished.length })} jobs={finished}
        onConfirm={async () => { await onClearFinished(); setClearing(false); }} onClose={() => setClearing(false)} />}
    </section>
  );
}
