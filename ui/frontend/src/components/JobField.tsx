import { useState } from "react";
import { Field, Select, type Width } from "./Field";
import { useCoreLoad } from "../lib/useCoreLoad";
import { useLang, useT } from "../lib/i18n";
import type { Key } from "../lib/i18n/es";
import type { CoreAPI, Job } from "../lib/core";

const OTHER = "__other__";
const known = ["created", "arming", "armed", "completed", "cancelled", "failed"];
const at = (j: Job) => Date.parse(j.finishedAt ?? j.armedAt ?? "");

// «Trabajo o carpeta» de Patrol: elige entre los trabajos del núcleo (el más reciente primero) o escribe un ID o ruta.
// Lo que sube es siempre el ID o la ruta, igual que cuando solo se escribía. Sin trabajos queda el campo de texto.
export function JobField({ core, label, value, onChange, w = "lg" }: { core: CoreAPI; label: string; value: string; onChange: (v: string) => void; w?: Width }) {
  const t = useT();
  const lang = useLang();
  const [jobs, setJobs] = useState<Job[]>([]);
  const [other, setOther] = useState(false);
  useCoreLoad((live) => core.listJobs({ includePast: true }).then((l) => { if (live()) setJobs([...(l ?? [])].sort((a, b) => (at(b) || -Infinity) - (at(a) || -Infinity))); }), [core]);
  const text = <Field label={jobs.length ? t("job.other.label") : label} value={value} onChange={onChange} w={w} mono />;
  if (!jobs.length) return text;
  const isJob = jobs.some((j) => j.id === value);
  const manual = other || (value !== "" && !isJob);
  const date = (j: Job) => (Number.isNaN(at(j)) ? "" : new Date(at(j)).toLocaleString(lang, { dateStyle: "short", timeStyle: "short" }));
  const opt = (j: Job): [string, string] => [j.id, [j.name, date(j), known.includes(j.state) ? t(`patrol.state.${j.state}` as Key) : j.state].filter(Boolean).join(" · ")];
  return (
    <>
      <Select label={label} w={w} value={manual ? OTHER : value} placeholder={t("common.select")}
        onChange={(v) => { setOther(v === OTHER); onChange(v === OTHER ? (isJob ? "" : value) : v); }}
        options={[...jobs.map(opt), [OTHER, t("job.other")]]} />
      {manual && text}
    </>
  );
}
