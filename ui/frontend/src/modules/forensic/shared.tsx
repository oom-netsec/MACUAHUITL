import { Field, Notice, Select, TextArea } from "../../components/Field";
import { EmptyState, ResultPanel } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import type { LogSource, MsgEntry } from "./api";
import "./forensic.css";

// Texto traducido con fragmentos literales entre acentos graves (`debug`): esos tramos salen en <code>.
export function Rich({ text }: { text: string }) {
  return <>{text.split("`").map((p, i) => (i % 2 ? <code key={i}>{p}</code> : p))}</>;
}

// Qué hace la herramienta, en una frase bajo el título de la pestaña.
export function Intro({ text }: { text: string }) {
  return <p className="forensic-intro"><Rich text={text} /></p>;
}

export const runKbd = <kbd aria-hidden="true">Ctrl ↵</kbd>;

// Antes de la primera ejecución: qué hacer primero.
export function FirstRun({ what }: { what: Key }) {
  const t = useT();
  return <EmptyState icon="search" title={t("forensic.empty.title")}>{t(what)}</EmptyState>;
}

export function Warnings({ list }: { list?: string[] }) {
  const t = useT();
  if (!list?.length) return null;
  return <Notice kind="warn"><ul className="forensic-warnings">{list.map((w) => <li key={w}>{t("forensic.warning", { w })}</li>)}</ul></Notice>;
}

const SEV: Key[] = ["forensic.sev.0", "forensic.sev.1", "forensic.sev.2", "forensic.sev.3", "forensic.sev.4", "forensic.sev.5", "forensic.sev.6", "forensic.sev.7"];

// MsgCard es la ficha de un mensaje de la base de conocimiento. Los comandos son de lectura.
export function MsgCard({ e }: { e: MsgEntry }) {
  const t = useT();
  return (
    <ResultPanel title={e.id} meta={e.severity >= 0 ? t("forensic.card.severity", { n: e.severity, name: t(SEV[e.severity]) }) : t("forensic.card.varSeverity")}>
      <div className="panel-body">
        <p><strong>{t("forensic.card.meaning")}</strong> {e.meaning}</p>
        <p><strong>{t("forensic.card.cause")}</strong> {e.cause}</p>
        <p><strong>{t("forensic.card.action")}</strong> {e.action}</p>
        <p className="meta">{t("forensic.card.verify")}</p>
        <ul className="notes">{e.verify.map((c) => <li key={c}><code>{c}</code></li>)}</ul>
        <p className="meta">{t("forensic.card.source", { x: e.source })}</p>
      </div>
    </ResultPanel>
  );
}

// SourceState es lo que escribe el usuario; toSource lo convierte en una fuente válida (null si falta algo).
export type SourceKind = "text" | "path" | "capture" | "job";
export interface SourceState { kind: SourceKind; text: string; path: string; job: string; device: string }
export const emptySource: SourceState = { kind: "text", text: "", path: "", job: "", device: "" };

export function toSource(s: SourceState): LogSource | null {
  switch (s.kind) {
    case "text": return s.text.trim() ? { text: s.text } : null;
    case "path": return s.path.trim() ? { path: s.path.trim() } : null;
    case "capture": return { capture: true };
    case "job": return s.job.trim() ? { job: s.job.trim(), device: s.device.trim() } : null;
  }
}

// SourcePicker elige de dónde salen los mensajes: texto pegado, archivo local, captura del receptor syslog o show logging de un trabajo de Patrol.
export function SourcePicker({ value, onChange }: { value: SourceState; onChange: (s: SourceState) => void }) {
  const t = useT();
  const set = (p: Partial<SourceState>) => onChange({ ...value, ...p });
  return (
    <>
      <div className="field-row">
        <Select label={t("forensic.src.label")} value={value.kind} onChange={(kind) => set({ kind })} w="lg"
          options={[["text", t("forensic.src.text")], ["path", t("forensic.src.path")], ["capture", t("forensic.src.capture")], ["job", t("forensic.src.job")]]} />
      </div>
      {value.kind === "text" && <TextArea label={t("forensic.src.textLabel")} value={value.text} onChange={(text) => set({ text })} rows={10} />}
      {value.kind === "path" && <Field label={t("forensic.src.pathLabel")} value={value.path} onChange={(path) => set({ path })} w="full" mono />}
      {value.kind === "capture" && <p className="hint">{t("forensic.src.captureNote")}</p>}
      {value.kind === "job" && (
        <div className="field-row">
          <Field label={t("forensic.src.jobLabel")} value={value.job} onChange={(job) => set({ job })} w="lg" mono />
          <Field label={t("forensic.src.device")} value={value.device} onChange={(device) => set({ device })} w="md" mono />
        </div>
      )}
    </>
  );
}
