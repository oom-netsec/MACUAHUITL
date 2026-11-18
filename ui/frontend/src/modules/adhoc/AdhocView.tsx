import { plural } from "../../lib/plural";
import { CredentialSelect, useCredentials } from "../../components/CredentialSelect";
import { useEffect, useRef, useState } from "react";
import type { AdhocResult, CoreAPI } from "../../lib/core";
import { Field, Notice, TextArea } from "../../components/Field";
import { RunButton } from "../../components/RunButton";
import { ExportMenu } from "../../components/Files";
import { AdhocMatrix } from "./AdhocMatrix";
import { EmptyState, Page, ResultPanel, useResult } from "../../components/Page";
import { Hl, Terminal } from "../../components/Terminal";
import { parseTargets } from "../patrol/PatrolView";
import { useT } from "../../lib/i18n";
import { jobState } from "../../lib/vocab";
import "./adhoc.css";
import { resolveAccepted } from "../../lib/hostkeys";

// Lotes: comandos de solo lectura en varios equipos, como un trabajo de Patrol de una ronda.
// El núcleo rechaza todo comando que no sea de lectura; la app no aplica configuración.

const views = ["matrix", "host", "table", "csv", "markdown"] as const;
type ViewName = (typeof views)[number];

// "host", "host:puerto" (un solo ':') o "[ipv6]:puerto" / "[ipv6]"; una IPv6 sin corchetes va sin puerto.
export function parseTarget(s: string): { address: string; port: number } {
  const b = /^\[([^\]]+)\](?::(\d+))?$/.exec(s);
  if (b) return { address: b[1], port: b[2] ? Number(b[2]) : 0 };
  const i = s.lastIndexOf(":");
  if (i > 0 && s.indexOf(":") === i && /^\d+$/.test(s.slice(i + 1))) return { address: s.slice(0, i), port: Number(s.slice(i + 1)) };
  return { address: s, port: 0 };
}

// maxWaitMs: tope de la espera del resultado; pasado, se deja de preguntar (el trabajo sigue en Patrol).
export function AdhocView({ core, pollMs = 700, maxWaitMs = 15 * 60_000 }: { core: CoreAPI; pollMs?: number; maxWaitMs?: number }) {
  const t = useT();
  const { creds, vault, error: vaultError } = useCredentials(core);
  const [cred, setCred] = useState("");
  const [devices, setDevices] = useState("");
  const [commands, setCommands] = useState(["show version", "show ip interface brief"].join("\n"));
  const [accept, setAccept] = useState("");
  const [note, setNote] = useState("");
  const [picked, setPicked] = useState("");
  const [view, setView] = useState<ViewName>("matrix");
  const r = useResult<AdhocResult | null>();
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

  const run = () => {
    setNote(""); setPicked("");
    return r.run(async () => {
      const targets = parseTargets(devices).map(parseTarget);
      // Con varios equipos una huella sin equipo no se manda: valdría para cualquiera. El campo viejo ya no se usa.
      const keys = resolveAccepted(accept, targets);
      if (keys.ambiguous) throw new Error(t("fps.needHost"));
      const st = await core.adhocStart(targets, cred, commands, [], keys.keys);
      if (!st.armed) { setNote(t("adhoc.unarmed", { job: st.jobId, detail: st.detail })); return null; }
      const deadline = Date.now() + maxWaitMs;
      for (;;) {
        const res = await core.adhocResult(st.jobId);
        if (!alive.current) return null;
        if (res.done) {
          if (res.error) throw new Error(t("adhoc.failed", { job: st.jobId, error: res.error }));
          if (!res.report) throw new Error(t("adhoc.empty", { job: st.jobId, state: jobState(t, res.state) }));
          return res;
        }
        if (Date.now() >= deadline) throw new Error(t("adhoc.timeout", { job: st.jobId, state: jobState(t, res.state), secs: Math.round(maxWaitMs / 1000) }));
        await new Promise((ok) => setTimeout(ok, pollMs));
      }
    });
  };

  const res = r.data;
  const rows = res?.report?.rows ?? [];
  const failed = rows.filter((x) => !x.ok).length;
  const viewLabel: Record<ViewName, string> = { matrix: t("adhoc.view.matrix"), host: t("adhoc.view.host"), table: t("adhoc.view.table"), csv: "CSV", markdown: "Markdown" };
  const status = r.busy ? { tone: "info" as const, label: t("adhoc.status.running") }
    : r.error ? { tone: "bad" as const, label: t("adhoc.status.failed") }
    : failed ? { tone: "warn" as const, label: t("adhoc.status.partial", { n: failed }) }
    : res ? { tone: "ok" as const, label: t("adhoc.status.done") } : undefined;
  const started = r.busy || !!res || !!r.error;

  return (
    <Page title={t("adhoc.title")} description={t("adhoc.hint")}>
      <CredentialSelect creds={creds} vault={vault} vaultError={vaultError} value={cred} onChange={setCred} w="lg" />
      <TextArea label={t("adhoc.devices")} value={devices} onChange={setDevices} rows={3} />
      <TextArea label={t("adhoc.commands")} value={commands} onChange={setCommands} rows={5} />
      <Field label={t("fps.accepted")} hint={t("fps.accepted.hint.multi")} value={accept} onChange={setAccept} w="lg" mono />
      <div className="actions">
        <RunButton primary kbd busy={r.busy} onClick={run} missing={[!cred && t("need.cred"), !devices.trim() && t("need.targets"), !commands.trim() && t("need.commands")]}>
          {t(r.busy ? "adhoc.running" : "adhoc.run")}
        </RunButton>
      </div>
      {note && <Notice kind="warn">{note}</Notice>}
      {!started && !note && <EmptyState icon="layers" title={t("adhoc.empty.title")}>{t("adhoc.empty.text")}</EmptyState>}
      {started && (
        <ResultPanel title={t("common.output")} status={status} error={r.error}
          meta={res ? t("adhoc.caption", { rows: plural(t, "unit.row", rows.length), devices: res.report ? plural(t, "unit.device", res.report.devices) : "" }) : undefined}
          actions={res && (
            <>
              <nav aria-label={t("adhoc.viewLabel")} className="view-switch">
                {views.map((v) => <button key={v} className="quiet sm" aria-current={view === v ? "true" : undefined} onClick={() => setView(v)}>{viewLabel[v]}</button>)}
              </nav>
              <ExportMenu name={t("file.lote")} formats={[{ fmt: "csv", data: () => res.csv }, { fmt: "md", data: () => res.markdown }]} />
            </>
          )}>
          {r.busy && <p className="panel-body meta">{t("adhoc.waiting")}</p>}
          {res && view === "matrix" && <AdhocMatrix rows={rows} commands={res.report?.commands ?? []} picked={picked} onPick={setPicked} />}
          {res && view === "host" && <Terminal text={res.text} aria-label={t("adhoc.view.host")} />}
          {res && view === "table" && (
            <div className="table-wrap flat adhoc-table">
              <table>
                <thead><tr><th>{t("adhoc.col.device")}</th><th>{t("adhoc.col.command")}</th><th>{t("adhoc.col.status")}</th><th>{t("common.output")}</th></tr></thead>
                <tbody>{rows.map((x, i) => (
                  <tr key={i} data-fail={x.ok ? undefined : "1"}>
                    <td className="mono">{x.device}</td>
                    <td><code>{x.command}</code></td>
                    <td>{t(x.ok ? "adhoc.ok" : "adhoc.noOutput")}</td>
                    <td><pre className="code"><Hl text={x.ok ? x.output : x.note ?? ""} /></pre></td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
          {res && view === "csv" && <textarea className="export" aria-label={viewLabel.csv} readOnly rows={12} value={res.csv} />}
          {res && view === "markdown" && <textarea className="export" aria-label={viewLabel.markdown} readOnly rows={12} value={res.markdown} />}
        </ResultPanel>
      )}
    </Page>
  );
}
