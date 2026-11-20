import { plural } from "../../lib/plural";
import { CredentialSelect, useCredentials } from "../../components/CredentialSelect";
import { useEffect, useRef, useState } from "react";
import type { AdhocResult, AdhocStart, CoreAPI } from "../../lib/core";
import { Notice, TextArea } from "../../components/Field";
import { RunButton } from "../../components/RunButton";
import { ExportMenu } from "../../components/Files";
import { AdhocMatrix } from "./AdhocMatrix";
import { EmptyState, Page, ResultPanel, useResult } from "../../components/Page";
import { Hl, Terminal } from "../../components/Terminal";
import { parseTarget, parseTargets } from "../../lib/targets";
import { useT } from "../../lib/i18n";
import { jobState } from "../../lib/vocab";
import "./adhoc.css";
import { type AcceptedKey, type HostKeyInfo, hostKeysFromErr, pendingToInfo } from "../../lib/hostkeys";
import { TargetsField } from "../inventory/TargetField";
import { HostKeyTrust } from "../../components/HostKeyTrust";

// Lotes: comandos de solo lectura en varios equipos, como un trabajo de Patrol de una ronda.
// El núcleo rechaza todo comando que no sea de lectura; la app no aplica configuración.

const views = ["matrix", "host", "table", "csv", "markdown"] as const;
type ViewName = (typeof views)[number];

// maxWaitMs: tope de la espera del resultado; pasado, se deja de preguntar (el trabajo sigue en Patrol).
export function AdhocView({ core, pollMs = 700, maxWaitMs = 15 * 60_000 }: { core: CoreAPI; pollMs?: number; maxWaitMs?: number }) {
  const t = useT();
  const { creds, vault, error: vaultError } = useCredentials(core);
  const [cred, setCred] = useState("");
  const [devices, setDevices] = useState("");
  const [commands, setCommands] = useState(["show version", "show ip interface brief"].join("\n"));
  const [hks, setHks] = useState<HostKeyInfo[]>([]); // huellas pendientes que devolvió el núcleo al no armar el lote
  const [unarmed, setUnarmed] = useState(""); // trabajo creado sin armar: «Confiar y reintentar» lo arma, no crea otro
  const [note, setNote] = useState("");
  const [picked, setPicked] = useState("");
  const [view, setView] = useState<ViewName>("matrix");
  const r = useResult<AdhocResult | null>();
  const gen = useRef(0); // generación: una respuesta de una llamada anterior a una edición no fija huellas ni trabajo
  const clearHks = () => { gen.current++; setHks([]); setUnarmed(""); };
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

  // accept: pares (equipo, huella) aceptados con un clic en «Confiar y reintentar», solo para este reintento.
  const run = (accept: AcceptedKey[] = []) => {
    setNote(""); setPicked("");
    const job = accept.length ? unarmed : "";
    clearHks();
    const mine = gen.current;
    return r.run(async () => {
      let st: AdhocStart = { jobId: job, armed: true, detail: "" };
      if (job) {
        try { await core.armJob(job, [], accept, []); } // mismo trabajo (ya tiene sus equipos y comandos)
        catch (e) { // otro equipo sigue sin confiar: el panel vuelve con las huellas del error de ArmJob, y el error se muestra
          if (gen.current === mine) { setUnarmed(job); setHks(hostKeysFromErr(e)); }
          throw e;
        }
      }
      else st = await core.adhocStart(parseTargets(devices).map(parseTarget), cred, commands, [], accept);
      if (!st.armed) {
        if (gen.current !== mine) return null; // se editó el pedido durante la llamada: esta respuesta ya no vale
        setNote(t("adhoc.unarmed", { job: st.jobId, detail: st.detail }));
        setUnarmed(st.jobId);
        setHks(pendingToInfo(st.hostKeys)); // el núcleo ya trae las huellas: no hace falta un Login Test
        return null;
      }
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
      <CredentialSelect creds={creds} vault={vault} vaultError={vaultError} value={cred} onChange={(v) => { setCred(v); clearHks(); }} w="lg" />
      <TargetsField core={core} value={devices} onChange={(v) => { setDevices(v); clearHks(); }} onPickCredential={(id) => { if (!cred && creds.some((c) => c.id === id)) { setCred(id); clearHks(); } }} />
      <TextArea label={t("adhoc.commands")} value={commands} onChange={(v) => { setCommands(v); clearHks(); }} rows={5} />
      <div className="actions">
        <RunButton primary kbd busy={r.busy} onClick={() => run()} missing={[!cred && t("need.cred"), !devices.trim() && t("need.targets"), !commands.trim() && t("need.commands")]}>
          {t(r.busy ? "adhoc.running" : "adhoc.run")}
        </RunButton>
      </div>
      {note && <Notice kind="warn">{note}</Notice>}
      {hks.length > 0 && <HostKeyTrust items={hks} busy={r.busy} onTrust={run} />}
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
