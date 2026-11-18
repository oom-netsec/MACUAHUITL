// Ping y traceroute sobre el mismo destino (decisión del dueño): casillas, un solo Ejecutar y un panel por herramienta.
// Cada una corre con su propio diagRun (useDiagRun), así que Detener en un panel no corta el otro.
import { useEffect, useState } from "react";
import { Advanced } from "../../components/Advanced";
import { RunButton } from "../../components/RunButton";
import { Check, Field } from "../../components/Field";
import { EmptyState, Page, ResultPanel } from "../../components/Page";
import { Terminal } from "../../components/Terminal";
import { CopyButton } from "../../components/Data";
import { useInbox } from "../../app/activity";
import { useT } from "../../lib/i18n";
import type { CoreAPI, NetInterface } from "../../lib/core";
import { PingOptions, PingSummaryCard, SweepTable } from "./PingExt";
import { PING_FORM0, ipFamily, patchForm, pingOptions } from "./pingOpts";
import { DiagViz } from "./DiagViz";
import { useDiagRun } from "./useDiagRun";
import type { ResolvedTarget } from "./api";
import { isWindows } from "../../lib/platform";
import "./diag.css";

type Run = ReturnType<typeof useDiagRun>;
const famName = (f: string) => (f === "ipv6" ? "IPv6" : "IPv4");

function ToolPanel({ tool, run }: { tool: "ping" | "traceroute"; run: Run }) {
  const t = useT();
  const { runId, lines, result, summary, sweep, stoppable, fam, interval, t0, err } = run;
  const status = runId ? { tone: "info" as const, label: t("diag.status.running") }
    : result?.canceled ? { tone: "" as const, label: t("diag.status.canceled") }
    : result ? (result.ok ? { tone: "ok" as const, label: t("diag.status.done") } : { tone: "bad" as const, label: t("diag.status.failed") }) : undefined;
  return (
    <div data-tool={tool}>
      {tool === "ping" && summary && <PingSummaryCard s={summary} />}
      {tool === "ping" && sweep.length > 0 && <SweepTable points={sweep} fam={fam} />}
      <DiagViz tool={tool} lines={lines} t0={t0} interval={interval} path={result?.ok ? result.path : undefined} />
      <ResultPanel title={t(`diag.title.${tool}`)} status={status} error={err || (result && !result.ok && !result.canceled ? result.text : "")}
        meta={result?.ok ? t("diag.done", { code: result.code ?? 0, path: result.path ?? "" }) : result?.canceled ? result.text : undefined}
        actions={<>
          {/* Un ping continuo se detiene con resumen (Detener) y además se puede cortar (Cancelar); lo demás solo se corta. */}
          <button className="sm" onClick={stoppable ? run.stop : run.cancel} disabled={!runId} aria-label={t("diag.stopTool", { tool })}>{t("diag.stop")}</button>
          {stoppable && <button className="sm" onClick={run.cancel} disabled={!runId} aria-label={t("diag.cancelTool", { tool })}>{t("common.cancel")}</button>}
          {lines.length > 0 && <CopyButton value={lines.join("\n")} label={t(`diag.title.${tool}`)} />}
          <button className="quiet sm" disabled={!lines.length || !!runId} onClick={() => run.setLines([])} aria-label={t("diag.clearTool", { tool })}>{t("common.clear")}</button>
        </>}>
        <Terminal text={lines.join("\n")} role="log" aria-label={t(`diag.title.${tool}`)} />
      </ResultPanel>
    </div>
  );
}

export function PingTraceView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [target, setTarget] = useState("");
  const [doPing, setDoPing] = useState(true);
  const [doTrace, setDoTrace] = useState(false);
  const [pf, setPf] = useState(PING_FORM0);
  const setP = (p: Partial<typeof pf>) => setPf((f) => patchForm(f, p));
  const [hops, setHops] = useState("30");
  const [ifaces, setIfaces] = useState<NetInterface[]>([]);
  const ping = pingOptions(pf, isWindows());
  const pingRun = useDiagRun(core);
  const traceRun = useDiagRun(core);
  // El menú de equipo manda la dirección y la herramienta («ping» o «traceroute») a este módulo.
  useInbox("ping", setTarget);
  useInbox("ping-tool", (tool) => { setDoPing(tool === "ping"); setDoTrace(tool === "traceroute"); });
  useEffect(() => { void core.listInterfaces().then((l) => setIfaces(l ?? []), () => setIfaces([])); }, [core]);

  const [ran, setRan] = useState({ ping: false, trace: false }); // herramientas de la última ejecución: lo de la otra ya no es de este destino
  const busy = !!pingRun.runId || !!traceRun.runId;
  const run = () => {
    setRan({ ping: doPing, trace: doTrace });
    if (doPing) void pingRun.start(() => ({
      tool: "ping", targets: [target], options: ping.options, stoppable: !!(ping.options.continuous || ping.options.duration),
      fam: (ping.options.family as "4" | "6" | undefined) ?? (ipFamily(target.trim()) ? String(ipFamily(target.trim())) as "4" | "6" : "?"), interval: Number(ping.options.interval) || 1,
    }));
    if (doTrace) void traceRun.start(() => ({ tool: "traceroute", targets: [target], options: { max_hops: hops } }));
  };
  // Si ping y traceroute resolvieron distinto (p. ej. familias distintas) se muestran las dos; el nombre igual a la IP no se resolvió nada.
  const res: [string, ResolvedTarget][] = ([["ping", ran.ping && pingRun.resolved], ["traceroute", ran.trace && traceRun.resolved]] as const)
    .filter((x): x is readonly ["ping" | "traceroute", ResolvedTarget] => !!x[1] && x[1].name !== x[1].ip).map(([k, r]) => [k, r]);
  const same = res.length === 2 && res[0][1].ip === res[1][1].ip;
  const shown = same ? res.slice(0, 1) : res;

  return (
    <Page title={t("diag.title.pingTrace")} description={t("diag.desc.pingTrace")}>
      <div className="field-row">
        <Field label={t("diag.target")} hint={t("diag.target.hint")} value={target} onChange={setTarget} w="lg" mono />
        {doPing && <Field label={t("diag.count")} type="number" value={pf.count} onChange={(count) => setP({ count })} w="sm" disabled={pf.continuous} error={ping.errors.count ? t(ping.errors.count) : undefined} />}
      </div>
      <div className="field-row" role="group" aria-label={t("diag.pt.tools")}>
        <Check label={t("diag.title.ping")} checked={doPing} onChange={setDoPing} />
        <Check label={t("diag.title.traceroute")} checked={doTrace} onChange={setDoTrace} />
      </div>
      {doTrace && (
        <Advanced changed={hops !== "30" ? 1 : 0}>
          <Field label={t("diag.hops")} type="number" value={hops} onChange={setHops} w="sm" />
        </Advanced>
      )}
      {doPing && <PingOptions form={pf} set={setP} errors={ping.errors} active={ping.active} ifaces={ifaces} disabled={!!pingRun.runId} />}
      <div className="actions">
        <RunButton primary kbd onClick={run} busy={busy} disabled={pingRun.launching || traceRun.launching}
          missing={[doPing && Object.keys(ping.errors).length > 0 && t("need.fixFields"), !doPing && !doTrace && t("need.diagTool"), !target.trim() && t("need.target")]}>{t("common.run")}</RunButton>
      </div>
      {shown.length > 0 && (
        <p className="meta" aria-label={t("diag.resolved.label")}>
          {shown.map(([k, r]) => <span key={k}>{shown.length > 1 && `${t(k === "ping" ? "diag.title.ping" : "diag.title.traceroute")}: `}{t("diag.resolved", { name: r.name, ip: r.ip, family: famName(r.family) })} </span>)}
        </p>
      )}
      {!(ran.ping && pingRun.started) && !(ran.trace && traceRun.started) && <EmptyState icon="pulse" title={t("diag.empty.title")}>{t("diag.empty")}</EmptyState>}
      {ran.ping && pingRun.started && <ToolPanel tool="ping" run={pingRun} />}
      {ran.trace && traceRun.started && <ToolPanel tool="traceroute" run={traceRun} />}
    </Page>
  );
}
