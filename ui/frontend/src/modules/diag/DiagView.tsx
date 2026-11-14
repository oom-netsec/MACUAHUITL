import { useContext, useEffect, useRef, useState } from "react";
import type { CoreAPI, DiagEvent, NetInterface } from "../../lib/core";
import { Field, Select, errorText } from "../../components/Field";
import { EmptyState, Page, ResultPanel } from "../../components/Page";
import { Terminal } from "../../components/Terminal";
import { Icon } from "../../components/Icon";
import { ModuleIdContext, useBusy, useInbox, useNav } from "../../app/activity";
import { useT } from "../../lib/i18n";
import { outputsErrorText } from "../../lib/outputsError";
import { DiagViz } from "./DiagViz";
import "./diag.css";

export type ToolName = "ping" | "traceroute" | "nmap" | "iperf3" | "pcap";

// Cada herramienta tiene opciones cerradas (spec §9): no hay línea de comandos libre.
export function DiagView({ core, tool }: { core: CoreAPI; tool: ToolName }) {
  const t = useT();
  const go = useNav();
  const [target, setTarget] = useState("");
  const [count, setCount] = useState("4");
  const [hops, setHops] = useState("30");
  const [ports, setPorts] = useState("");
  const [scan, setScan] = useState<"connect" | "syn" | "udp" | "ping">("connect");
  const [mode, setMode] = useState<"client" | "server">("client");
  const [seconds, setSeconds] = useState("10");
  const [iface, setIface] = useState("any");
  const [ifaces, setIfaces] = useState<NetInterface[]>([]);
  const [filter, setFilter] = useState("");
  const [runId, setRunId] = useState("");
  const [lines, setLines] = useState<string[]>([]);
  const [result, setResult] = useState<{ ok: boolean; text: string; code?: number; path?: string; canceled?: boolean } | null>(null);
  const [copied, setCopied] = useState(false);
  const [t0, setT0] = useState(0); // inicio de la ejecución en segundos Unix: eje de tiempo de las gráficas
  const [err, setErr] = useState("");
  // Eventos que llegan antes de conocer el ID de la ejecución (un fallo inmediato, la primera línea).
  // Solo se guardan mientras arranca: con varias vistas montadas, una inactiva no acumula lo ajeno.
  const pending = useRef<DiagEvent[]>([]);
  const starting = useRef(false);
  const [launching, setLaunching] = useState(false); // igual que starting pero visible: apaga el botón mientras arranca
  const runRef = useRef("");
  useBusy(!!runId);
  // El menú de equipo manda la dirección al módulo con su id (ping, traceroute…); cada instancia toma solo la suya.
  const moduleId = useContext(ModuleIdContext);
  const needsTarget = tool !== "pcap" && !(tool === "iperf3" && mode === "server");
  useInbox(moduleId, (addr) => { if (needsTarget) setTarget(addr); });
  useEffect(() => {
    if (tool === "pcap") core.listInterfaces().then(setIfaces).catch(() => setIfaces([]));
  }, [core, tool]);

  const apply = (e: DiagEvent) => {
    if (e.done) {
      setResult(e.canceled ? { ok: false, canceled: true, text: t("diag.canceled") } : e.error
        ? { ok: false, text: t("diag.error", { msg: errorText(new Error(e.error)) }) }
        : { ok: true, text: t("diag.done", { code: e.exitCode ?? 0, path: e.outputPath ?? "" }), code: e.exitCode ?? 0, path: e.outputPath });
      runRef.current = "";
      setRunId("");
    } else if (e.line !== undefined) {
      setLines((l) => (l.length > 5000 ? [...l.slice(-4000), e.line!] : [...l, e.line!]));
    }
  };
  const applyRef = useRef(apply); // el suscriptor se crea una vez: sin esto se quedaría con el t del primer render
  applyRef.current = apply;
  useEffect(
    () =>
      core.onDiag((e: DiagEvent) => {
        if (starting.current) {
          pending.current.push(e);
          return;
        }
        if (e.runId === runRef.current) applyRef.current(e);
      }),
    [core],
  );

  const run = async () => {
    setErr(""); setLines([]); setResult(null); setT0(Math.floor(Date.now() / 1000));
    const options: Record<string, string> = {};
    let targets: string[] = [];
    switch (tool) {
      case "ping": options.count = count; targets = [target]; break;
      case "traceroute": options.max_hops = hops; targets = [target]; break;
      case "nmap": options.scan = scan; if (ports) options.ports = ports; targets = [target]; break;
      case "iperf3": options.mode = mode; if (mode === "client") { options.seconds = seconds; targets = [target]; } break;
      case "pcap": options.interface = iface; options.seconds = seconds; if (filter) options.filter = filter; break;
    }
    pending.current = [];
    runRef.current = "";
    starting.current = true; setLaunching(true);
    try {
      const id = await core.diagRun(tool, targets, options);
      runRef.current = id;
      setRunId(id);
      starting.current = false;
      const early = pending.current.filter((e) => e.runId === id);
      pending.current = [];
      early.forEach((e) => applyRef.current(e));
    } catch (e) {
      starting.current = false;
      setErr(outputsErrorText(errorText(e), t));
    } finally {
      setLaunching(false);
    }
  };
  const cancel = () => core.diagCancel(runId).catch((e) => setErr(errorText(e)));

  const copy = async () => { await core.copyText(lines.join("\n")); setCopied(true); window.setTimeout(() => setCopied(false), 1500); };
  const status = runId ? { tone: "info" as const, label: t("diag.status.running") }
    : result?.canceled ? { tone: "" as const, label: t("diag.status.canceled") }
    : result ? (result.ok ? { tone: "ok" as const, label: t("diag.status.done") } : { tone: "bad" as const, label: t("diag.status.failed") }) : undefined;
  const started = !!runId || lines.length > 0 || !!result || !!err;

  return (
    <Page title={t(`diag.title.${tool}`)} description={t(`diag.desc.${tool}`)}>
      <div className="field-row">
        {needsTarget && <Field label={t("diag.target")} hint={t("diag.target.hint")} value={target} onChange={setTarget} w="lg" mono />}
        {tool === "ping" && <Field label={t("diag.count")} type="number" value={count} onChange={setCount} w="sm" />}
        {tool === "traceroute" && <Field label={t("diag.hops")} type="number" value={hops} onChange={setHops} w="sm" />}
        {tool === "nmap" && <Field label={t("diag.ports")} hint={t("diag.ports.hint")} value={ports} onChange={setPorts} w="md" mono />}
        {tool === "iperf3" && <Select label={t("diag.mode")} value={mode} onChange={setMode} options={[["client", t("diag.mode.client")], ["server", t("diag.mode.server")]]} w="md" />}
        {(tool === "iperf3" || tool === "pcap") && <Field label={t("diag.seconds")} type="number" value={seconds} onChange={setSeconds} w="sm" />}
      </div>
      {tool === "nmap" && (
        <Select label={t("diag.scan")} value={scan} onChange={setScan} w="lg"
          options={[["connect", t("diag.scan.connect")], ["syn", t("diag.scan.syn")], ["udp", t("diag.scan.udp")], ["ping", t("diag.scan.ping")]]} />
      )}
      {tool === "pcap" && (
        <>
          <div className="field-row">
            <Select label={t("diag.iface")} value={iface} onChange={setIface} w="lg" options={[
              ["any", t("diag.iface.any")],
              ...ifaces.map((i) => [i.name, !i.up ? `${i.name} · ${t("diag.iface.down")}` : i.addresses.length ? `${i.name} · ${i.addresses.join(", ")}` : i.name] as [string, string]),
            ]} />
            <Field label={t("diag.filter")} hint={t("diag.filter.hint")} value={filter} onChange={setFilter} w="lg" mono />
          </div>
          <p className="hint">{t("diag.pcap.req")}</p>
        </>
      )}
      <div className="actions">
        <button className="primary" onClick={run} disabled={!!runId || launching || (needsTarget && !target.trim())} aria-busy={!!runId}>{t("common.run")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
        <button onClick={cancel} disabled={!runId}>{t("common.cancel")}</button>
      </div>
      {!started && <EmptyState icon="pulse" title={t("diag.empty.title")}>{t("diag.empty")}</EmptyState>}
      {started && <DiagViz tool={tool} lines={lines} t0={t0} path={result?.ok ? result.path : undefined} />}
      {started && (
        <ResultPanel title={t("common.output")} status={status} error={err || (result && !result.ok && !result.canceled ? result.text : "")}
          meta={result?.ok ? t("diag.done", { code: result.code ?? 0, path: result.path ?? "" }) : result?.canceled ? result.text : undefined}
          actions={<>
            {tool === "pcap" && result?.ok && result.path && <button className="primary sm" onClick={() => go("pcap", result.path)}>{t("diag.analyze")}</button>}
            <button className="quiet sm" disabled={!lines.length} onClick={copy}><Icon name="copy" size={14} />{t(copied ? "common.copied" : "common.copy")}</button>
            <button className="quiet sm" disabled={!lines.length || !!runId} onClick={() => setLines([])}>{t("common.clear")}</button>
          </>}>
          <Terminal text={lines.join("\n")} role="log" aria-label={t("common.output")} />
        </ResultPanel>
      )}
    </Page>
  );
}
