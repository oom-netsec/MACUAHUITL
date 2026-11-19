import { Advanced } from "../../components/Advanced";
import { RunButton } from "../../components/RunButton";
import { useContext, useEffect, useId, useState } from "react";
import type { CoreAPI, NetInterface } from "../../lib/core";
import { Check, Field, Notice, Select } from "../../components/Field";
import { EmptyState, Page, ResultPanel } from "../../components/Page";
import { Terminal } from "../../components/Terminal";
import { CopyButton } from "../../components/Data";
import { ModuleIdContext, useInbox, useNav } from "../../app/activity";
import { useT } from "../../lib/i18n";
import { useDiagRun, type DiagSpec } from "./useDiagRun";
import { PingOptions, PingSummaryCard, SweepTable } from "./PingExt";
import { PING_FORM0, ipFamily, patchForm, pingOptions, type PingForm } from "./pingOpts";
import { DiagViz } from "./DiagViz";
import { isWindows } from "../../lib/platform"; // ADR 0012 (i): en Windows el SYN necesita Npcap, fuera del producto
import "./diag.css";

export type ToolName = "ping" | "traceroute" | "nmap" | "iperf3" | "pcap";

// Cada herramienta tiene opciones cerradas (spec §9): no hay línea de comandos libre.
export function DiagView({ core, tool }: { core: CoreAPI; tool: ToolName }) {
  const t = useT();
  const go = useNav();
  const [target, setTarget] = useState("");
  const [pf, setPf] = useState<PingForm>(PING_FORM0);
  const setP = (p: Partial<PingForm>) => setPf((f) => patchForm(f, p));
  const count = pf.count;
  const ping = pingOptions(pf, isWindows());
  const [hops, setHops] = useState("30");
  const [ports, setPorts] = useState("");
  const [scan, setScan] = useState<"connect" | "syn" | "udp" | "ping">("connect");
  const [skipDisc, setSkipDisc] = useState(false);
  const pnWhy = useId();
  const [mode, setMode] = useState<"client" | "server">("client");
  const [seconds, setSeconds] = useState("10");
  const [iface, setIface] = useState("any");
  const [bind, setBind] = useState("");
  const [port, setPort] = useState("5201");
  const [ifaces, setIfaces] = useState<NetInterface[]>([]);
  const [ifState, setIfState] = useState<"loading" | "ok" | "error">("loading");
  const [filter, setFilter] = useState("");
  const { runId, lines, setLines, result, summary, sweep, stoppable, fam, interval, t0, err, launching, started, start, stop, cancel } = useDiagRun(core);
  // El menú de equipo manda la dirección al módulo con su id (ping, traceroute…); cada instancia toma solo la suya.
  const moduleId = useContext(ModuleIdContext);
  const needsTarget = tool !== "pcap" && !(tool === "iperf3" && mode === "server");
  useInbox(moduleId, (addr) => { if (needsTarget) setTarget(addr); });
  // La vista queda montada toda la sesión: las interfaces se vuelven a leer al pasar a servidor y antes de arrancarlo (DHCP, VPN).
  const loadIfaces = () => core.listInterfaces().then((l) => { setIfaces(l ?? []); setIfState("ok"); return l ?? []; }, () => { setIfaces([]); setIfState("error"); return [] as NetInterface[]; });
  useEffect(() => {
    if (tool === "pcap" || tool === "iperf3" || tool === "ping") void loadIfaces();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- loadIfaces solo usa core
  }, [core, tool, mode]);

  // El servidor iperf3 escucha en una IP de esta máquina (nunca en todas; link-local no sirve con -B) y en un puerto alto (≥ 1024; en Windows, 1-65535: no hay puertos privilegiados, ADR 0012 (h)).
  const server = tool === "iperf3" && mode === "server";
  const binds = localIPs(ifaces);
  const bindIP = binds.includes(bind) ? bind : binds[0] ?? "";
  const portOk = (isWindows() ? /^[1-9]\d{0,4}$/ : /^[1-9]\d{3,4}$/).test(port) && Number(port) <= 65535; // sin ceros a la izquierda: el núcleo los rechaza
  const run = () => start(async () => {
    if (server && !localIPs(await loadIfaces()).includes(bindIP)) return t("diag.bind.gone", { ip: bindIP }); // la IP ya no está (DHCP, VPN)
    const options: Record<string, string> = {};
    let targets: string[] = [];
    let extra: Partial<DiagSpec> = {};
    switch (tool) {
      case "ping": Object.assign(options, ping.options); targets = [target]; extra = { stoppable: !!(ping.options.continuous || ping.options.duration), fam: (ping.options.family as "4" | "6" | undefined) ?? (ipFamily(target.trim()) ? String(ipFamily(target.trim())) as "4" | "6" : "?"), interval: Number(ping.options.interval) || 1 }; break;
      case "traceroute": options.max_hops = hops; targets = [target]; break;
      case "nmap": options.scan = scan; if (ports && scan !== "ping") options.ports = ports; if (skipDisc && scan !== "ping") options.skip_discovery = "true"; targets = [target]; break; // -Pn con scan=ping: diag.err.skip_with_ping
      case "iperf3": options.mode = mode; if (mode === "client") { options.seconds = seconds; targets = [target]; } else { options.bind = bindIP; options.port = port; } break;
      case "pcap": options.interface = iface; options.seconds = seconds; if (filter) options.filter = filter; break;
    }
    return { tool, targets, options, ...extra };
  });

  const status = runId ? { tone: "info" as const, label: t("diag.status.running") }
    : result?.canceled ? { tone: "" as const, label: t("diag.status.canceled") }
    : result ? (result.ok ? { tone: "ok" as const, label: t("diag.status.done") } : { tone: "bad" as const, label: t("diag.status.failed") }) : undefined;

  return (
    <Page title={t(`diag.title.${tool}`)} description={t(`diag.desc.${tool}`)}>
      <div className="field-row">
        {needsTarget && <Field label={t("diag.target")} hint={t("diag.target.hint")} value={target} onChange={setTarget} w="lg" mono />}
        {tool === "ping" && <Field label={t("diag.count")} type="number" value={count} onChange={(count) => setP({ count })} w="sm" disabled={pf.continuous} error={ping.errors.count ? t(ping.errors.count) : undefined} />}
        {tool === "nmap" && scan !== "ping" && <Field label={t("diag.ports")} hint={t("diag.ports.hint")} value={ports} onChange={setPorts} w="md" mono />}
        {tool === "iperf3" && <Select label={t("diag.mode")} value={mode} onChange={setMode} options={[["client", t("diag.mode.client")], ["server", t("diag.mode.server")]]} w="md" />}
        {((tool === "iperf3" && !server) || tool === "pcap") && <Field label={t("diag.seconds")} type="number" value={seconds} onChange={setSeconds} w="sm" />}
        {server && binds.length > 0 && <Select label={t("diag.bind")} value={bindIP} onChange={setBind} options={binds.map((a) => [a, a] as [string, string])} w="md" />}
      </div>
      {tool === "traceroute" && (
        <Advanced changed={hops !== "30" ? 1 : 0}>
          <Field label={t("diag.hops")} type="number" value={hops} onChange={setHops} w="sm" />
        </Advanced>
      )}
      {server && (
        <Advanced forceOpen={!portOk} changed={port !== "5201" ? 1 : 0}>
          <Field label={t("diag.port")} hint={t("diag.port.hint")} value={port} onChange={setPort} error={portOk ? undefined : t("diag.port.invalid")} inputMode="numeric" w="sm" mono />
        </Advanced>
      )}
      {server && ifState !== "loading" && binds.length === 0 && <Notice kind="warn">{t(ifState === "error" ? "diag.bind.error" : "diag.bind.none")}</Notice>}
      {tool === "ping" && <PingOptions form={pf} set={setP} errors={ping.errors} active={ping.active} ifaces={ifaces} disabled={!!runId} />}
      {tool === "nmap" && (
        <Select label={t("diag.scan")} value={scan} onChange={setScan} w="lg"
          options={([["connect", t("diag.scan.connect")], ["syn", t("diag.scan.syn")], ["udp", t("diag.scan.udp")], ["ping", t("diag.scan.ping")]] as [typeof scan, string][])
            .filter(([v]) => v !== "syn" || !isWindows())} />
      )}
      {tool === "nmap" && <Check label={t("diag.skipDiscovery")} checked={skipDisc && scan !== "ping"} onChange={setSkipDisc} disabled={scan === "ping"} describedBy={scan === "ping" ? pnWhy : undefined} />}
      {tool === "nmap" && scan === "ping" && <p className="hint" id={pnWhy}>{t("diag.skipDiscovery.ping")}</p>}
      {tool === "pcap" && (
        <>
          <div className="field-row">
            <Select label={t("diag.iface")} value={iface} onChange={setIface} w="lg" options={[
              ["any", t("diag.iface.any")],
              ...ifaces.map((i) => [i.name, !i.up ? `${i.name} · ${t("diag.iface.down")}` : i.addresses.length ? `${i.name} · ${i.addresses.join(", ")}` : i.name] as [string, string]),
            ]} />
          </div>
          <Advanced changed={filter ? 1 : 0}>
            <Field label={t("diag.filter")} hint={t("diag.filter.hint")} value={filter} onChange={setFilter} w="lg" mono />
          </Advanced>
          <p className="hint">{t("diag.pcap.req")}</p>
        </>
      )}
      <div className="actions">
        <RunButton primary kbd onClick={run} busy={!!runId} disabled={launching}
          missing={[tool === "ping" && Object.keys(ping.errors).length > 0 && t("need.fixFields"), needsTarget && !target.trim() && t("need.target"), server && !bindIP && t("need.bindIP"), server && !portOk && t("need.portValid")]}>{t("common.run")}</RunButton>
        {stoppable && <button onClick={stop} disabled={!runId}>{t("diag.stop")}</button>}
        <button onClick={cancel} disabled={!runId}>{t("common.cancel")}</button>
      </div>
      {!started && <EmptyState icon="pulse" title={t("diag.empty.title")}>{t("diag.empty")}</EmptyState>}
      {tool === "ping" && summary && <PingSummaryCard s={summary} />}
      {tool === "ping" && sweep.length > 0 && <SweepTable points={sweep} fam={fam} />}
      {started && <DiagViz tool={tool} lines={lines} t0={t0} interval={interval} path={result?.ok ? result.path : undefined} />}
      {started && (
        <ResultPanel title={t("common.output")} status={status} error={err || (result && !result.ok && !result.canceled ? result.text : "")}
          meta={result?.ok ? t("diag.done", { code: result.code ?? 0, path: result.path ?? "" }) : result?.canceled ? result.text : undefined}
          actions={<>
            {tool === "pcap" && result?.ok && result.path && <button className="primary sm" onClick={() => go("pcap", result.path)}>{t("diag.analyze")}</button>}
            {lines.length > 0 && <CopyButton value={lines.join("\n")} label={t("common.output")} />}
            <button className="quiet sm" disabled={!lines.length || !!runId} onClick={() => setLines([])}>{t("common.clear")}</button>
          </>}>
          <Terminal text={lines.join("\n")} role="log" aria-label={t("common.output")} />
        </ResultPanel>
      )}
    </Page>
  );
}

// IPs de esta máquina donde puede escuchar el servidor iperf3: interfaces arriba, sin prefijo ni zona, sin 0.0.0.0/::
// ni link-local (fe80::/10, 169.254/16); primero las que no son loopback.
export function localIPs(ifaces: NetInterface[]): string[] {
  const ok = (a: string) => a && a !== "0.0.0.0" && a !== "::" && !/^fe[89ab]/i.test(a) && !a.startsWith("169.254.");
  const up = ifaces.filter((i) => i.up);
  const ips = (l: NetInterface[]) => l.flatMap((i) => i.addresses.map((a) => a.replace(/\/\d+$/, "").replace(/%.*$/, ""))).filter(ok);
  return [...new Set([...ips(up.filter((i) => !i.loopback)), ...ips(up.filter((i) => i.loopback))])];
}
