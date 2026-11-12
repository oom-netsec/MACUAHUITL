// Lo que cada herramienta muestra además del texto: se arma leyendo las líneas en vivo (parse.ts), sin API nueva.
import { useMemo } from "react";
import { LazyTimeChart } from "../../components/charts/LazyTimeChart";
import { Meter } from "../../components/charts/Mini";
import { CopyButton, StatusPill } from "../../components/Data";
import { Badge, type Tone } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { captureCount, parseIperf, parseNmap, parsePing, parseTraceroute, pingStats } from "./parse";

type Props = { lines: string[]; t0: number }; // t0: inicio de la ejecución, segundos Unix
const n2 = (n: number) => String(Math.round(n * 100) / 100);
const n1 = (n: number) => Math.round(n * 10) / 10;

// shortcut: supone el intervalo de 1 s de ping; si se agrega -i, usar la hora de llegada de cada línea.
function PingViz({ lines, t0 }: Props) {
  const t = useT();
  const r = useMemo(() => parsePing(lines), [lines]);
  const s = pingStats(r);
  const chart = useMemo(() => {
    const max = Math.max(0, ...r.replies.map((x) => x.seq), ...r.lost);
    const seqs = Array.from({ length: max }, (_, i) => i + 1);
    return {
      times: seqs.map((q) => t0 + q),
      values: seqs.map((q) => r.replies.find((x) => x.seq === q)?.rtt ?? null),
      marks: r.lost.map((q) => ({ at: t0 + q, label: t("diag.ping.lostMark", { seq: q }) })),
    };
  }, [r, t0, t]);
  const series = useMemo(() => [{ label: t("diag.ping.rtt"), values: chart.values }], [chart, t]);
  if (!s) return null;
  return (
    <>
      <LazyTimeChart title={t("diag.ping.chart")} unit="ms" times={chart.times} series={series} marks={chart.marks} fileName="ping-rtt" />
      <section aria-label={t("diag.ping.stats")}>
        <dl className="stats">
          <div><dt>{t("diag.stat.min")}</dt><dd>{n2(s.min)} ms</dd></div>
          <div><dt>{t("diag.stat.avg")}</dt><dd>{n2(s.avg)} ms</dd></div>
          <div><dt>{t("diag.stat.max")}</dt><dd>{n2(s.max)} ms</dd></div>
          <div><dt>{t("diag.stat.jitter")}</dt><dd>{n2(s.jitter)} ms</dd></div>
          <div><dt>{t("diag.stat.loss")}</dt><dd>{t("diag.stat.lossValue", { pct: s.lossPct, lost: r.lost.length, sent: s.sent })}</dd></div>
          <div><dt>{t("diag.stat.lost")}</dt><dd>{r.lost.length ? r.lost.join(", ") : t("diag.stat.none")}</dd></div>
        </dl>
      </section>
    </>
  );
}

function TraceViz({ lines }: Props) {
  const t = useT();
  const hops = useMemo(() => parseTraceroute(lines), [lines]);
  if (!hops.length) return null;
  const avg = hops.map((h) => (h.rtts.length ? n1(h.rtts.reduce((a, b) => a + b, 0) / h.rtts.length) : null));
  const max = Math.max(1, ...avg.map((a) => a ?? 0));
  return (
    <div className="table-wrap hops">
      <table aria-label={t("diag.trace.table")}>
        <thead><tr><th scope="col">{t("diag.trace.hop")}</th><th scope="col">{t("diag.trace.host")}</th><th scope="col">{t("diag.trace.rtt")}</th></tr></thead>
        <tbody>
          {hops.map((h, i) => (
            <tr key={h.hop} data-state={!h.rtts.length ? "bad" : h.stars ? "warn" : undefined}>
              <td className="mono">{h.hop}</td>
              <td className="mono">{h.host ? (h.host === h.address ? h.host : `${h.host} (${h.address})`) : "*"}</td>
              <td>
                {avg[i] === null
                  ? <Badge tone="warn">{t("diag.trace.noreply")}</Badge>
                  : <><Meter value={avg[i]!} max={max} label={t("diag.trace.rttLabel", { n: h.hop })} unit="ms" />{h.stars > 0 && <span className="meta"> · {t("diag.trace.partial", { n: h.stars })}</span>}</>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IperfViz({ lines, t0 }: Props) {
  const t = useT();
  const r = useMemo(() => parseIperf(lines), [lines]);
  const times = useMemo(() => r.points.map((p) => t0 + p.end), [r, t0]);
  const series = useMemo(() => [{ label: t("diag.iperf.chart"), values: r.points.map((p) => p.mbps) }], [r, t]);
  if (!r.points.length) return null;
  const retr = r.points.reduce((a, p) => a + (p.retr ?? 0), 0);
  return (
    <>
      <LazyTimeChart title={t("diag.iperf.chart")} unit="Mbps" times={times} series={series} fileName={t("file.iperf3-rendimiento")} />
      <section aria-label={t("diag.iperf.stats")}>
        <dl className="stats">
          <div><dt>{t("diag.iperf.retr")}</dt><dd>{retr}</dd></div>
          {r.sender !== undefined && <div><dt>{t("diag.iperf.sender")}</dt><dd>{n2(r.sender)} Mbps</dd></div>}
          {r.receiver !== undefined && <div><dt>{t("diag.iperf.receiver")}</dt><dd>{n2(r.receiver)} Mbps</dd></div>}
        </dl>
      </section>
    </>
  );
}

const STATES = ["open", "closed", "filtered", "unfiltered"];
const STATE_TONE: Record<string, Tone> = { open: "ok", filtered: "warn" };

function NmapViz({ lines }: Props) {
  const t = useT();
  const hosts = useMemo(() => parseNmap(lines), [lines]);
  const label = (s: string) => s.split("|").map((x) => (STATES.includes(x) ? t(`diag.nmap.state.${x}` as Key) : x)).join(" / ");
  return (
    <>
      {hosts.map((h) => (
        <div key={h.host} className="table-wrap nmap-host">
          <p className="nmap-name mono">{h.host}</p>
          {h.hidden && <p className="meta">{h.hidden.state === "closed" || h.hidden.state === "filtered" ? t(`diag.nmap.hidden.${h.hidden.state}` as Key, { n: h.hidden.n }) : t("diag.nmap.hidden", { n: h.hidden.n, state: h.hidden.state })}</p>}
          {h.ports.length ? (
            <table aria-label={t("diag.nmap.ports", { host: h.host })}>
              <thead><tr><th scope="col">{t("diag.nmap.port")}</th><th scope="col">{t("diag.nmap.state")}</th><th scope="col">{t("diag.nmap.service")}</th></tr></thead>
              <tbody>{h.ports.map((p) => (
                <tr key={`${p.port}/${p.proto}`}>
                  <td className="mono">{p.port}/{p.proto}</td>
                  <td><StatusPill tone={STATE_TONE[p.state] ?? ""} label={label(p.state)} /></td>
                  <td className="mono">{p.service}</td>
                </tr>
              ))}</tbody>
            </table>
          ) : <p className="meta">{h.host}: {t("diag.nmap.noports")}</p>}
        </div>
      ))}
    </>
  );
}

function CaptureViz({ lines, path }: Props & { path?: string }) {
  const t = useT();
  const n = useMemo(() => captureCount(lines), [lines]);
  return (
    <>
      {n !== null && <dl className="stats"><div><dt>{t("diag.capture.count")}</dt><dd role="status" aria-label={t("diag.capture.count")}>{n}</dd></div></dl>}
      {path && (
        <section aria-label={t("diag.capture.file")}>
          <p><code className="mono">{path}</code> <CopyButton value={path} label={t("diag.capture.copy")} /></p>
          <p className="hint">{t("diag.capture.hint")}</p>
        </section>
      )}
    </>
  );
}

export function DiagViz({ tool, lines, t0, path }: Props & { tool: string; path?: string }) {
  return (
    <div className="diag-viz">
      {tool === "ping" && <PingViz lines={lines} t0={t0} />}
      {tool === "traceroute" && <TraceViz lines={lines} t0={t0} />}
      {tool === "iperf3" && <IperfViz lines={lines} t0={t0} />}
      {tool === "nmap" && <NmapViz lines={lines} t0={t0} />}
      {tool === "pcap" && <CaptureViz lines={lines} t0={t0} path={path} />}
    </div>
  );
}
