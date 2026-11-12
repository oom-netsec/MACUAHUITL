import { useEffect, useRef, useState, type ReactNode } from "react";
import type { CoreAPI, SyslogEvent } from "../../lib/core";
import { Check, Field, Notice, PathField, Select, errorText } from "../../components/Field";
import { EmptyState, Page, ResultPanel, Section, useResult } from "../../components/Page";
import { Icon } from "../../components/Icon";
import { Terminal } from "../../components/Terminal";
import { useBusy, useInbox } from "../../app/activity";
import { useT } from "../../lib/i18n";
import { errInfo, type ErrInfo } from "../../lib/coreError";
import type { Key } from "../../lib/i18n/es";
import { SyslogTable } from "./SyslogTable";
import { IngestOptionsBox } from "../../components/ingest/IngestOptions";
import { IngestDropsBanner, IngestStatusLine } from "../../components/ingest/IngestStatus";
import { MAX_LIVE, useBatch, useIngestOpts } from "../../components/ingest/useIngest";
import type { OptKey } from "../../components/ingest/ingestOpts";
import { toMsg, type SysMsg, type WireMsg } from "./syslogStats";
import { parsePcap, pcapFromReport } from "./pcapParse";
import type { PcapReportData } from "./api";
import { PcapReport } from "./PcapReport";
import { parseTrace } from "./dnsTrace";
import { DnsTree } from "./DnsTree";
import { parseTls } from "./tlsChain";
import { TlsChain } from "./TlsChain";
import "./tools.css";

// Resultado de texto de una llamada: panel con copiar y limpiar; el estado vacío explica qué hacer primero.
// view: vista gráfica del texto (null si no se reconoce el formato); el texto completo queda en la terminal.
function TextResult({ core, r, empty, view }: { core: CoreAPI; r: ReturnType<typeof useResult<string>>; empty: ReactNode; view?: (text: string) => ReactNode }) {
  const t = useT();
  const [copied, setCopied] = useState(false);
  if (!r.busy && !r.data && !r.error) return <>{empty}</>;
  const status = r.busy ? { tone: "info" as const, label: t("diag.status.running") }
    : r.error ? { tone: "bad" as const, label: t("diag.status.failed") } : { tone: "ok" as const, label: t("diag.status.done") };
  const copy = async () => { await core.copyText(r.data ?? ""); setCopied(true); window.setTimeout(() => setCopied(false), 1500); };
  const extra = r.data && view ? view(r.data) : null;
  const title = t(extra ? "tools.fullReport" : "common.output");
  return (
    <>
    {extra}
    <ResultPanel title={title} status={status} error={r.error}
      actions={<>
        <button className="quiet sm" disabled={!r.data} onClick={copy}><Icon name="copy" size={14} />{t(copied ? "common.copied" : "common.copy")}</button>
        <button className="quiet sm" disabled={r.busy} onClick={r.reset}>{t("common.clear")}</button>
      </>}>
      <Terminal text={r.data ?? ""} role="log" aria-label={title} />
    </ResultPanel>
    </>
  );
}

const runKbd = <kbd aria-hidden="true">Ctrl ↵</kbd>;

export function PcapPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [path, setPath] = useState("");
  const [top, setTop] = useState("20");
  const r = useResult<string>();
  const [rep, setRep] = useState<PcapReportData | null>(null); // el informe estructurado de la última corrida
  useInbox("pcap", setPath);
  const pick = () => core.pickPath({ title: t("pcap.path"), filters: [{ name: t("pcap.filter"), pattern: "*.pcap;*.pcapng" }] });
  const run = async () => {
    const n = Number(top) || 20;
    setRep(null);
    const d = core.toolsPcapReport && await core.toolsPcapReport(path, n); // un error se muestra, sin repetir con el método de texto
    if (!d?.text) return core.toolsPcap(path, n);
    setRep(d);
    return d.text;
  };
  return (
    <Page title={t("pcap.title")} description={t("pcap.desc")}>
      <PathField label={t("pcap.path")} hint={t("pcap.path.hint")} value={path} onChange={setPath} pick={pick} />
      <div className="field-row">
        <Field label={t("pcap.top")} type="number" value={top} onChange={setTop} w="sm" />
      </div>
      <div className="actions">
        <button className="primary" disabled={!path || r.busy} aria-busy={r.busy} onClick={() => r.run(run)}>{t("pcap.analyze")}{runKbd}</button>
      </div>
      <TextResult core={core} r={r} view={(s) => { const p = rep ? pcapFromReport(rep) : parsePcap(s); return p && <PcapReport p={p} />; }}
        empty={<EmptyState icon="pulse" title={t("pcap.empty.title")}>{t("pcap.empty")}</EmptyState>} />
    </Page>
  );
}

const dnsModes = ["query", "transport", "hygiene", "exposure", "trace", "zone", "dnssec"] as const;
const deepModes = new Set(["trace", "zone", "dnssec"]);
const dnsTypes = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "CAA", "DS", "DNSKEY"];

export function DnsPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [mode, setMode] = useState<string>("query");
  const [name, setName] = useState("");
  const [type, setType] = useState("A");
  const [servers, setServers] = useState("");
  const [deep, setDeep] = useState(false);
  const [dnssec, setDnssec] = useState(false);
  const r = useResult<string>();
  const needsDeep = deepModes.has(mode) && !deep;
  const list = servers.split(/[\s,;]+/).filter(Boolean);
  return (
    <Page title={t("dns.title")} description={t("dns.desc")}>
      <Section title={t("dns.section.query")}>
        <div className="field-row">
          <Select label={t("dns.mode")} value={mode} onChange={setMode} options={dnsModes.map((m) => [m, t(`dns.mode.${m}` as Key)])} w="lg" />
          <Field label={t("dns.name")} value={name} onChange={setName} w="lg" mono />
          <Select label={t("dns.type")} value={type} onChange={setType} options={dnsTypes.map((x) => [x, x])} w="sm" />
        </div>
        <Field label={t("dns.servers")} hint={t("dns.servers.hint")} value={servers} onChange={setServers} w="full" mono />
      </Section>
      <Section title={t("dns.section.options")}>
        <Check label={t("dns.dnssec")} checked={dnssec} onChange={setDnssec} />
        <Check label={t("dns.deep")} checked={deep} onChange={setDeep} />
        {needsDeep && <Notice kind="warn">{t("dns.needsDeep")}</Notice>}
      </Section>
      <div className="actions">
        <button className="primary" disabled={needsDeep || (!name && mode !== "exposure") || r.busy} aria-busy={r.busy}
          onClick={() => r.run(() => core.toolsDns({ mode, name, type, servers: list, deep, dnssec }))}>{t("dns.query")}{runKbd}</button>
      </div>
      <TextResult core={core} r={r} view={(s) => { const tr = mode === "trace" ? parseTrace(s) : null; return tr && <DnsTree trace={tr} />; }}
        empty={<EmptyState icon="pulse" title={t("dns.empty.title")}>{t("dns.empty")}</EmptyState>} />
    </Page>
  );
}

export function TlsPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [host, setHost] = useState("");
  const [port, setPort] = useState("443");
  const [sni, setSni] = useState("");
  const r = useResult<string>();
  return (
    <Page title={t("tls.title")} description={t("tls.desc")}>
      <div className="field-row">
        <Field label={t("tls.host")} value={host} onChange={setHost} w="lg" mono />
        <Field label={t("tls.port")} type="number" value={port} onChange={setPort} w="xs" mono />
        <Field label={t("tls.sni")} hint={t("tls.sni.hint")} value={sni} onChange={setSni} w="lg" mono />
      </div>
      <div className="actions">
        <button className="primary" disabled={!host || r.busy} aria-busy={r.busy} onClick={() => r.run(() => core.toolsTls(host, Number(port) || 443, sni))}>{t("tls.inspect")}{runKbd}</button>
      </div>
      <TextResult core={core} r={r} view={(s) => { const i = parseTls(s); return i && <TlsChain info={i} />; }}
        empty={<EmptyState icon="pulse" title={t("tls.empty.title")}>{t("tls.empty")}</EmptyState>} />
    </Page>
  );
}

export function SyslogPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [addr, setAddr] = useState("127.0.0.1:5514");
  const [proto, setProto] = useState<"udp" | "tcp">("udp");
  const [any, setAny] = useState(false);
  const [save, setSave] = useState(false);
  const [runId, setRunId] = useState("");
  const [status, setStatus] = useState("");
  const [err, setErr] = useState("");
  const [msgs, setMsgs] = useState<SysMsg[]>([]);
  const [received, setReceived] = useState(0);
  const o = useIngestOpts("syslog", save);
  const seq = useRef(0);
  const runRef = useRef("");
  const pending = useRef<SyslogEvent[]>([]);
  const starting = useRef(false);
  // Los mensajes pasan a la lista una vez cada FLUSH_MS: bajo inundación no hay un render por mensaje.
  const batch = useBatch<SysMsg>((b, n) => {
    setReceived((r) => r + n);
    setMsgs((l) => { const all = l.length ? l.concat(b) : b; return all.length > MAX_LIVE ? all.slice(-MAX_LIVE) : all; }); // tope en memoria; los archivos guardan todo
  });
  useBusy(!!runId);

  // Un error de inicio llega como done{error} (el RPC es un stream) o como rechazo de syslogStart: se marca junto al campo que nombra, o va en un aviso.
  const showError = (raw: string, info?: ErrInfo) => {
    const m = errorText(new Error(raw));
    if (!o.mapError(m, info)) setErr(m);
  };

  const apply = (e: SyslogEvent) => {
    if (e.done) {
      batch.flush();
      if (e.error) showError(e.error, e.errorInfo);
      setStatus(t("syslog.stopped"));
      runRef.current = "";
      setRunId("");
    } else if (e.listening) {
      setStatus(t("syslog.listening", { addr: e.listening, proto }) + (e.outputPath ? ` · ${t("syslog.saving", { path: e.outputPath })}` : ""));
      o.meta(e);
    } else if (o.meta(e)) {
      // rotatedPath o descartes: ya anotados
    } else if (e.json) {
      try {
        batch.push(toMsg(JSON.parse(e.json) as WireMsg, seq.current++, Date.now()));
      } catch { /* evento malformado: se ignora */ }
    }
  };
  useEffect(
    () =>
      core.onSyslog((e) => {
        if (starting.current) {
          pending.current.push(e);
          return;
        }
        if (e.runId === runRef.current) apply(e);
      }),
    [core],
  );
  const start = async () => {
    setErr("");
    if (!o.check()) { setErr(t("syslog.err.fix")); return; }
    batch.reset();
    setMsgs([]); setStatus(""); setReceived(0);
    const opts = o.begin();
    pending.current = [];
    starting.current = true;
    try {
      const id = await core.syslogStart(addr, proto, any, save, opts);
      runRef.current = id;
      o.started();
      setRunId(id);
      starting.current = false;
      const early = pending.current.filter((e) => e.runId === id);
      pending.current = [];
      early.forEach(apply);
    } catch (e) {
      starting.current = false;
      showError(errorText(e), errInfo(e));
    }
  };
  const stop = () => core.diagCancel(runId).catch((e) => setErr(errorText(e)));
  const touch = (k: OptKey) => { o.touch(k); setErr(""); };
  const started = !!runId || !!status || msgs.length > 0;
  return (
    <Page title={t("syslog.title")} description={t("syslog.desc")}>
      <Section title={t("syslog.section.listen")}>
        <div className="field-row">
          <Field label={t("syslog.addr")} value={addr} onChange={(v) => { setAddr(v); touch("addr"); }} w="lg" mono error={o.errors.addr} />
          <Select label={t("syslog.proto")} value={proto} onChange={setProto} options={[["udp", "UDP"], ["tcp", "TCP"]]} w="xs" />
        </div>
        <Check label={t("syslog.any")} checked={any} onChange={setAny} />
        <Check label={t("syslog.save")} checked={save} onChange={setSave} disabled={!!runId} />
        {runId && <p className="hint">{t("syslog.locked")}</p>}
        <p className="hint">{t("syslog.hint")}</p>
        <IngestOptionsBox form={o.form} onChange={(k, v) => { o.setOpt(k, v); setErr(""); }} save={save} errors={o.errors} open={o.open} onOpen={o.setOpen} disabled={!!runId} />
      </Section>
      <div className="actions">
        <button className="primary" disabled={!!runId} aria-busy={!!runId} onClick={start}>{t("syslog.listen")}{runKbd}</button>
        <button disabled={!runId} onClick={stop}>{t("common.stop")}</button>
      </div>
      {err && <Notice kind="error">{err}</Notice>}
      {!started && <EmptyState icon="syslog" title={t("syslog.empty.title")}>{t("syslog.empty.first")}</EmptyState>}
      {o.drops && <IngestDropsBanner drops={o.drops} />}
      {started && (
        <ResultPanel title={t("syslog.messages")}
          status={runId ? { tone: status ? "ok" : "info", label: status || t("diag.status.running") } : status ? { tone: "", label: status } : undefined}
          meta={t("syslog.count", { n: received })}>
          <IngestStatusLine received={received} file={o.run.save ? { name: o.file, folder: o.folder, perSource: o.run.perSource } : null} />
          {msgs.length === 0 ? <p className="empty panel-body">{t("syslog.empty")}</p> : <SyslogTable msgs={msgs} />}
          {received > msgs.length && <p className="hint panel-body">{t(o.run.save ? "syslog.capped" : "syslog.cappedNoSave", { n: msgs.length, files: o.run.maxFiles })}</p>}
        </ResultPanel>
      )}
    </Page>
  );
}
