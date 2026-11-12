import { useEffect, useRef, useState, type ReactNode } from "react";
import { Hl, Terminal } from "../../components/Terminal";
import type { CoreAPI, Credential, GnmiTarget, SnmpTarget, Topo, VisEvent, VisKind } from "../../lib/core";
import { Check, Field, Notice, Select, errorText } from "../../components/Field";
import { EmptyState, Page, ResultPanel, Section, Tabs, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { formatBytes } from "../../components/Files";
import { Icon } from "../../components/Icon";
import { IngestOptionsBox } from "../../components/ingest/IngestOptions";
import { IngestDropsBanner, IngestStatusLine } from "../../components/ingest/IngestStatus";
import { useBatch, useIngestOpts, MAX_LIVE } from "../../components/ingest/useIngest";
import { Sparkline } from "../../components/charts/Mini";
import { IfaceCharts, TalkerBars, TrapsTable, busiest, trend, type Counter, type Sample, type TrapMsg, type TrapRow } from "./VisParts";
import "./visibility.css";
import { useVaultVersion } from "../../lib/vaultSignal";

type Sub = "topo" | "snmp" | "traps" | "flows" | "gnmi";
const subs: [Sub, Key][] = [["topo", "visibility.sub.topo"], ["snmp", "visibility.sub.snmp"], ["traps", "visibility.sub.traps"], ["flows", "visibility.sub.flows"], ["gnmi", "visibility.sub.gnmi"]];

// Ejecución en vivo (sondeo, escucha, suscripción): guarda los eventos que lleguen
// antes de conocer el runId y descarta los de otras ejecuciones.
// ing: en traps y flujos, las opciones y el juntado de eventos (error de inicio junto a su campo, archivo actual y descartes).
type Ingest = { o: ReturnType<typeof useIngestOpts>; flush: () => void };
function useLive(core: CoreAPI, kind: VisKind, onData: (e: VisEvent) => void, ing?: Ingest, onRun?: (running: boolean) => void) {
  const t = useT();
  const [runId, setRunId] = useState("");
  // Se guarda la clave y sus valores para que el aviso siga el idioma activo.
  const [status, setStatus] = useState<{ key: Key; vars?: Record<string, string> } | null>(null);
  const [err, setErr] = useState("");
  const runRef = useRef("");
  const pending = useRef<VisEvent[]>([]);
  const starting = useRef(false);
  const handler = useRef(onData);
  handler.current = onData;
  const ingRef = useRef(ing);
  ingRef.current = ing;
  const runCb = useRef(onRun);
  runCb.current = onRun;
  useEffect(() => { runCb.current?.(!!runId); }, [runId]); // la pestaña muestra «en curso» mientras haya escucha
  // Un error de inicio llega como done{error} (el RPC es un stream) o como rechazo del inicio: junto al campo que nombra, o en un aviso.
  const fail = (raw: string) => {
    const m = errorText(new Error(raw));
    if (!ingRef.current?.o.mapError(m)) setErr(m);
  };
  const apply = (e: VisEvent) => {
    if (e.done) {
      ingRef.current?.flush();
      if (e.error) fail(e.error);
      setStatus({ key: "visibility.stopped" });
      runRef.current = "";
      setRunId("");
    } else if (e.listening) {
      ingRef.current?.o.meta(e);
      setStatus(e.outputPath ? { key: "visibility.listeningSaving", vars: { addr: e.listening, path: e.outputPath } } : { key: "visibility.listening", vars: { addr: e.listening } });
    } else if (!ingRef.current?.o.meta(e)) {
      handler.current(e);
    }
  };
  useEffect(
    () =>
      core.onVis(kind, (e) => {
        if (starting.current) {
          pending.current.push(e);
          return;
        }
        if (e.runId === runRef.current) apply(e);
      }),
    [core, kind],
  );
  const start = async (f: () => Promise<string>) => {
    setErr(""); setStatus(null);
    pending.current = [];
    starting.current = true;
    try {
      const id = await f();
      runRef.current = id;
      ingRef.current?.o.started();
      setRunId(id);
      starting.current = false;
      const early = pending.current.filter((e) => e.runId === id);
      pending.current = [];
      early.forEach(apply);
    } catch (e) {
      starting.current = false;
      fail(errorText(e));
    }
  };
  const stop = () => core.diagCancel(runId).catch((e) => setErr(errorText(e)));
  // El error va en línea sobre el panel; el estado (escuchando, detenido) es la insignia del panel de salida.
  const view = err ? <Notice kind="error">{err}</Notice> : null;
  const badge = status ? { tone: (status.key === "visibility.stopped" ? "" : "ok") as "" | "ok", label: t(status.key, status.vars) } : undefined;
  return { runId, start, stop, view, badge, started: !!runId || !!status, setErr };
}

// Resultado de una consulta puntual: la salida de texto en terminal, o el error del núcleo.
function Report({ r }: { r: { busy: boolean; data: string | null; error: string } }) {
  const t = useT();
  if (!r.data && !r.error) return null;
  return <ResultPanel title={t("common.output")} error={r.error}>{r.data && <Terminal text={r.data} aria-label={t("common.output")} />}</ResultPanel>;
}

const kbd = <kbd aria-hidden="true">Ctrl ↵</kbd>;

function useCredentials(core: CoreAPI) {
  const t = useT();
  const [creds, setCreds] = useState<Credential[]>([]);
  const vv = useVaultVersion(); // la bóveda cambió: volver a listar credenciales
  useEffect(() => {
    core.listCredentials().then(setCreds).catch(() => setCreds([])); // bóveda cerrada: sin lista
  }, [core, vv]);
  return [["", t("visibility.none")], ...creds.map((c) => [c.id, `${c.label} (${c.username})`] as [string, string])] as [string, string][];
}

const words = (s: string) => s.split(/[\s,]+/).filter(Boolean);

function TopoPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [src, setSrc] = useState("");
  const [pcap, setPcap] = useState("");
  const r = useResult<Topo>();
  const topo = r.data;
  const svgURL = topo ? "data:image/svg+xml;charset=utf-8," + encodeURIComponent(topo.svg) : "";
  return (
    <>
      <Section title={t("visibility.sec.source")} description={t("visibility.topo.note")}>
        <div className="field-row">
          <Field label={t("visibility.topo.src")} value={src} onChange={setSrc} w="lg" mono />
          <Field label={t("visibility.topo.pcap")} value={pcap} onChange={setPcap} w="lg" mono />
        </div>
        <div className="actions">
          <button className="primary" disabled={(!src && !pcap) || r.busy} aria-busy={r.busy} onClick={() => r.run(() => core.topoBuild(src.trim(), pcap.trim()))}>{t("visibility.topo.build")}{kbd}</button>
        </div>
      </Section>
      {!topo && !r.error && !r.busy && <EmptyState icon="layers" title={t("visibility.empty.title")}>{t("visibility.topo.empty")}</EmptyState>}
      {(topo || r.error) && (
        <ResultPanel title={t("visibility.sub.topo")} error={r.error}
          actions={topo && (
            <span className="export-links">
              <a href={svgURL} download={`${t("file.topologia")}.svg`}>{t("visibility.topo.exportSvg")}</a>
              <a href={"data:application/json;charset=utf-8," + encodeURIComponent(topo.json)} download={`${t("file.topologia")}.json`}>{t("visibility.topo.exportJson")}</a>
            </span>
          )}>
          {topo && (
            <>
              <div className="panel-body">
                {/* Como imagen: un SVG en <img> no ejecuta nada aunque un nombre CDP venga manipulado. */}
                <img className="topo" src={svgURL} alt={t("visibility.sub.topo")} />
              </div>
              <Terminal text={topo.text} aria-label={t("common.output")} />
            </>
          )}
        </ResultPanel>
      )}
    </>
  );
}

function bps(v?: number | null) {
  if (v == null) return "-";
  if (v >= 1e9) return (v / 1e9).toFixed(2) + " Gb/s";
  if (v >= 1e6) return (v / 1e6).toFixed(2) + " Mb/s";
  if (v >= 1e3) return (v / 1e3).toFixed(1) + " kb/s";
  return v.toFixed(0) + " b/s";
}

const profiles: [string, Key][] = [["sistema", "visibility.prof.system"], ["interfaces", "visibility.prof.interfaces"], ["cpu", "visibility.prof.cpu"], ["memoria", "visibility.prof.memory"]];

type PanelProps = { core: CoreAPI; active: boolean; onRun: (running: boolean) => void };

function SnmpPanel({ core, active, onRun }: PanelProps) {
  const t = useT();
  const credOpts = useCredentials(core);
  const [host, setHost] = useState("");
  const [port, setPort] = useState("161");
  const [version, setVersion] = useState<"2c" | "3">("2c");
  const [cred, setCred] = useState("");
  const [auth, setAuth] = useState("SHA");
  const [priv, setPriv] = useState("AES");
  const [oids, setOids] = useState("");
  const [bulk, setBulk] = useState(true);
  const [prof, setProf] = useState<Record<string, boolean>>({ sistema: true, interfaces: true });
  const [every, setEvery] = useState("10");
  const [hist, setHist] = useState<Sample[]>([]);
  const [picked, setPicked] = useState<string[] | null>(null);
  const sample = hist[hist.length - 1] ?? null;
  const r = useResult<string>();
  const live = useLive(core, "snmp", (e) => {
    try { const s = JSON.parse(e.json ?? "") as Sample; setHist((h) => [...h.slice(-119), s]); } catch { /* evento malformado: se ignora */ }
  }, undefined, onRun);
  const charted = picked ?? busiest(hist);
  const toggleChart = (name: string) => setPicked(charted.includes(name) ? charted.filter((n) => n !== name) : [...charted, name]);
  const target = (): SnmpTarget => ({ host: host.trim(), port: Number(port) || 161, version, credentialId: cred, auth, priv });
  return (
    <>
      <Section title={t("visibility.sec.target")}>
        <div className="field-row">
          <Field label={t("visibility.host")} value={host} onChange={setHost} w="lg" mono />
          <Field label={t("visibility.port")} type="number" value={port} onChange={setPort} w="xs" mono />
          <Select label={t("visibility.version")} value={version} onChange={setVersion} options={[["2c", "v2c"], ["3", "v3 authPriv"]]} w="md" />
        </div>
        <div className="field-row">
          <Select label={t("visibility.snmp.cred")} value={cred} onChange={setCred} options={credOpts} w="lg" />
          {version === "3" && (
            <>
              <Select label={t("visibility.auth")} value={auth} onChange={setAuth} options={[["SHA", "SHA"], ["SHA256", "SHA-256"], ["SHA384", "SHA-384"], ["SHA512", "SHA-512"]]} w="md" />
              <Select label={t("visibility.priv")} value={priv} onChange={setPriv} options={[["AES", "AES-128"], ["AES192", "AES-192"], ["AES256", "AES-256"]]} w="md" />
            </>
          )}
        </div>
      </Section>
      <Section title={t("visibility.sec.query")}>
        <Field label={t("visibility.snmp.oids")} value={oids} onChange={setOids} w="full" mono />
        <Check label={t("visibility.snmp.bulk")} checked={bulk} onChange={setBulk} />
        <div className="actions">
          <button className="primary" disabled={!host || !cred || !oids || r.busy} aria-busy={r.busy} onClick={() => r.run(() => core.snmpGet(target(), words(oids)))}>Get{kbd}</button>
          <button disabled={!host || !cred || !oids || r.busy} aria-busy={r.busy} onClick={() => r.run(() => core.snmpWalk(target(), words(oids)[0], bulk))}>Walk</button>
        </div>
        <Report r={r} />
      </Section>
      <Section title={t("visibility.snmp.poll")}>
        <div className="cols">
          {profiles.map(([k, l]) => <Check key={k} label={t(l)} checked={!!prof[k]} onChange={(v) => setProf({ ...prof, [k]: v })} />)}
        </div>
        <Field label={t("visibility.every")} type="number" value={every} onChange={setEvery} w="sm" mono />
        <div className="actions">
          <button disabled={!host || !cred || !!live.runId} onClick={() => { setHist([]); setPicked(null); live.start(() => core.snmpPollStart(target(), profiles.map(([k]) => k).filter((k) => prof[k]), Number(every) || 10)); }}>{t("visibility.snmp.pollNow")}</button>
          <button disabled={!live.runId} onClick={live.stop}>{t("common.stop")}</button>
        </div>
        {live.view}
        {active && !sample && !live.started && <EmptyState icon="pulse" title={t("visibility.empty.title")}>{t("visibility.snmp.empty")}</EmptyState>}
        {active && (sample || live.started) && (
          <ResultPanel title={t("visibility.sample")} status={live.badge}
            meta={sample ? `${new Date(sample.Time).toLocaleTimeString()} ${sample.System?.sysName ?? ""} ${sample.System?.sysDescr?.split("\n")[0] ?? ""}` : undefined}>
            {sample && (
              <>
                {sample.Interfaces && sample.Interfaces.length > 0 && (
                  <div className="table-wrap flat">
                    <table>
                      <caption>{t("visibility.col.interfaces")}</caption>
                      <thead><tr><th>{t("visibility.col.iface")}</th><th>{t("visibility.col.state")}</th><th className="num">{t("visibility.col.in")}</th><th className="num">{t("visibility.col.out")}</th><th className="num">{t("visibility.col.errors")}</th></tr></thead>
                      <tbody>
                        {sample.Interfaces.map((i) => (
                          <tr key={i.Name}>
                            <td className="mono">
                              <button className="quiet icon sm" aria-pressed={charted.includes(i.Name)} aria-label={t("visibility.chart.toggle", { name: i.Name })} onClick={() => toggleChart(i.Name)}><Icon name="pulse" size={14} /></button>
                              {i.Name}
                            </td>
                            <td>{i.Oper}</td>
                            <td className="mono num"><span className="rate">{bps(i.InBps)}<Sparkline values={trend(hist, i.Name)} label={`${i.Name} ${t("visibility.col.in")}`} unit="Mb/s" width={72} height={20} /></span></td>
                            <td className="mono num">{bps(i.OutBps)}</td><td className="mono num">{(i.InErrors ?? 0) + (i.OutErrors ?? 0)}</td></tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {charted.length > 0 && (
                  <>
                    <p className="panel-body meta">{t("visibility.chart.hint")}</p>
                    <IfaceCharts hist={hist} names={charted} syncKey={`snmp-${live.runId || "last"}`} />
                  </>
                )}
                {((sample.CPU?.length ?? 0) > 0 || (sample.Memory?.length ?? 0) > 0) && (
                  <div className="panel-body readings">
                    {sample.CPU?.map((c) => <p key={c.Index}>{t("visibility.snmp.cpu", { idx: c.Index, s5: c.FiveSec, m1: c.OneMin, m5: c.FiveMin })}</p>)}
                    {sample.Memory?.map((m) => <p key={m.Name}>{t("visibility.snmp.memory", { name: m.Name, pct: m.UsedPct.toFixed(1) })}</p>)}
                  </div>
                )}
                {sample.Errors?.map((e) => <div className="panel-body" key={e}><Notice kind="warn">{e}</Notice></div>)}
              </>
            )}
          </ResultPanel>
        )}
      </Section>
    </>
  );
}

function TrapsPanel({ core, active, onRun }: PanelProps) {
  const t = useT();
  const credOpts = useCredentials(core);
  const [addr, setAddr] = useState("127.0.0.1:1162");
  const [any, setAny] = useState(false);
  const [save, setSave] = useState(false);
  const [cred, setCred] = useState("");
  const [traps, setTraps] = useState<TrapRow[]>([]);
  const [received, setReceived] = useState(0);
  const o = useIngestOpts("traps", save);
  const seq = useRef(0);
  // Los traps pasan a la lista una vez cada 100 ms; la lista guarda los últimos MAX_LIVE y el conteo sigue.
  const batch = useBatch<TrapRow>((b, n) => {
    setReceived((r) => r + n);
    setTraps((l) => { const all = l.length ? l.concat(b) : b; return all.length > MAX_LIVE ? all.slice(-MAX_LIVE) : all; });
  });
  const live = useLive(core, "traps", (e) => {
    try {
      const m = JSON.parse(e.json ?? "") as TrapMsg;
      batch.push({ ...m, id: ++seq.current, at: new Date().toISOString() });
    } catch { /* evento malformado: se ignora */ }
  }, { o, flush: batch.flush }, onRun);
  const go = () => {
    live.setErr("");
    if (!o.check()) { live.setErr(t("syslog.err.fix")); return; }
    batch.reset(); setTraps([]); setReceived(0);
    const opts = o.begin();
    live.start(() => core.trapsStart(addr, any, save, cred, "SHA", "AES", opts));
  };
  const clear = () => { batch.reset(); setTraps([]); setReceived(0); };
  return (
    <>
      <Section title={t("visibility.sec.listen")} description={t("visibility.traps.note")}>
        <div className="field-row">
          <Field label={t("visibility.listenAddr")} value={addr} onChange={(v) => { setAddr(v); o.touch("addr"); }} w="lg" mono error={o.errors.addr} />
          <Select label={t("visibility.traps.user")} value={cred} onChange={setCred} options={credOpts} w="lg" />
        </div>
        <Check label={t("visibility.anyIf")} checked={any} onChange={setAny} />
        <Check label={t("visibility.traps.save")} checked={save} onChange={setSave} disabled={!!live.runId} />
        {live.runId && <p className="hint">{t("syslog.locked")}</p>}
        <IngestOptionsBox kind="traps" form={o.form} onChange={o.setOpt} save={save} errors={o.errors} open={o.open} onOpen={o.setOpen} disabled={!!live.runId} />
        <div className="actions">
          <button className="primary" disabled={!!live.runId} onClick={go}>{t("visibility.listen")}{kbd}</button>
          <button disabled={!live.runId} onClick={live.stop}>{t("common.stop")}</button>
        </div>
      </Section>
      {live.view}
      {o.drops && <IngestDropsBanner kind="traps" drops={o.drops} />}
      {!active ? null : !live.started && traps.length === 0
        ? <EmptyState icon="pulse" title={t("visibility.empty.title")}>{t("visibility.traps.empty")}</EmptyState>
        : (
          <ResultPanel title={t("visibility.events")} status={live.badge} meta={t("visibility.traps.count", { n: received })} actions={<button className="quiet sm" disabled={!traps.length} onClick={clear}>{t("common.clear")}</button>}>
            <IngestStatusLine kind="traps" received={received} file={o.run.save ? { name: o.file, folder: o.folder, perSource: o.run.perSource } : null} />
            <TrapsTable rows={traps} />
            {received > traps.length && <p className="hint panel-body">{t(o.run.save ? "traps.capped" : "traps.cappedNoSave", { n: traps.length, files: o.run.maxFiles })}</p>}
          </ResultPanel>
        )}
    </>
  );
}

interface Snap { Flows: number; Bytes: number; Errors?: number; Talkers?: Counter[]; Conversations?: Counter[]; Ports?: Counter[]; Protocols?: Counter[]; Exporters?: { Exporter: string; Flows: number; Bytes: number; Errors: number }[] }

function CounterTable({ title, rows }: { title: string; rows?: Counter[] }) {
  const t = useT();
  if (!rows || rows.length === 0) return null;
  return (
    <div className="table-wrap flat">
      <table className="counters">
        <caption>{title}</caption>
        <thead><tr><th>{t("visibility.col.key")}</th><th className="num">Bytes</th><th className="num">{t("visibility.col.packets")}</th><th className="num">{t("visibility.sub.flows")}</th></tr></thead>
        <tbody>{rows.map((r) => <tr key={r.Key}><td className="mono">{r.Key}</td><td className="mono num">{formatBytes(r.Bytes)}</td><td className="mono num">{r.Packets}</td><td className="mono num">{r.Flows}</td></tr>)}</tbody>
      </table>
    </div>
  );
}

function FlowsPanel({ core, active, onRun }: PanelProps) {
  const t = useT();
  const [addr, setAddr] = useState("127.0.0.1:2055");
  const [any, setAny] = useState(false);
  const [save, setSave] = useState(false);
  const [top, setTop] = useState("10");
  const [snap, setSnap] = useState<Snap | null>(null);
  const o = useIngestOpts("flows", save);
  // Cada evento es el resumen completo: basta el último de cada ventana de 100 ms.
  const batch = useBatch<Snap>((b) => setSnap(b[b.length - 1]), 1);
  const live = useLive(core, "flows", (e) => {
    try { batch.push(JSON.parse(e.json ?? "") as Snap); } catch { /* evento malformado: se ignora */ }
  }, { o, flush: batch.flush }, onRun);
  const go = () => {
    live.setErr("");
    if (!o.check()) { live.setErr(t("syslog.err.fix")); return; }
    batch.reset(); setSnap(null);
    const opts = o.begin();
    live.start(() => core.flowsStart(addr, any, save, Number(top) || 10, opts));
  };
  return (
    <>
      <Section title={t("visibility.sec.listen")} description={t("visibility.flows.note")}>
        <div className="field-row">
          <Field label={t("visibility.listenAddr")} value={addr} onChange={(v) => { setAddr(v); o.touch("addr"); }} w="lg" mono error={o.errors.addr} />
          <Field label={t("visibility.flows.top")} type="number" value={top} onChange={setTop} w="sm" mono />
        </div>
        <Check label={t("visibility.anyIf")} checked={any} onChange={setAny} />
        <Check label={t("visibility.flows.save")} checked={save} onChange={setSave} disabled={!!live.runId} />
        {live.runId && <p className="hint">{t("syslog.locked")}</p>}
        <IngestOptionsBox kind="flows" form={o.form} onChange={o.setOpt} save={save} errors={o.errors} open={o.open} onOpen={o.setOpen} disabled={!!live.runId} />
        <div className="actions">
          <button className="primary" disabled={!!live.runId} onClick={go}>{t("visibility.listen")}{kbd}</button>
          <button disabled={!live.runId} onClick={live.stop}>{t("common.stop")}</button>
        </div>
      </Section>
      {live.view}
      {o.drops && <IngestDropsBanner kind="flows" drops={o.drops} />}
      {active && !snap && !live.started && <EmptyState icon="pulse" title={t("visibility.empty.title")}>{t("visibility.flows.empty")}</EmptyState>}
      {active && (snap || live.started) && (
        <ResultPanel title={t("visibility.summary")} status={live.badge}
          meta={snap ? t("visibility.flows.summary", { flows: snap.Flows, bytes: formatBytes(snap.Bytes), errors: snap.Errors ?? 0 }) : undefined}>
          <IngestStatusLine kind="flows" received={snap?.Flows ?? 0} file={o.run.save ? { name: o.file, folder: o.folder, perSource: o.run.perSource } : null} />
          {snap && (
            <>
              {snap.Talkers && snap.Talkers.length > 0 && <TalkerBars title={t("visibility.flows.talkers")} rows={snap.Talkers} total={snap.Bytes} />}
              <CounterTable title={t("visibility.flows.conversations")} rows={snap.Conversations} />
              <CounterTable title={t("visibility.flows.ports")} rows={snap.Ports} />
              <CounterTable title={t("visibility.flows.protocols")} rows={snap.Protocols} />
              <CounterTable title={t("visibility.flows.exporters")} rows={snap.Exporters?.map((x) => ({ Key: x.Exporter, Bytes: x.Bytes, Packets: x.Errors, Flows: x.Flows }))} />
            </>
          )}
        </ResultPanel>
      )}
    </>
  );
}

interface GnmiUpd { Path?: string; Value?: unknown; Sync?: boolean; Delete?: boolean }

function GnmiPanel({ core, active, onRun }: PanelProps) {
  const t = useT();
  const credOpts = useCredentials(core);
  const [host, setHost] = useState("");
  const [port, setPort] = useState("9339");
  const [cred, setCred] = useState("");
  const [ca, setCa] = useState("");
  const [paths, setPaths] = useState("/interfaces/interface[name=GigabitEthernet1/0/1]/state/counters");
  const [mode, setMode] = useState<"sample" | "on_change">("sample");
  const [every, setEvery] = useState("10");
  const [ups, setUps] = useState<GnmiUpd[]>([]);
  const r = useResult<string>();
  const live = useLive(core, "gnmi", (e) => {
    try {
      const u = JSON.parse(e.json ?? "") as GnmiUpd;
      setUps((l) => (l.length > 2000 ? [...l.slice(-1500), u] : [...l, u]));
    } catch { /* evento malformado: se ignora */ }
  }, undefined, onRun);
  const target = (): GnmiTarget => ({ host: host.trim(), port: Number(port) || 9339, credentialId: cred, caPath: ca.trim(), serverName: "" });
  const list = paths.split(/\s+/).filter(Boolean);
  return (
    <>
      <Section title={t("visibility.sec.target")}>
        <div className="field-row">
          <Field label={t("visibility.host")} value={host} onChange={setHost} w="lg" mono />
          <Field label={t("visibility.port")} type="number" value={port} onChange={setPort} w="xs" mono />
          <Select label={t("visibility.gnmi.cred")} value={cred} onChange={setCred} options={credOpts} w="md" />
        </div>
        <Field label={t("visibility.gnmi.ca")} value={ca} onChange={setCa} w="full" mono />
      </Section>
      <Section title={t("visibility.sec.query")} description={t("visibility.gnmi.note")}>
        <Field label={t("visibility.gnmi.paths")} value={paths} onChange={setPaths} w="full" mono />
        <div className="actions"><button className="primary" disabled={!host || !list.length || r.busy} aria-busy={r.busy} onClick={() => r.run(() => core.gnmiGet(target(), list, ""))}>Get{kbd}</button></div>
        <Report r={r} />
      </Section>
      <Section title={t("visibility.sec.subscribe")}>
        <div className="field-row">
          <Select label={t("visibility.gnmi.mode")} value={mode} onChange={setMode} options={[["sample", t("visibility.gnmi.sample")], ["on_change", t("visibility.gnmi.onChange")]]} w="md" />
          <Field label={t("visibility.every")} type="number" value={every} onChange={setEvery} w="sm" mono />
        </div>
        <div className="actions">
          <button disabled={!host || !list.length || !!live.runId} onClick={() => { setUps([]); live.start(() => core.gnmiSubscribeStart(target(), list, mode, Number(every) || 10)); }}>{t("visibility.gnmi.subscribe")}</button>
          <button disabled={!live.runId} onClick={live.stop}>{t("common.stop")}</button>
        </div>
        {live.view}
        {!active ? null : !live.started && ups.length === 0
          ? <EmptyState icon="pulse" title={t("visibility.empty.title")}>{t("visibility.gnmi.empty")}</EmptyState>
          : (
            <ResultPanel title={t("visibility.events")} status={live.badge} actions={<button className="quiet sm" disabled={!ups.length} onClick={() => setUps([])}>{t("common.clear")}</button>}>
              <Terminal as="ul" aria-live="polite" aria-label={t("visibility.events")}>{ups.map((u, i) => <li key={i}><Hl text={u.Sync ? t("visibility.gnmi.synced") : `${u.Path} = ${u.Delete ? t("visibility.gnmi.deleted") : JSON.stringify(u.Value)}`} /></li>)}</Terminal>
            </ResultPanel>
          )}
      </Section>
    </>
  );
}

// Los paneles se montan al visitarlos y se quedan montados (ocultos) para que una escucha en curso no pierda su vista ni su botón Detener.
export function VisibilityView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sub, setSub] = useState<Sub>("topo");
  const [seen, setSeen] = useState<Set<Sub>>(() => new Set(["topo"]));
  const [running, setRunning] = useState<Partial<Record<Sub, boolean>>>({});
  const go = (s: Sub) => { setSub(s); setSeen((v) => (v.has(s) ? v : new Set(v).add(s))); };
  const run = (s: Sub) => (r: boolean) => setRunning((m) => (!!m[s] === r ? m : { ...m, [s]: r }));
  const panel = (s: Sub, body: ReactNode) => seen.has(s) && <div className="vis-panel" hidden={sub !== s}>{body}</div>;
  return (
    <Page title={t("visibility.title")} description={t("visibility.desc")}
      tabs={<Tabs label={t("visibility.view")} value={sub} onChange={go} tabs={subs.map(([s, k]) => [s, running[s] ? t("visibility.tab.running", { name: t(k) }) : t(k)] as [Sub, string])} />}>
      {panel("topo", <TopoPanel core={core} />)}
      {panel("snmp", <SnmpPanel core={core} active={sub === "snmp"} onRun={run("snmp")} />)}
      {panel("traps", <TrapsPanel core={core} active={sub === "traps"} onRun={run("traps")} />)}
      {panel("flows", <FlowsPanel core={core} active={sub === "flows"} onRun={run("flows")} />)}
      {panel("gnmi", <GnmiPanel core={core} active={sub === "gnmi"} onRun={run("gnmi")} />)}
    </Page>
  );
}
