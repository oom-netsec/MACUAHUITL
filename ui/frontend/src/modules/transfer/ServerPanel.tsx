import { useEffect, useRef, useState } from "react";
import { useBusy } from "../../app/activity";
import { Check, Console, Field, Notice, PathField, Select, errorText } from "../../components/Field";
import type { CoreAPI, NetInterface } from "../../lib/core";
import { Badge, EmptyState, ResultPanel, Section } from "../../components/Page";
import { CopyButton } from "../../components/Data";
import { useT } from "../../lib/i18n";
import type { TransferHintInfo, TransferLine, TransferProto, TransferReady } from "./api";
import { iosCommands, splitListen } from "./ios";
import { defaultPort, serveProblem, splitList } from "./validate";

interface Srv { runId: string; ready: TransferReady; lines: TransferLine[]; done: boolean; error?: string; legacy: boolean; cleanup?: string }

const protos: [TransferProto, string][] = [["tftp", "TFTP"], ["ftp", "FTP"], ["scp", "SCP"], ["sftp", "SFTP"], ["http", "HTTP"]];

function Log({ lines }: { lines: TransferLine[] }) {
  const t = useT();
  if (!lines.length) return <p className="meta">{t("transfer.log.empty")}</p>;
  return (
    <div className="table-wrap flat">
    <table>
      <caption>{t("transfer.log")}</caption>
      <thead><tr><th>{t("transfer.log.client")}</th><th>{t("transfer.log.file")}</th><th>{t("transfer.log.bytes")}</th><th>SHA-256</th><th>{t("transfer.log.result")}</th></tr></thead>
      <tbody>
        {lines.map((l, i) => (
          <tr key={i}>
            <td>{l.Client}</td>
            <td>{l.File} <span className="badge">{l.Dir === "escritura" ? t("transfer.dir.in") : t("transfer.dir.out")}</span></td>
            <td className="num">{l.Bytes}</td>
            <td className="mono hash">{l.SHA256 ?? ""}</td>
            <td><Badge tone={l.Result === "ok" ? "ok" : "bad"}>{l.Rejected ? t("transfer.log.rejected") : l.Result === "ok" ? t("transfer.log.ok") : t("transfer.log.error")}</Badge> {l.Error}</td>
          </tr>
        ))}
      </tbody>
    </table>
    </div>
  );
}

function Card({ core, s, onStop, onRemove }: { core: CoreAPI; s: Srv; onStop: () => void; onRemove: () => void }) {
  const t = useT();
  const r = s.ready;
  const { host, port } = splitListen(r.listening);
  const [hint, setHint] = useState<TransferHintInfo | null>(null);
  useEffect(() => {
    if (r.protocol !== "http") core.transferHint(r.protocol, host, port).then(setHint).catch(() => {});
  }, [core, r.protocol, host, port]);
  const cmds = iosCommands(r, !!r.recvDir, { ip: t("transfer.ios.ip"), file: t("transfer.ios.file") }).join("\n");
  const label = r.protocol.toUpperCase();
  return (
    <div role="group" aria-label={`${label} ${r.listening}`}>
    <ResultPanel pad title={`${label} · ${r.listening}`} status={{ tone: s.done ? "" : "ok", label: s.done ? t("transfer.closed") : t("transfer.active") }}
      actions={s.done ? <button type="button" className="quiet sm" onClick={onRemove}>{t("transfer.remove")}</button> : <button type="button" className="sm" onClick={onStop}>{t("common.stop")}</button>}>
      {s.error && <Notice kind="error">{s.error}</Notice>}
      {r.protocol === "ftp" && <Notice kind="warn">{t("transfer.ftpWarn")}</Notice>}
      {r.protocol === "tftp" && r.recvDir && <Notice kind="warn">{t("transfer.udpWarn")}</Notice>}
      {s.legacy && <Notice kind="warn">{t("transfer.legacyWarn")}</Notice>}
      <dl className="stats">
        <div><dt>{t("transfer.addr")}</dt><dd className="mono">{r.listening} <CopyButton value={r.listening} label={t("transfer.addr")} /></dd></div>
        {r.user && <div><dt>{t("transfer.user")}</dt><dd className="mono">{r.user} <CopyButton value={r.user} label={t("transfer.user")} /></dd></div>}
        {r.user && <div><dt>{t("transfer.password")}</dt><dd className="mono">{r.password} <CopyButton value={r.password} label={t("transfer.password")} /></dd></div>}
        {r.recvDir && <div><dt>{t("transfer.recvAt")}</dt><dd className="mono">{r.recvDir}</dd></div>}
        {r.fromDir && <div><dt>{t("transfer.sendFrom")}</dt><dd className="mono">{r.fromDir}</dd></div>}
      </dl>
      {r.user && <p className="hint">{t("transfer.cred.note")}</p>}
      {r.fingerprints?.map((fp, i) => <p key={fp} className="meta">{t("transfer.fingerprint", { n: i + 1 })}: <code>{fp}</code> <CopyButton value={fp} label={t("transfer.fingerprint", { n: i + 1 })} /></p>)}
      <Console label={t("transfer.ios")} text={cmds} copy={core.copyText} />
      {hint && (
        <>
          <Notice kind="warn">{t("transfer.privileged", { std: hint.standardPort, port })}</Notice>
          <Console label={t("transfer.redirect")} text={hint.nftables} copy={core.copyText} />
          <p className="hint">{t("transfer.redirect.narrow", { ip: host })}</p>
          {hint.remove && <Console label={t("transfer.redirect.remove")} text={hint.remove} copy={core.copyText} />}
        </>
      )}
      {s.done && s.cleanup && (
        <>
          <Notice kind="warn">{t("transfer.closed.cleanup")}</Notice>
          <Console label={t("transfer.redirect.remove")} text={s.cleanup} copy={core.copyText} />
        </>
      )}
      <Log lines={s.lines} />
    </ResultPanel>
    </div>
  );
}

export function ServerPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [proto, setProto] = useState<TransferProto>("tftp");
  const [ifaces, setIfaces] = useState<NetInterface[]>([]);
  const [listen, setListen] = useState("");
  const [port, setPort] = useState(defaultPort.tftp);
  const [write, setWrite] = useState(false);
  const [recvDir, setRecvDir] = useState("");
  const [fromDir, setFromDir] = useState("");
  const [files, setFiles] = useState("");
  const [allow, setAllow] = useState("");
  const [minutes, setMinutes] = useState("30");
  const [any, setAny] = useState(false);
  const [legacy, setLegacy] = useState(false);
  const legacyNext = useRef(false); // lo que se pidió al abrir: la tarjeta lo recuerda
  const [err, setErr] = useState("");
  const [servers, setServers] = useState<Srv[]>([]);
  const seen = useRef(new Set<string>());

  useEffect(() => { core.listInterfaces().then((l) => setIfaces(l ?? [])).catch((e) => setErr(errorText(e))); }, [core]);
  const ips = ifaces.filter((i) => i.up).flatMap((i) => i.addresses.map((a) => [a.replace(/\/\d+$/, ""), i.name] as const));

  // Montado siempre (como Campo): cambiar de pestaña no pierde servidores ni su registro.
  useEffect(() => core.onTransfer((e) => {
    if (e.ready) {
      seen.current.add(e.runId);
      setServers((l) => [...l, { runId: e.runId, ready: e.ready!, lines: [], done: false, legacy: legacyNext.current && (e.ready!.protocol === "scp" || e.ready!.protocol === "sftp") }]);
    } else if (e.line) setServers((l) => l.map((s) => (s.runId === e.runId ? { ...s, lines: [...s.lines.slice(-499), e.line!] } : s)));
    else if (e.done) {
      const msg = e.error && errorText(new Error(e.error));
      // Un error sin tarjeta es que el servidor no llegó a abrir (carpeta o regla inválida).
      if (seen.current.has(e.runId)) setServers((l) => l.map((s) => (s.runId === e.runId ? { ...s, done: true, error: msg || undefined, cleanup: e.cleanup } : s)));
      else if (msg) setErr(msg);
    }
  }), [core]);
  useBusy(servers.some((s) => !s.done));

  const ssh = proto === "scp" || proto === "sftp";
  const form = { proto, any, listen, port, write, recvDir, fromDir, files, allow, minutes };
  const start = async () => {
    const p = serveProblem(form);
    if (p) { setErr(t(p)); return; }
    setErr("");
    const host = any ? "0.0.0.0" : listen;
    legacyNext.current = ssh && legacy;
    try {
      await core.transferServe({
        protocol: proto, listen: host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`, allowAny: any,
        files: splitList(files), fromDir, write, recvDir: write ? recvDir : "", allow: splitList(allow), seconds: Number(minutes) * 60, legacySsh: ssh && legacy,
      });
    } catch (e) {
      setErr(errorText(e));
    }
  };
  const stop = (s: Srv) => core.transferStop(s.ready.serverId)
    .then(() => setServers((l) => l.map((x) => (x.runId === s.runId ? { ...x, done: true } : x))))
    .catch((e) => setErr(errorText(e)));
  return (
    <>
      <Section title={t("transfer.form.server")}>
        <div className="field-row">
          <Select label={t("transfer.proto")} value={proto} onChange={(p) => { setProto(p); setPort(defaultPort[p]); }} options={protos} w="sm" />
          <Select label={t("transfer.listen")} hint={t("transfer.listen.hint")} value={any ? "" : listen} onChange={setListen} w="md"
            options={[["", t("common.select")], ...ips.map(([ip, n]) => [ip, `${ip} · ${n}`] as [string, string])]} />
          <Field label={t("transfer.port")} hint={t("transfer.port.hint")} type="number" value={port} onChange={setPort} w="sm" />
          <Field label={t("transfer.minutes")} type="number" value={minutes} onChange={setMinutes} w="sm" />
        </div>
        {proto === "ftp" && <Notice kind="warn">{t("transfer.ftpWarn")}</Notice>}
        <Check label={t("transfer.any")} checked={any} onChange={setAny} />
        {any && <Notice kind="warn">{t("transfer.any.warn")}</Notice>}
        <PathField label={t("transfer.fromDir")} hint={t("transfer.fromDir.hint")} value={fromDir} onChange={setFromDir} pick={() => core.pickPath({ title: t("transfer.fromDir"), directory: true })} />
        <Field label={t("transfer.files")} hint={t("transfer.files.hint")} value={files} onChange={setFiles} />
        <Check label={t("transfer.write")} checked={write} onChange={setWrite} />
        {write && proto === "tftp" && <Notice kind="warn">{t("transfer.udpWarn")}</Notice>}
        {write && <PathField label={t("transfer.recvDir")} hint={t("transfer.recvDir.hint")} value={recvDir} onChange={setRecvDir} pick={() => core.pickPath({ title: t("transfer.recvDir"), directory: true })} />}
        <Field label={t("transfer.allow")} hint={t("transfer.allow.hint")} value={allow} onChange={setAllow} />
        {ssh && <Check label={t("transfer.legacy.server")} checked={legacy} onChange={setLegacy} />}
        {ssh && <p className="hint">{t("transfer.legacy.server.hint")}</p>}
        <div className="actions"><button className="primary" onClick={start}>{t("transfer.open")}<kbd aria-hidden="true">Ctrl ↵</kbd></button></div>
        {err && <Notice kind="error">{err}</Notice>}
      </Section>
      {servers.length === 0 && <EmptyState icon="upload" title={t("transfer.servers.none")} />}
      {servers.map((s) => (
        <Card key={s.runId} core={core} s={s} onStop={() => stop(s)} onRemove={() => setServers((l) => l.filter((x) => x.runId !== s.runId))} />
      ))}
    </>
  );
}
