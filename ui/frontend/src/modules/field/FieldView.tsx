import { useState } from "react";
import { Hl, Terminal } from "../../components/Terminal";
import type { CoreAPI, ServeEvent } from "../../lib/core";
import { Check, Field, Notice, Select, TextArea, errorText } from "../../components/Field";
import { EmptyState, Page, ResultPanel, Section, Tabs, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { useStream } from "../../lib/stream";
import { useNav } from "../../app/activity";
import "./field.css";

type Sub = "serve" | "hash";
const subs: [Sub, Key][] = [["serve", "field.sub.serve"], ["hash", "field.sub.hash"]];

interface Xfer { Client?: string; File?: string; Bytes?: number; Duration?: number; Result?: string; Error?: string }

function ServePanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const go = useNav();
  const [proto, setProto] = useState<"tftp" | "http">("tftp");
  const [addr, setAddr] = useState("");
  const [files, setFiles] = useState("");
  const [minutes, setMinutes] = useState("60");
  const [any, setAny] = useState(false);
  const [runId, setRunId] = useState("");
  const [status, setStatus] = useState<{ k: Key; v?: Record<string, string> } | null>(null);
  const [hint, setHint] = useState("");
  const [err, setErr] = useState("");
  const [xfers, setXfers] = useState<Xfer[]>([]);
  const s = useStream<ServeEvent>(core.onServe, (e) => {
    if (e.done) {
      if (e.error) setErr(errorText(new Error(e.error)));
      setStatus({ k: "field.stopped" });
      setRunId("");
      s.clear();
    } else if (e.listening) {
      setStatus({ k: "field.serving", v: { addr: e.listening, proto } });
      setHint(e.hint ?? "");
    } else if (e.transfer) {
      try {
        const x = JSON.parse(e.transfer) as Xfer;
        setXfers((l) => [...l.slice(-500), x]);
      } catch { /* evento malformado: se ignora */ }
    }
  });
  s.onUnmount(core.diagCancel);
  const start = async () => {
    setErr(""); setXfers([]); setStatus(null); setHint("");
    try {
      setRunId(await s.start(() => core.serveStart({ protocol: proto, addr, files: files.split(/[\n,;]+/).map((f) => f.trim()).filter(Boolean), allowAny: any, seconds: (Number(minutes) || 60) * 60 })));
    } catch (e) {
      setErr(errorText(e));
    }
  };
  const badge = runId && status ? { tone: "ok" as const, label: t(status.k, status.v) }
    : status ? { tone: "" as const, label: t(status.k, status.v) }
    : runId ? { tone: "info" as const, label: t("field.starting") } : undefined;
  return (
    <>
      <Section title={t("field.sec.serve")} description={t("field.serveNote")}>
        <Notice kind="info">{t("field.toTransfer")} <button type="button" className="sm" onClick={() => go("transfer")}>{t("field.toTransfer.go")}</button></Notice>
        <div className="field-row">
          <Select label={t("field.proto")} value={proto} onChange={setProto} options={[["tftp", t("field.proto.tftp")], ["http", t("field.proto.http")]]} w="md" />
          <Field label={t("field.addr")} value={addr} onChange={setAddr} w="lg" mono />
          <Field label={t("field.minutes")} type="number" value={minutes} onChange={setMinutes} w="sm" mono />
        </div>
        <TextArea label={t("field.files")} value={files} onChange={setFiles} rows={2} />
        <Check label={t("field.any")} checked={any} onChange={setAny} />
        <div className="actions">
          <button className="primary" disabled={!!runId || !addr || !files} aria-busy={!!runId && !status} onClick={start}>{t("field.serve")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
          <button disabled={!runId} onClick={() => core.diagCancel(runId).catch((e) => setErr(errorText(e)))}>{t("common.stop")}</button>
        </div>
      </Section>
      {err && <Notice kind="error">{err}</Notice>}
      {!badge && !xfers.length && <EmptyState icon="tools" title={t("field.empty.title")}>{t("field.empty")}</EmptyState>}
      {(badge || xfers.length > 0) && (
        <div className="field-out"><ResultPanel title={t("field.transfers")} status={badge}>
          {hint && <Terminal text={hint} aria-label={t("field.hint")} />}
          <Terminal as="ul" aria-live="polite" aria-label={t("field.transfers")}>
            {xfers.map((x, i) => (
              <li key={i} data-sev={x.Result === "ok" ? undefined : 3}>
                <Hl text={t("field.xfer", { client: x.Client ?? "", file: x.File ?? "", bytes: x.Bytes ?? 0, secs: ((x.Duration ?? 0) / 1e9).toFixed(1), result: x.Result === "ok" ? t("transfer.log.ok") : x.Result === undefined ? "" : t("transfer.log.error"), error: x.Error ? ` ${x.Error}` : "" })} />
              </li>
            ))}
          </Terminal>
        </ResultPanel></div>
      )}
    </>
  );
}

function HashPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [path, setPath] = useState("");
  const [md5, setMd5] = useState("");
  const [sha, setSha] = useState("");
  const r = useResult<{ text: string; ok: boolean }>();
  const published = md5.trim() !== "" || sha.trim() !== "";
  const status = r.data ? (!r.data.ok ? { tone: "bad" as const, label: t("field.hash.bad") } : published ? { tone: "ok" as const, label: t("field.hash.match") } : { tone: "info" as const, label: t("field.hash.computed") }) : undefined;
  return (
    <>
      <Section title={t("field.sub.hash")} description={t("field.hash.note")}>
        <Field label={t("field.hash.path")} value={path} onChange={setPath} w="full" mono />
        <div className="field-row">
          <Field label={t("field.hash.md5")} value={md5} onChange={setMd5} w="lg" mono />
          <Field label={t("field.hash.sha")} value={sha} onChange={setSha} w="full" mono />
        </div>
        <div className="actions">
          <button className="primary" disabled={!path || r.busy} aria-busy={r.busy} onClick={() => r.run(() => core.fieldHash(path, md5.trim(), sha.trim()))}>{t("field.hash.calc")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
        </div>
      </Section>
      {r.data && !r.data.ok && <Notice kind="error">{t("field.hash.mismatch")}</Notice>}
      {!r.data && !r.error && !r.busy && <EmptyState icon="tools" title={t("field.empty.title")}>{t("field.hash.empty")}</EmptyState>}
      {(r.data || r.error) && (
        <ResultPanel title={t("common.output")} status={status} error={r.error}>
          {r.data && <Terminal text={r.data.text} aria-label={t("common.output")} />}
        </ResultPanel>
      )}
    </>
  );
}

export function FieldView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sub, setSub] = useState<Sub>("serve");
  return (
    <Page title={t("nav.field")} description={t("field.desc")}
      tabs={<Tabs label={t("field.tool")} value={sub} onChange={setSub} tabs={subs.map(([s, k]) => [s, t(k)] as [Sub, string])} />}>
      {/* Montados siempre: cambiar de sub-pestaña no corta el servidor. */}
      <div hidden={sub !== "serve"}><ServePanel core={core} /></div>
      <div hidden={sub !== "hash"}><HashPanel core={core} /></div>
    </Page>
  );
}
