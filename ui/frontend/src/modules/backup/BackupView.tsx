import { useCallback, useEffect, useRef, useState } from "react";
import type { CoreAPI, Credential } from "../../lib/core";
import { Check, Field, Notice, Select, TextArea, errorText } from "../../components/Field";
import { EmptyState, Page, ResultPanel, Section } from "../../components/Page";
import { Terminal } from "../../components/Terminal";
import { DiffView } from "../../components/DiffView";
import { CopyButton } from "../../components/Data";
import { DownloadButton } from "../../components/Files";
import { parseTargets } from "../patrol/PatrolView";
import { AssistExecution } from "../../components/AssistRun";
import { assistOwner } from "../../app/useShellStatus";

const noop = () => {};
import { parseTarget } from "../adhoc/AdhocView";
import type { BackupDiff, BackupEntry, BackupList } from "./api";
import { RestorePanel } from "./RestorePanel";
import { BackupTimeline } from "./BackupTimeline";
import { useT } from "../../lib/i18n";
import { useInbox } from "../../app/activity";
import "./backup.css";
import { useVaultVersion } from "../../lib/vaultSignal";
import { parseFingerprints } from "../../lib/hostkeys";

// Respaldos: running-config (y startup-config) de cada equipo en outputs/respaldos/, con permisos 0600.
// Respaldar es solo lectura (un trabajo de Patrol). Restaurar (fase 16c) planea desde aquí y ejecuta con el modo asistido.

export function BackupView({ core, pollMs = 700, maxWaitMs = 10 * 60_000 }: { core: CoreAPI; pollMs?: number; maxWaitMs?: number }) {
  const t = useT();
  const [creds, setCreds] = useState<Credential[]>([]);
  const [cred, setCred] = useState("");
  const [devices, setDevices] = useState("");
  useInbox("backup", setDevices); // desde el menú de equipo
  const [startup, setStartup] = useState(false);
  const [secrets, setSecrets] = useState(false);
  const [keep, setKeep] = useState("30");
  const [every, setEvery] = useState("0");
  const [rounds, setRounds] = useState("2");
  const [accept, setAccept] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [liveRestore, setLiveRestore] = useState(false);
  useEffect(() => {
    let alive = true;
    core.assistListRuns().then((rs) => { if (alive) setLiveRestore(rs.some((r) => r.active && assistOwner(r.runId) === "backup")); }, () => {});
    return () => { alive = false; };
  }, [core]);
  const [note, setNote] = useState<{ kind: "ok" | "info" | "warn"; text: string } | null>(null);
  const [list, setList] = useState<BackupList>({ backups: [], masked: false });
  const [sel, setSel] = useState<string[]>([]);
  const [diff, setDiff] = useState<{ meta: BackupDiff; before: string; after: string } | null>(null);
  const [restoring, setRestoring] = useState<BackupEntry | null>(null);
  const [shown, setShown] = useState<{ meta: BackupEntry; text: string } | null>(null);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const vv = useVaultVersion(); // la bóveda cambió: volver a listar credenciales
  useEffect(() => { core.listCredentials().then((l) => { setCreds(l); setCred((c) => (l.some((x) => x.id === c) ? c : l[0]?.id ?? "")); }).catch(() => setCreds([])); }, [core, vv]); // bóveda cerrada: sin lista

  const reload = useCallback(async () => {
    try { const l = await core.backupList(""); if (alive.current) { setList(l); setSel((s) => s.filter((id) => l.backups.some((b) => b.id === id))); } } catch (e) { if (alive.current) setErr(errorText(e)); }
  }, [core]);
  useEffect(() => { void reload(); }, [reload]);

  const scheduled = Number(every) > 0;
  const run = async () => {
    setErr(""); setNote(null); setBusy(true);
    try {
      const st = await core.backupStart({
        targets: parseTargets(devices).map(parseTarget), credentialId: cred, startup, keep: Number(keep) || 0,
        intervalSeconds: Math.round(Number(every) * 60), rounds: scheduled ? Number(rounds) : 0, secrets,
        accept: parseFingerprints(accept),
      });
      if (!st.armed) { setNote({ kind: "warn", text: t("backup.notArmed", { job: st.jobId, detail: st.detail }) }); return; }
      if (scheduled) { setNote({ kind: "info", text: t("backup.scheduled", { job: st.jobId }) }); return; }
      const deadline = Date.now() + maxWaitMs;
      for (;;) {
        const r = await core.backupCollect(st.jobId);
        if (!alive.current) return;
        if (r.done) {
          if (r.error) setErr(t("backup.jobError", { job: st.jobId, error: r.error }));
          else setNote(r.warnings.length ? { kind: "warn", text: t("backup.savedWarn", { n: r.saved.length, warnings: r.warnings.join("; ") }) } : { kind: "ok", text: t("backup.saved", { n: r.saved.length }) });
          break;
        }
        if (Date.now() >= deadline) { setErr(t("backup.stillRunning", { job: st.jobId, state: r.state })); break; }
        await new Promise((ok) => setTimeout(ok, pollMs));
      }
      await reload();
    } catch (e) { setErr(errorText(e)); } finally { if (alive.current) setBusy(false); }
  };

  const toggle = (id: string) => setSel((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id].slice(-2)));
  const compare = async () => {
    setErr(""); setDiff(null);
    // El más viejo es A: la diferencia se lee «de A a B».
    const at = (id: string) => list.backups.find((x) => x.id === id)?.at ?? "";
    const [a, b] = [...sel].sort((x, y) => at(x).localeCompare(at(y)));
    try {
      // El núcleo dice qué líneas son volátiles; el visor muestra los textos completos sin ellas.
      const [meta, x, y] = await Promise.all([core.backupDiff(a, b), core.backupGet(a), core.backupGet(b)]);
      const skip = new Set(meta.ignored);
      const clean = (txt: string) => txt.split("\n").filter((l) => !skip.has(l.trim())).join("\n");
      setDiff({ meta, before: clean(x.text), after: clean(y.text) });
    } catch (e) { setErr(errorText(e)); }
  };
  const view = async (id: string) => {
    setErr(""); setShown(null);
    try { setShown(await core.backupGet(id)); } catch (e) { setErr(errorText(e)); }
  };
  return (
    <Page title={t("backup.title")} description={<>{t("backup.intro.a")}<code>outputs/respaldos/</code>{t("backup.intro.b")}</>}>
      <Section title={t("backup.sec.run")}>
        <Select label={t("backup.cred")} value={cred} onChange={setCred} options={creds.map((c) => [c.id, `${c.label} (${c.username})`] as [string, string])} w="md" />
        <TextArea label={t("backup.devices")} value={devices} onChange={setDevices} rows={3} />
        <Check label={t("backup.startup")} checked={startup} onChange={setStartup} />
        <Check label={t("backup.secrets")} checked={secrets} onChange={setSecrets} />
        {secrets && <Notice kind="warn">{t("backup.secretsWarn")}</Notice>}
        <div className="field-row end">
          <Field label={t("backup.keep")} type="number" value={keep} onChange={setKeep} w="sm" />
          <Field label={t("backup.every")} type="number" value={every} onChange={setEvery} w="md" />
          {scheduled && <Field label={t("backup.rounds")} type="number" value={rounds} onChange={setRounds} w="sm" />}
          <Field label={t("fps.accepted")} value={accept} onChange={setAccept} w="lg" mono />
        </div>
        <div className="actions">
          <button className="primary" disabled={busy || !cred || !devices.trim()} aria-busy={busy} onClick={run}>{t(busy ? "backup.busy" : scheduled ? "backup.schedule" : "backup.now")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
        </div>
        {err && <Notice kind="error">{err}</Notice>}
        {note && <Notice kind={note.kind}>{note.text}</Notice>}
      </Section>

      <Section title={t("backup.saved.title")} description={t("backup.list.hint")}>
        {list.masked && <Notice kind="warn">{t("backup.maskedWarn")}</Notice>}
        {list.backups.length === 0 ? <EmptyState icon="layers" title={t("backup.none")}>{t("backup.none.hint")}</EmptyState> : (
          <BackupTimeline backups={list.backups} sel={sel} onToggle={toggle} onView={view} onRestore={setRestoring} />
        )}
        <div className="actions">
          <button disabled={sel.length !== 2} onClick={compare}>{t("backup.compare")}</button>
          <button className="quiet" onClick={reload}>{t("backup.refresh")}</button>
        </div>
      </Section>
      {restoring && <RestorePanel key={restoring.id} core={core} entry={restoring} creds={creds} onClose={() => setRestoring(null)} />}
      {/* Una restauración que quedó viva (se cerró la app) se retoma aquí aunque no haya entrada elegida: confirmar, revertir o abortar. */}
      {!restoring && liveRestore && <AssistExecution core={core} plan={null} onStarted={noop} onActive={noop} onError={setErr} />}

      {diff && (
        <>
          {diff.meta.masked && <Notice kind="warn">{t("backup.diff.maskedWarn")}</Notice>}
          <DiffView label={t("backup.diff.title")} before={diff.before} after={diff.after} />
          {diff.meta.ignored.length > 0 && <p className="meta">{t("backup.diff.ignored", { list: diff.meta.ignored.join("; ") })}</p>}
        </>
      )}
      {shown && (
        <ResultPanel title={t("backup.content")} meta={shown.meta.id} actions={<>
          <CopyButton value={shown.text} label={t("backup.copyLabel")} />
          <DownloadButton name={`${shown.meta.device}-${shown.meta.at.replace(/[-:]/g, "")}.cfg`} data={() => shown.text} label={t("backup.download")} />
        </>}>
          {shown.meta.masked && <div className="panel-body"><Notice kind="warn">{t("backup.shownMasked")}</Notice></div>}
          <Terminal text={shown.text} aria-label={shown.meta.id} />
        </ResultPanel>
      )}
    </Page>
  );
}
