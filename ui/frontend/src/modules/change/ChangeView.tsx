import { useEffect, useState } from "react";
import type { ChangeSummary, CoreAPI, Credential, LoginResult } from "../../lib/core";
import { Check, Field, Notice, Select, TextArea, errorText } from "../../components/Field";
import { Badge, EmptyState, Page, ResultPanel, Section, Tabs, useResult, type Tone } from "../../components/Page";
import { Hl, Terminal } from "../../components/Terminal";
import { ExportMenu } from "../../components/Files";
import { levelKey, reportMarkdown, verdictCounts, verdictKey, diffCounts, type DeviceReport } from "./report";
import { parseTargets } from "../patrol/PatrolView";
import { useT } from "../../lib/i18n";
import { outputsErrorText } from "../../lib/outputsError";
import { jobState } from "../../lib/vocab";
import type { Key } from "../../lib/i18n/es";
import "./change.css";
import { useVaultVersion } from "../../lib/vaultSignal";

// Ventana de cambio: la app solo recolecta (Patrol, comandos de lectura) y compara.
// Nunca aplica configuración.

type Sub = "prepost" | "upgrade" | "compliance";
const subs: [Sub, Key][] = [["prepost", "change.sub.prepost"], ["upgrade", "change.sub.upgrade"], ["compliance", "change.sub.compliance"]];

const verdictTone: Record<string, Tone> = { ok: "ok", review: "warn", regression: "bad" };
const stateTone = (s: string): Tone => (s === "completed" ? "ok" : s === "failed" ? "bad" : s ? "info" : "");

// El peor veredicto de los equipos resume el cambio.
function worst(devs: DeviceReport[], t: (k: Key) => string): { tone: Tone; label: string } {
  const v = devs.some((d) => d.verdict === "regression") ? "regression" : devs.some((d) => d.verdict === "review") ? "review" : "ok";
  return { tone: verdictTone[v], label: t(verdictKey[v]) };
}

function PrePost({ core }: { core: CoreAPI }) {
  const t = useT();
  const [creds, setCreds] = useState<Credential[]>([]);
  const [changes, setChanges] = useState<ChangeSummary[]>([]);
  const [name, setName] = useState("");
  const [targets, setTargets] = useState("");
  const [cred, setCred] = useState("");
  const [out, setOut] = useState("");
  const [current, setCurrent] = useState("");
  const [login, setLogin] = useState<LoginResult[]>([]);
  const [trusted, setTrusted] = useState<Set<string>>(new Set());
  const [msg, setMsg] = useState<{ kind: "info" | "warn"; text: string } | null>(null);
  const [err, setErr] = useState("");
  const [devices, setDevices] = useState<DeviceReport[] | null>(null);
  const [note, setNote] = useState("");
  const [rep, setRep] = useState<{ name: string; json: string } | null>(null);

  const refresh = () => core.listChanges().then(setChanges).catch((e) => setErr(errorText(e)));
  const vv = useVaultVersion(); // la bóveda cambió: volver a listar credenciales
  useEffect(() => {
    core.listCredentials().then((l) => { setCreds(l); setCred((c) => (l.some((x) => x.id === c) ? c : "")); }).catch(() => setCreds([]));
    refresh();
  }, [core, vv]);

  const guard = async (f: () => Promise<void>) => {
    setErr(""); setMsg(null);
    try {
      await f();
    } catch (e) {
      setErr(outputsErrorText(e, t));
    }
  };
  const create = () => guard(async () => {
    const id = await core.changeCreate({ name, targets: parseTargets(targets).map((address) => ({ address })), defaultCredentialId: cred, outputDir: out });
    setCurrent(id); setLogin([]); setTrusted(new Set()); setDevices(null);
    setMsg({ kind: "info", text: t("change.created", { id }) });
    await refresh();
  });
  const capture = (phase: "pre" | "post") => guard(async () => {
    const r = await core.changeCapture(current, phase, [...trusted], []);
    if (r.armed) {
      setLogin([]);
      setMsg({ kind: "info", text: t("change.capturing", { phase: phase.toUpperCase(), job: r.jobId }) });
    } else {
      setMsg({ kind: "warn", text: t("change.unarmed", { job: r.jobId, detail: r.detail }) });
      setLogin(await core.loginTest(r.jobId));
    }
    await refresh();
  });
  const showReport = (id: string) => guard(async () => {
    const r = await core.changeReport(id, "", "");
    const rep = JSON.parse(r.json) as { devices?: DeviceReport[]; note?: string };
    setDevices(rep.devices ?? []); setNote(rep.note ?? "");
    setRep({ name: changes.find((c) => c.id === id)?.name ?? id, json: JSON.stringify(rep, null, 2) });
  });
  const toggle = (fp: string, on: boolean) => setTrusted((s) => { const n = new Set(s); if (on) n.add(fp); else n.delete(fp); return n; });

  return (
    <>
      <Section title={t("change.sec.new")} description={t("change.prepost.hint")}>
        <div className="field-row">
          <Field label={t("change.name")} value={name} onChange={setName} w="md" />
          <Field label={t("change.targets")} value={targets} onChange={setTargets} w="lg" mono />
        </div>
        <div className="field-row">
          <Select label={t("assist.cred")} value={cred} onChange={setCred} w="md" options={[["", t("change.pick")], ...creds.map((c) => [c.id, `${c.label} (${c.username})`] as [string, string])]} />
          <Field label={t("change.outDir")} value={out} onChange={setOut} w="lg" mono />
        </div>
        <div className="actions">
          <button className="primary" disabled={!name || !targets || !cred} onClick={create}>{t("change.create")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
        </div>
      </Section>
      {msg && <Notice kind={msg.kind}>{msg.text}</Notice>}
      {err && <Notice kind="error">{err}</Notice>}
      {current && (
        <Section title={t("change.sec.capture")}>
          <div className="actions">
            <button onClick={() => capture("pre")}>{t("change.capture", { phase: "PRE" })}</button>
            <button onClick={() => capture("post")}>{t("change.capture", { phase: "POST" })}</button>
          </div>
          {login.filter((l) => l.fingerprint).map((l) => (
            <Check key={l.fingerprint} label={t("change.trust", { fp: l.fingerprint, target: l.target })} checked={trusted.has(l.fingerprint)} onChange={(v) => toggle(l.fingerprint, v)} />
          ))}
          {login.filter((l) => !l.passed && !l.fingerprint).map((l) => <Notice key={l.target} kind="warn"><code>{l.target}</code> {l.failedStep} {l.detail}</Notice>)}
        </Section>
      )}
      <Section title={t("change.sec.list")}>
        {changes.length === 0 ? <EmptyState icon="layers" title={t("change.empty.title")}>{t("change.empty")}</EmptyState> : (
          <div className="table-wrap change-table">
            <table>
              <thead><tr><th>{t("change.col.change")}</th><th>PRE</th><th>POST</th><th><span className="sr">{t("change.col.actions")}</span></th></tr></thead>
              <tbody>
                {changes.map((c) => (
                  <tr key={c.id}>
                    <td><button className="quiet sm" onClick={() => { setCurrent(c.id); setLogin([]); setTrusted(new Set()); }} aria-current={current === c.id ? "true" : undefined}>{c.name}</button></td>
                    <td>{c.preState ? <Badge tone={stateTone(c.preState)}>{jobState(t, c.preState)}</Badge> : "—"}</td>
                    <td>{c.postState ? <Badge tone={stateTone(c.postState)}>{jobState(t, c.postState)}</Badge> : "—"}</td>
                    <td className="row-actions"><button className="sm" disabled={c.preState !== "completed" || c.postState !== "completed"} onClick={() => showReport(c.id)} aria-label={t("change.reportOf", { name: c.name })}>{t("change.report")}</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
      {devices && rep && (
        <div aria-live="polite">
          <ResultPanel title={t("change.sum.title")} status={worst(devices, t)} meta={t("change.sum.counts", verdictCounts(devices))}
            actions={<ExportMenu name={rep.name} formats={[{ fmt: "md", data: () => reportMarkdown(rep.name, devices, note, t) }, { fmt: "json", data: () => rep.json }]} />} />
          {devices.map((d) => (
            <ResultPanel key={d.address} title={`${d.hostname || d.address} (${d.address})`} meta={d.config_diff.length > 0 ? t("change.diffCount", diffCounts(d.config_diff)) : undefined} status={{ tone: verdictTone[d.verdict] ?? "", label: verdictKey[d.verdict] ? t(verdictKey[d.verdict]) : d.verdict }}>
              {d.findings.length > 0 && (
                <div className="table-wrap flat">
                  <table>
                    <thead><tr><th>{t("change.col.level")}</th><th>{t("change.col.facet")}</th><th>{t("change.col.detail")}</th></tr></thead>
                    <tbody>
                      {d.findings.map((f, i) => (
                        <tr key={i}>
                          <td><Badge tone={verdictTone[f.level] ?? ""}>{levelKey[f.level] ? t(levelKey[f.level]) : f.level}</Badge></td>
                          <td className="mono">{f.facet}</td>
                          <td className="mono wrap">{f.detail}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {d.config_diff.length > 0 && <p className="panel-body meta">{t("change.diffNote")}</p>}
              {d.config_diff.length > 0 && (
                <Terminal as="ul" aria-label={t("change.configDiff")}>
                  {d.config_diff.map((l, i) => <li key={i} data-op={l.startsWith("-") ? "-" : l.startsWith("+") ? "+" : " "}><Hl text={l} /></li>)}
                </Terminal>
              )}
              {d.findings.length === 0 && d.config_diff.length === 0 && <p className="panel-body meta">{t("change.noFindings")}</p>}
            </ResultPanel>
          ))}
          {note && <Notice kind="info">{note}</Notice>}
        </div>
      )}
    </>
  );
}

function Upgrade({ core }: { core: CoreAPI }) {
  const t = useT();
  const [outputs, setOutputs] = useState("");
  const [image, setImage] = useState("");
  const [size, setSize] = useState("");
  const [md5, setMd5] = useState("");
  const [verify, setVerify] = useState("");
  const r = useResult<{ text: string }>();
  const check = () => r.run(() => core.upgradeCheck({ outputs, image, size: Number(size) || 0, md5, verify }));
  return (
    <>
      <Section title={t("change.sub.upgrade")} description={t("change.upgrade.hint")}>
        <TextArea label={t("change.upgrade.outputs")} value={outputs} onChange={setOutputs} rows={8} />
        <div className="field-row">
          <Field label={t("change.upgrade.image")} value={image} onChange={setImage} w="lg" mono />
          <Field label={t("change.upgrade.size")} type="number" value={size} onChange={setSize} w="sm" mono />
          <Field label={t("change.upgrade.md5")} value={md5} onChange={setMd5} w="lg" mono />
        </div>
        <TextArea label={t("change.upgrade.verify")} value={verify} onChange={setVerify} rows={3} />
        <div className="actions">
          <button className="primary" disabled={!outputs || !image || r.busy} aria-busy={r.busy} onClick={check}>{t("change.upgrade.check")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
        </div>
      </Section>
      <Outcome r={r} empty={t("change.upgrade.empty")} />
    </>
  );
}

// Resultado de una verificación: vacío con la instrucción, o panel con el texto (o el error) del núcleo.
function Outcome({ r, empty }: { r: ReturnType<typeof useResult<{ text: string }>>; empty: string }) {
  const t = useT();
  if (!r.busy && !r.data && !r.error) return <EmptyState icon="info" title={t("change.empty.result")}>{empty}</EmptyState>;
  return (
    <ResultPanel title={t("common.output")} error={r.error} status={r.busy ? { tone: "info", label: t("change.running") } : undefined}>
      {r.data && <Terminal text={r.data.text} aria-label={t("common.output")} />}
    </ResultPanel>
  );
}

function Compliance({ core }: { core: CoreAPI }) {
  const t = useT();
  const [config, setConfig] = useState("");
  const [template, setTemplate] = useState("");
  const r = useResult<{ text: string }>();
  return (
    <>
      <Section title={t("change.sub.compliance")} description={t("change.compliance.hint")}>
        <TextArea label={t("change.compliance.config")} value={config} onChange={setConfig} rows={8} />
        <TextArea label={t("change.compliance.template")} value={template} onChange={setTemplate} rows={6} />
        <div className="actions">
          <button className="primary" disabled={!config || r.busy} aria-busy={r.busy} onClick={() => r.run(() => core.complianceCheck(config, template))}>{t("change.compliance.eval")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
        </div>
      </Section>
      <Outcome r={r} empty={t("change.compliance.empty")} />
    </>
  );
}

export function ChangeView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sub, setSub] = useState<Sub>("prepost");
  return (
    <Page title={t("nav.change")} description={t("change.desc")}
      tabs={<Tabs label={t("change.tool")} value={sub} onChange={setSub} tabs={subs.map(([s, l]) => [s, t(l)] as [Sub, string])} />}>
      {sub === "prepost" && <PrePost core={core} />}
      {sub === "upgrade" && <Upgrade core={core} />}
      {sub === "compliance" && <Compliance core={core} />}
    </Page>
  );
}
