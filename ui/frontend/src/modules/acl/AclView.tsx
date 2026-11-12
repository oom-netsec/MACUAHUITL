import { useState } from "react";
import type { Acl, AclFinding, CoreAPI } from "../../lib/core";
import { Notice, Select, TextArea } from "../../components/Field";
import { EmptyState, Page, ResultPanel, Section, useResult } from "../../components/Page";
import { Icon } from "../../components/Icon";
import { CopyButton } from "../../components/Data";
import { ExportMenu } from "../../components/Files";
import { tableCsv, tableMarkdown } from "../../lib/tableExport";
import { Terminal } from "../../components/Terminal";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import "./acl.css";

const vendors: [string, string][] = [["ios-xe", "Cisco IOS / IOS-XE"], ["nx-os", "Cisco NX-OS"], ["asa", "Cisco ASA"]];

const opts = (r: Acl["rules"][number]) => [r.destinationPorts, r.established && "established", r.log && "log"].filter(Boolean).join(" ");
// La regla como una línea, para pegarla en un equipo o en un correo.
const ruleLine = (r: Acl["rules"][number]) => [r.action, r.protocol, r.source, r.sourcePorts, r.destination, opts(r)].filter(Boolean).join(" ");
// Una IP o red se copia sola; "any" no.
const Addr = ({ v }: { v: string }) => <>{v}{v && v !== "any" && <CopyButton value={v} label={v} />}</>;

// Importa una ACL, muestra hallazgos y la vuelve a generar para otra plataforma.
// La salida es texto para copiar: nunca se aplica a un equipo (spec §13).
export function AclView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [from, setFrom] = useState("ios-xe");
  const [to, setTo] = useState("nx-os");
  const [text, setText] = useState("");
  const [copied, setCopied] = useState(false);
  const imp = useResult<{ acl: Acl; findings: AclFinding[] }>();
  const gen = useResult<string>();
  const busy = imp.busy || gen.busy;

  const importAndAnalyze = () => {
    gen.reset();
    return imp.run(async () => {
      const acl = await core.aclImport(from, text);
      return { acl, findings: await core.aclAnalyze(acl) };
    });
  };
  const acl = imp.data?.acl;
  const findings = imp.data?.findings ?? [];
  const byIndex = new Map(findings.map((f) => [f.index, f]));
  const kind = (k: string) => (["shadowed", "redundant", "impossible"].includes(k) ? t(`acl.kind.${k}` as Key) : k);
  const exportRows = () => acl?.rules.map((r, i) => {
    const f = byIndex.get(i);
    return [String(i + 1), r.action, r.protocol, r.source, r.sourcePorts, r.destination, opts(r), f ? `${kind(f.kind)}: ${f.detail}` : ""];
  }) ?? [];
  const exportHead = ["#", t("acl.col.action"), t("acl.col.proto"), t("acl.col.src"), t("acl.col.srcPorts"), t("acl.col.dst"), t("acl.col.dstPorts"), t("acl.col.finding")];
  const copy = async () => { await core.copyText(gen.data ?? ""); setCopied(true); window.setTimeout(() => setCopied(false), 1500); };

  return (
    <Page title={t("acl.title")} description={t("acl.desc")}>
      <Section title={t("acl.section.import")}>
        <Select label={t("acl.from")} value={from} onChange={setFrom} options={vendors} w="md" />
        <TextArea label={t("acl.input")} rows={10} value={text} onChange={setText} />
        <div className="actions">
          <button className="primary" onClick={importAndAnalyze} disabled={busy || !text.trim()} aria-busy={imp.busy}>{t("acl.import")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
        </div>
      </Section>
      {imp.error && <Notice kind="error">{imp.error}</Notice>}
      {!acl && !imp.error && <EmptyState icon="shield" title={t("acl.empty.title")}>{t("acl.empty")}</EmptyState>}
      {acl && (
        <>
          <ResultPanel title={acl.name || t("acl.rules")} status={findings.length ? { tone: "warn", label: t("acl.findings", { n: findings.length }) } : { tone: "ok", label: t("acl.findings.none") }}
            actions={<ExportMenu name={acl.name || "acl"} formats={[{ fmt: "csv", data: () => tableCsv(exportHead, exportRows()) }, { fmt: "md", data: () => tableMarkdown(exportHead, exportRows()) }]} />}>
            <div className="table-wrap acl-rules">
              <table aria-label={acl.name}>
                <thead>
                  <tr><th>#</th><th>{t("acl.col.action")}</th><th>{t("acl.col.proto")}</th><th>{t("acl.col.src")}</th><th>{t("acl.col.srcPorts")}</th>
                    <th>{t("acl.col.dst")}</th><th>{t("acl.col.dstPorts")}</th><th>{t("acl.col.finding")}</th></tr>
                </thead>
                <tbody>
                  {acl.rules.map((r, i) => {
                    const f = byIndex.get(i);
                    return (
                      <tr key={i} data-kind={f?.kind}>
                        <td className="mono">{i + 1}<CopyButton value={ruleLine(r)} label={t("acl.rule", { n: i + 1 })} /></td><td>{r.action}</td><td>{r.protocol}</td><td className="mono"><Addr v={r.source} /></td><td className="mono">{r.sourcePorts}</td>
                        <td className="mono"><Addr v={r.destination} /></td>
                        <td className="mono">{opts(r)}</td>
                        <td>{f ? `${kind(f.kind)}: ${f.detail}` : ""}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </ResultPanel>
          <Section title={t("acl.section.generate")} description={t("acl.result.hint")}>
            <Select label={t("acl.to")} value={to} onChange={setTo} options={vendors} w="md" />
            <div className="actions">
              <button className="primary" onClick={() => gen.run(() => core.aclGenerate(to, acl))} disabled={busy} aria-busy={gen.busy}>{t("acl.generate")}</button>
            </div>
          </Section>
          {(gen.data || gen.error) && (
            <ResultPanel title={t("acl.result")} error={gen.error}
              actions={<>
                <button className="quiet sm" disabled={!gen.data} onClick={copy}><Icon name="copy" size={14} />{t(copied ? "common.copied" : "common.copy")}</button>
                <button className="quiet sm" onClick={gen.reset}>{t("common.clear")}</button>
              </>}>
              <Terminal text={gen.data ?? ""} role="log" aria-label={t("acl.result")} />
            </ResultPanel>
          )}
        </>
      )}
    </Page>
  );
}
