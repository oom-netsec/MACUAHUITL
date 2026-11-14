import type { ReactNode } from "react";
import { CopyButton, Duration, StatusPill } from "../../components/Data";
import { Badge, ResultPanel, type Tone } from "../../components/Page";
import { Meter } from "../../components/charts/Mini";
import { Terminal } from "../../components/Terminal";
import { useT } from "../../lib/i18n";
import { vocab } from "../../lib/vocab";
import type { IkeReportData, PkiReportData, RadiusReportData, TacacsReportData } from "./api";
import { daysState, parsePki, parseRadius, parseTacacs, pkiFromData, radiusFromData, tacacsFromData, type CertInfo, type Finding } from "./parse";

// Tarjetas de resultado de RADIUS y TACACS+ y cadena de certificados de PKI, a partir del informe estructurado del núcleo
// o, sin él, de su texto. Si el texto no tiene la forma esperada, se muestra tal cual en la terminal.

const findingTone = (s: string): Tone => (s === "error" ? "bad" : s === "warning" ? "warn" : "info");

function Raw({ text }: { text: string }) {
  const t = useT();
  return <details className="raw-output"><summary>{t("security.rawOutput")}</summary><Terminal text={text} aria-label={t("common.output")} /></details>;
}

function Findings({ list }: { list: Finding[] }) {
  const t = useT();
  if (!list.length) return null;
  return (
    <ResultPanel title={t("security.findings")} pad>
      <ul className="findings">{list.map((f, i) => <li key={i}><Badge tone={findingTone(f.severity)}>{vocab(t, "findingSev", f.severity)}</Badge> {f.detail}</li>)}</ul>
    </ResultPanel>
  );
}

function Head({ children }: { children: ReactNode }) {
  return <p className="meta mono">{children}</p>;
}

export function ResultCards({ kind, text, report, fallback }: { kind: "radius" | "tacacs"; text: string; report?: RadiusReportData | TacacsReportData; fallback: ReactNode }) {
  const t = useT();
  const attrTable = (title: string, head: [string, string], rows: [string, string][]) => (
    rows.length ? (
      <div className="table-wrap flat">
        <table aria-label={t("security.card.attrs", { kind: title })}>
          <thead><tr><th scope="col">{head[0]}</th><th scope="col">{head[1]}</th></tr></thead>
          <tbody>{rows.map((r, i) => <tr key={i}><td className="mono">{r[0]}</td><td className="mono">{r[1]}</td></tr>)}</tbody>
        </table>
      </div>
    ) : null
  );
  if (kind === "radius") {
    const r = report ? radiusFromData(report as RadiusReportData) : parseRadius(text);
    if (!r) return <>{fallback}</>;
    return (
      <div className="sec-cards">
        <Head>{[t("security.card.server", { server: r.server }), r.method && t("security.card.method", { method: r.method })].filter(Boolean).join(" · ")}</Head>
        {r.exchanges.map((e, i) => {
          const tone: Tone = !e.code ? "bad" : e.code === "Access-Accept" ? "ok" : e.code === "Access-Challenge" ? "warn" : e.code === "Access-Reject" ? "bad" : "warn";
          return (
            <ResultPanel key={i} title={vocab(t, "exchange", e.kind)} status={{ tone, label: e.code || t("security.card.noReply") }}
              meta={e.code ? <><Duration ms={e.rttMs} /> · {t("security.card.attempt", { n: e.attempts })} · {t("security.card.ma", { v: vocab(t, "ma", e.messageAuthenticator) })}{e.mschap2Verified !== undefined && <> · {t(e.mschap2Verified ? "security.card.mschap2.ok" : "security.card.mschap2.bad")}</>}</> : undefined}>
              {e.error && <p className="panel-body meta">{e.error}</p>}
              {attrTable(vocab(t, "exchange", e.kind), [t("security.card.attr"), t("security.card.value")], e.attrs.map((a) => [a.name, a.value]))
                ?? (e.code && <p className="panel-body meta">{t("security.card.none")}</p>)}
            </ResultPanel>
          );
        })}
        <Findings list={r.findings} />
        <Raw text={text} />
      </div>
    );
  }
  const r = report ? tacacsFromData(report as TacacsReportData) : parseTacacs(text);
  if (!r) return <>{fallback}</>;
  return (
    <div className="sec-cards">
      <Head>{t("security.card.server", { server: r.server })}</Head>
      {r.steps.map((s, i) => {
        const tone: Tone = /^PASS/.test(s.status) ? "ok" : !s.status || /^(FAIL|ERROR)/.test(s.status) ? "bad" : "warn";
        return (
          <ResultPanel key={i} title={vocab(t, "exchange", s.kind)} status={{ tone, label: s.status || t("security.card.noReply") }} meta={s.status ? <Duration ms={s.rttMs} /> : undefined}>
            {s.error && <p className="panel-body meta">{s.error}</p>}
            {s.prompts.map((p, j) => <p key={j} className="panel-body meta">{t("security.card.prompt", { p })}</p>)}
            {s.message && <p className="panel-body meta">{t("security.card.message", { m: s.message })}</p>}
            {s.data && <p className="panel-body meta">{t("security.card.data", { d: s.data })}</p>}
            {attrTable(vocab(t, "exchange", s.kind), [t("security.card.dir"), t("security.card.attr")], [...s.sent.map((a): [string, string] => [t("security.card.sent"), a]), ...s.received.map((a): [string, string] => [t("security.card.recv"), a])])}
          </ResultPanel>
        );
      })}
      <Findings list={r.findings} />
      <Raw text={text} />
    </div>
  );
}

const phaseTone = (p: string): Tone => (p === "established" ? "ok" : p === "failed" ? "bad" : p === "mixed" || p === "incomplete" ? "warn" : "info");

// Decodificador IKE: tarjetas de fase 1 y 2, hallazgos con su acción y evidencia, y propuestas; todo del informe estructurado.
export function IkeCards({ report }: { report: IkeReportData }) {
  const t = useT();
  return (
    <div className="sec-cards">
      {([[1, report.phase1], [2, report.phase2]] as const).map(([n, p]) => (
        <ResultPanel key={n} title={t(n === 1 ? "security.ike.phase1" : "security.ike.phase2")} status={{ tone: phaseTone(p), label: vocab(t, "phase", p) }} />
      ))}
      {report.note && <p className="hint">{report.note}</p>}
      {report.findings.length > 0 && (
        <ResultPanel title={t("security.findings")} pad>
          <ul className="findings">{report.findings.map((f, i) => (
            <li key={i}>
              <Badge tone={findingTone(f.severity)}>{vocab(t, "findingSev", f.severity)}</Badge> <strong>{f.title}</strong>
              <p className="meta">{f.explanation}</p>
              <p className="meta">{t("security.ike.action")}: {f.action}</p>
              {f.evidence.length > 0 && <Terminal text={f.evidence.join("\n")} aria-label={t("security.ike.evidence")} />}
            </li>
          ))}</ul>
        </ResultPanel>
      )}
      {report.proposals.length > 0 && (
        <ResultPanel title={t("security.ike.proposals")}>
          <div className="table-wrap flat">
            <table aria-label={t("security.ike.proposals")}>
              <thead><tr>{(["phase", "source", "detail", "result"] as const).map((c) => <th key={c} scope="col">{t(`security.ike.col.${c}`)}</th>)}</tr></thead>
              <tbody>{report.proposals.map((p, i) => (
                <tr key={i}><td>{p.phase}</td><td>{p.source}</td><td className="mono">{p.detail}</td><td>{p.result ? vocab(t, "proposal", p.result) : ""}</td></tr>
              ))}</tbody>
            </table>
          </div>
        </ResultPanel>
      )}
      <Raw text={report.text} />
    </div>
  );
}

function Cert({ c }: { c: CertInfo }) {
  const t = useT();
  const days = c.daysLeft;
  const st = days == null ? null : daysState(days);
  const total = (Date.parse(c.notAfter) - Date.parse(c.notBefore)) / 86_400_000;
  const consumed = days != null && total > 0 ? Math.max(0, Math.min(100, Math.round((1 - days / total) * 100))) : null;
  const pill = st == null || days == null ? null
    : st === "expired" ? <StatusPill tone="bad" label={t("security.chain.expired", { n: -days })} />
    : st === "ok" ? <StatusPill tone="ok" label={t("security.chain.ok", { n: days })} />
    : <StatusPill tone={st === "bad" ? "bad" : "warn"} label={t("security.chain.soon", { n: days })} />;
  const rows: [string, string][] = [[t("security.chain.issuer"), c.issuer], [t("security.chain.valid"), c.notBefore && `${c.notBefore} → ${c.notAfter}`],
    [t("security.chain.key"), [c.keyType, c.sigAlg].filter(Boolean).join(" · ")], [t("security.chain.san"), c.san], [t("security.chain.usage"), c.usage]];
  return (
    <li className="chain-item" data-state={st ?? undefined}>
      <div className="chain-head">
        <Badge>{c.kind === "csr" ? t("security.chain.csr") : t("security.chain.cert")}</Badge>
        {c.isCA && <Badge tone="info">{t("security.chain.ca")}</Badge>}
        {c.selfSigned && <Badge>{t("security.chain.selfSigned")}</Badge>}
        {c.sigValid === false && <Badge tone="bad">{t("security.chain.sigInvalid")}</Badge>}
        <strong className="mono">{c.subject}</strong>
        {pill}
        {consumed != null && days != null && total > 0 && (
          <Meter label={t("security.chain.consumed")} value={consumed} unit="%" warn={Math.max(0, 100 * (1 - 30 / total))} crit={Math.max(0, 100 * (1 - 7 / total))} />
        )}
      </div>
      <dl className="chain-kv">
        {rows.filter(([, v]) => v).map(([k, v]) => <div key={k}><dt>{k}</dt><dd className="mono">{v}</dd></div>)}
        {([["SHA-256", c.sha256], ["SHA-1", c.sha1]] as const).filter(([, v]) => v).map(([alg, v]) => (
          <div key={alg}><dt>{alg}</dt><dd className="mono">{v} <CopyButton value={v} label={t("security.chain.fp", { alg })} /></dd></div>
        ))}
      </dl>
      {c.warnings.map((w, i) => <p key={i} className="meta">{w}</p>)}
    </li>
  );
}

export function CertChain({ text, report, fallback }: { text: string; report?: PkiReportData; fallback: ReactNode }) {
  const t = useT();
  const certs = report?.certificates.length ? pkiFromData(report) : parsePki(text);
  if (!certs) return <>{fallback}</>;
  return (
    <div className="sec-cards">
      <ol className="chain" aria-label={t("security.chain.label")}>{certs.map((c, i) => <Cert key={i} c={c} />)}</ol>
      <Raw text={text} />
    </div>
  );
}
