// Traza DNS como árbol con sangría: raíz → TLD → autoritativo, con servidor, RTT y respuesta de cada nivel.
import { CopyButton, Duration } from "../../components/Data";
import { Badge, Section } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import type { Trace } from "./dnsTrace";
import "./tools.css";

export function DnsTree({ trace }: { trace: Trace }) {
  const t = useT();
  const total = Math.round(trace.steps.reduce((a, s) => a + s.rttMs, 0));
  return (
    <div className="tools-report">
      <Section title={t("dns.trace.title")} description={`${trace.name} ${trace.type} · ${t("dns.trace.total", { n: trace.steps.length, ms: total })}`}>
        <ol className="dns-tree" aria-label={t("dns.trace.title")}>
          {trace.steps.map((s, i) => (
            <li key={i} className="dns-step" style={{ "--depth": Math.min(s.depth, 4) } as React.CSSProperties}>
              <div>
                <Badge>{t(`dns.trace.level.${Math.min(s.depth, 2)}` as Key)}</Badge>
                <span className="zone mono">{s.zone === "." ? t("dns.trace.zone.root") : s.zone}</span>
                <span className="mono">{s.server}</span>
                {s.ip && <><span className="mono">{s.ip}</span><CopyButton value={s.ip} label={s.ip} /></>}
                {!s.error && <Duration ms={s.rttMs} />}
                {s.rcode && <Badge tone={s.rcode === "NOERROR" ? "" : "warn"}>{s.rcode}</Badge>}
                {s.aa && <Badge tone="info">{t("dns.trace.aa")}</Badge>}
                {s.error && <Badge tone="bad">{t("dns.trace.failed", { error: s.error })}</Badge>}
              </div>
              {s.referral && <div className="detail">{t("dns.trace.refer", { zone: s.referral })}</div>}
              {s.answers.length > 0 && <div className="detail mono">{t("dns.trace.answer")}: {s.answers.join(" · ")}</div>}
            </li>
          ))}
        </ol>
        {(trace.final.length > 0 || trace.rcode) && (
          <p className="dns-final">
            <strong>{t("dns.trace.final")}</strong>{" "}
            {trace.rcode && <Badge tone={trace.rcode === "NOERROR" ? "ok" : "warn"}>{t("dns.trace.rcode", { rcode: trace.rcode })}</Badge>}
            {trace.final.map((f) => <span key={f} className="mono block">{f}</span>)}
          </p>
        )}
        {trace.cnames.length > 0 && <p className="hint">{t("dns.trace.cname")}: <span className="mono">{trace.cnames.join(" · ")}</span></p>}
        {trace.warnings.map((w) => <p key={w} className="hint">{w}</p>)}
      </Section>
    </div>
  );
}
