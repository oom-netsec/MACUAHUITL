// Cadena de certificados TLS en vertical: del servidor a la raíz, con cuenta regresiva de vencimiento y huella copiable.
import { CopyButton, StatusPill } from "../../components/Data";
import { Badge, Section } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { certTone, type TlsInfo } from "./tlsChain";
import "./tools.css";

const verifyCodes = ["unknown_authority", "hostname", "expired", "not_yet_valid"];
const verifyKey = (c?: string) => (c && verifyCodes.includes(c) ? c : "other"); // código desconocido o ausente = other

export function TlsChain({ info }: { info: TlsInfo }) {
  const t = useT();
  return (
    <div className="tools-report">
      <Section title={t("tls.chain.title")} description={[info.target, info.version && t("tls.summary", { version: info.version, cipher: info.cipher, alpn: info.alpn || "—" })].filter(Boolean).join(" · ")}>
        <p className="tls-status">
          <StatusPill tone={info.verified ? "ok" : "bad"} label={t(info.verified ? "tls.verified" : "tls.unverified")} />{" "}
          <StatusPill tone={info.nameMatches ? "ok" : "bad"} label={t(info.nameMatches ? "tls.nameOk" : "tls.nameBad")} />
          {!info.verified && <span className="hint"> {info.verifyCode !== undefined || !info.verifyError ? t(`tls.verify.${verifyKey(info.verifyCode)}` as Key) : info.verifyError}</span>}
        </p>
        <ol className="tls-chain" aria-label={t("tls.chain.title")}>
          {info.chain.map((c, i) => {
            const days = c.daysLeft;
            return (
              <li key={i} className="tls-cert">
                <div>
                  <Badge>{t(`tls.role.${c.role}` as Key)}</Badge>
                  <span className="role mono">{c.subject}</span>
                  <StatusPill tone={certTone(days)} label={Number.isNaN(days) ? "—" : days < 0 ? t("tls.expired", { n: -days }) : t("tls.days", { n: days })} />
                </div>
                <dl>
                  <dt>{t("tls.field.issuer")}</dt><dd className="mono">{c.issuer}</dd>
                  <dt>{t("tls.field.expires")}</dt><dd className="mono"><time dateTime={c.notAfter}>{new Date(c.notAfter).toLocaleDateString()}</time></dd>
                  {c.sans.length > 0 && <><dt>{t("tls.field.names")}</dt><dd className="mono">{c.sans.join(", ")}</dd></>}
                  {(c.keyType || c.sigAlg) && <><dt>{t("tls.field.key")}</dt><dd className="mono">{[c.keyType, c.sigAlg].filter(Boolean).join(" · ")}</dd></>}
                  {c.sha256 && <><dt>{t("tls.field.sha")}</dt><dd className="mono">{c.sha256}<CopyButton value={c.sha256} label={t("tls.field.sha")} /></dd></>}
                </dl>
              </li>
            );
          })}
        </ol>
      </Section>
    </div>
  );
}
