// Lee el JSON de tlsinspect.Report (el texto que devuelve la inspección TLS). Sin cadena devuelve null.
import type { Tone } from "../../components/Page";

export interface ChainCert { role: "leaf" | "intermediate" | "root"; subject: string; issuer: string; sans: string[]; notAfter: string; daysLeft: number; sha256: string; isCA: boolean; keyType: string; sigAlg: string }
export interface TlsInfo { target: string; version: string; cipher: string; alpn: string; verified: boolean; verifyError: string; verifyCode?: string; nameMatches: boolean; chain: ChainCert[]; findings: { severity: string; code: string; detail: string }[] }

const str = (v: unknown) => (typeof v === "string" ? v : "");
const DAY = 864e5;

// Aviso por debajo de 30 días; malo por debajo de 7 o vencido.
export const certTone = (days: number): Tone => (Number.isNaN(days) ? "" : days < 7 ? "bad" : days < 30 ? "warn" : "ok");

export function parseTls(text: string, now = Date.now()): TlsInfo | null {
  let j: Record<string, unknown>;
  try { j = JSON.parse(text); } catch { return null; }
  if (!j || typeof j !== "object" || !Array.isArray(j.Chain) || !j.Chain.length) return null;
  const raw = j.Chain as Record<string, unknown>[];
  const chain = raw.map((c, i): ChainCert => {
    const subject = str(c.Subject), issuer = str(c.Issuer);
    const root = i > 0 && i === raw.length - 1 && subject === issuer; // el primero siempre es el del servidor
    return {
      role: i === 0 ? "leaf" : root ? "root" : "intermediate", subject, issuer,
      sans: Array.isArray(c.SANs) ? c.SANs.filter((x): x is string => typeof x === "string") : [],
      notAfter: str(c.NotAfter), daysLeft: Math.floor((Date.parse(str(c.NotAfter)) - now) / DAY),
      sha256: str(c.SHA256), isCA: c.IsCA === true, keyType: [str(c.KeyType), c.KeyBits].filter(Boolean).join(" "), sigAlg: str(c.SigAlg),
    };
  });
  const findings = Array.isArray(j.Findings) ? (j.Findings as Record<string, unknown>[]).map((f) => ({ severity: str(f.Severity), code: str(f.Code), detail: str(f.Detail) })) : [];
  return { target: str(j.Target), version: str(j.Version), cipher: str(j.Cipher), alpn: str(j.ALPN), verified: j.Verified === true, verifyError: str(j.VerifyError), nameMatches: j.NameMatches === true, chain, findings };
}
