// Tarjetas de RADIUS, TACACS+ y PKI. Con el informe estructurado (fase 30b) se convierte directo; sin él (núcleo anterior)
// se lee el texto del núcleo (Report.Text de radiustest y tacacstest, pki.Text) y, si no tiene la forma esperada, devuelve
// null y la vista muestra la salida tal cual. Los dos caminos dan los mismos códigos cerrados en inglés.
import type { Certificate, PkiReportData, RadiusReportData, SecFindingData, TacacsReportData } from "./api";

export interface Finding { severity: "warning" | "error" | "info"; detail: string }
export interface Attr { name: string; value: string }

export interface RadiusExchange { kind: string; code: string; rttMs: number; attempts: number; messageAuthenticator: "absent" | "valid" | "invalid" | ""; error: string; attrs: Attr[] }
export interface RadiusReport { server: string; method: string; exchanges: RadiusExchange[]; findings: Finding[] }

export interface TacacsStep { kind: string; status: string; rttMs: number; error: string; prompts: string[]; message: string; data: string; sent: string[]; received: string[] }
export interface TacacsReport { server: string; steps: TacacsStep[]; findings: Finding[] }

export interface CertInfo {
  kind: "certificate" | "csr"; subject: string; issuer: string; serial: string; notBefore: string; notAfter: string; daysLeft: number | null;
  keyType: string; sigAlg: string; san: string; isCA: boolean; sha1: string; sha256: string; warnings: string[];
  usage: string; selfSigned: boolean; sigValid?: boolean; // solo del informe estructurado
}

const SEV: Record<string, Finding["severity"]> = { aviso: "warning", error: "error", info: "info" };
const MA: Record<string, "absent" | "valid" | "invalid"> = { "ausente": "absent", "válido": "valid", "inválido": "invalid" };
const FINDING = /^ {2}\[(.+?)\] (.*)$/;

function split(text: string) {
  const lines = text.split("\n");
  const at = lines.indexOf("Hallazgos:");
  const body = at < 0 ? lines : lines.slice(0, at);
  const findings = (at < 0 ? [] : lines.slice(at + 1)).flatMap((l): Finding[] => { const m = FINDING.exec(l); return m ? [{ severity: SEV[m[1]] ?? "info", detail: m[2] }] : []; });
  return { body, findings };
}

export function parseRadius(text: string): RadiusReport | null {
  const { body, findings } = split(text);
  const head = /^Servidor RADIUS (\S+)(?: \(método (\S+)\))?$/.exec(body[0] ?? "");
  if (!head) return null;
  const exchanges: RadiusExchange[] = [];
  for (const l of body.slice(1)) {
    const ex = /^(\S+): (.+)$/.exec(l);
    if (ex) {
      const r = /^(.+?) en ([\d.]+) ms \(intento (\d+), Message-Authenticator (.+)\)$/.exec(ex[2]);
      exchanges.push({ kind: ex[1], code: r?.[1] ?? "", rttMs: r ? Number(r[2]) : 0, attempts: r ? Number(r[3]) : 0, messageAuthenticator: MA[r?.[4] ?? ""] ?? "", error: "", attrs: [] });
      continue;
    }
    const cur = exchanges[exchanges.length - 1];
    if (!cur) continue;
    if (l.startsWith("  ! ")) cur.error = l.slice(4);
    else { const a = /^ {2}(\S+) +(.*)$/.exec(l); if (a) cur.attrs.push({ name: a[1], value: a[2] }); }
  }
  return exchanges.length ? { server: head[1], method: head[2] ?? "", exchanges, findings } : null;
}

export function parseTacacs(text: string): TacacsReport | null {
  const { body, findings } = split(text);
  const head = /^Servidor TACACS\+ (\S+)$/.exec(body[0] ?? "");
  if (!head) return null;
  const steps: TacacsStep[] = [];
  for (const l of body.slice(1)) {
    const st = /^(\S+): (.+)$/.exec(l);
    if (st) {
      const r = /^(\S+) en ([\d.]+) ms$/.exec(st[2]);
      steps.push({ kind: st[1], status: r?.[1] ?? "", rttMs: r ? Number(r[2]) : 0, error: "", prompts: [], message: "", data: "", sent: [], received: [] });
      continue;
    }
    const cur = steps[steps.length - 1];
    if (!cur) continue;
    let m: RegExpExecArray | null;
    if (l.startsWith("  ! ")) cur.error = l.slice(4);
    else if ((m = /^ {2}servidor pidió: "(.*)"$/.exec(l))) cur.prompts.push(m[1]);
    else if (l.startsWith("  mensaje: ")) cur.message = l.slice(11);
    else if (l.startsWith("  datos: ")) cur.data = l.slice(9);
    else if (l.startsWith("  enviado  ")) cur.sent.push(l.slice(11));
    else if (l.startsWith("  recibido ")) cur.received.push(l.slice(11));
  }
  return steps.length ? { server: head[1], steps, findings } : null;
}

export function parsePki(text: string): CertInfo[] | null {
  const out: CertInfo[] = [];
  for (const l of text.split("\n")) {
    const h = /^(certificado|CSR): (.*)$/.exec(l);
    if (h) {
      out.push({ kind: h[1] === "CSR" ? "csr" : "certificate", subject: h[2], issuer: "", serial: "", notBefore: "", notAfter: "", daysLeft: null, keyType: "", sigAlg: "", san: "", isCA: false, sha1: "", sha256: "", warnings: [], usage: "", selfSigned: false });
      continue;
    }
    const c = out[out.length - 1];
    if (!c) continue;
    if (l.startsWith("  ! ")) { c.warnings.push(l.slice(4)); continue; }
    // El núcleo imprime «  %-16s %s»: la clave ocupa 16 columnas.
    const k = l.slice(2, 18).trim(), v = l.slice(19);
    if (!l.startsWith("  ") || !k) continue;
    if (k === "Emisor") c.issuer = v;
    else if (k === "Serie") c.serial = v;
    else if (k === "Validez") {
      const m = /^(\S+) → (\S+) \((-?\d+) días\)$/.exec(v);
      if (m) { c.notBefore = m[1]; c.notAfter = m[2]; c.daysLeft = Number(m[3]); }
    } else if (k === "Llave") c.keyType = v;
    else if (k === "Firma") c.sigAlg = v;
    else if (k === "SAN") c.san = v;
    else if (k === "CA") c.isCA = true;
    else if (k === "SHA-1") c.sha1 = v;
    else if (k === "SHA-256") c.sha256 = v;
  }
  return out.length ? out : null;
}

/** Vigencia: aviso a menos de 30 días, mal a menos de 7 y vencido por debajo de 0. */
export const daysState = (days: number): "ok" | "warn" | "bad" | "expired" => (days < 0 ? "expired" : days < 7 ? "bad" : days < 30 ? "warn" : "ok");

const findings = (f: SecFindingData[]): Finding[] => f.map((x) => ({ severity: x.severity, detail: x.message }));

export function radiusFromData(d: RadiusReportData): RadiusReport {
  return {
    server: d.server, method: d.method ?? "", findings: findings(d.findings),
    exchanges: d.exchanges.map((e) => ({ kind: e.kind, code: e.code ?? "", rttMs: e.rttMs, attempts: e.attempts, messageAuthenticator: e.messageAuthenticator ?? "", error: e.error?.text ?? "", attrs: e.attrs })),
  };
}

export function tacacsFromData(d: TacacsReportData): TacacsReport {
  const dir = (s: TacacsReportData["steps"][number], w: "sent" | "received") => s.avPairs.filter((a) => a.direction === w).map((a) => a.value);
  return {
    server: d.server, findings: findings(d.findings),
    steps: d.steps.map((s) => ({ kind: s.kind, status: s.status ?? "", rttMs: s.rttMs, error: s.error?.text ?? "", prompts: s.prompts, message: s.message ?? "", data: s.data ?? "", sent: dir(s, "sent"), received: dir(s, "received") })),
  };
}

export function pkiFromData(d: PkiReportData): CertInfo[] {
  return d.certificates.map((c: Certificate) => ({
    kind: c.kind, subject: c.subject, issuer: c.issuer ?? "", serial: c.serial ?? "", notBefore: c.notBefore?.slice(0, 10) ?? "", notAfter: c.notAfter?.slice(0, 10) ?? "", daysLeft: c.daysLeft ?? null,
    keyType: c.key.description, sigAlg: c.signature.algorithm, san: c.san.join(", "), isCA: c.isCa, sha1: c.sha1 ?? "", sha256: c.sha256 ?? "", warnings: c.warnings.map((w) => w.message),
    usage: [...c.keyUsage, ...c.extKeyUsage].join(", "), selfSigned: c.selfSigned, sigValid: c.signature.valid,
  }));
}
