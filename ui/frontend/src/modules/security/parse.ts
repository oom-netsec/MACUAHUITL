// El núcleo entrega estas pruebas como texto (Report.Text de radiustest y tacacstest, pki.Text). Aquí se lee ese
// texto para dibujar tarjetas; si no tiene la forma esperada, devuelven null y la vista muestra la salida tal cual.

export interface Finding { severity: string; detail: string }
export interface Attr { name: string; value: string }

export interface RadiusExchange { kind: string; code: string; rttMs: number; attempts: number; messageAuthenticator: string; error: string; attrs: Attr[] }
export interface RadiusReport { server: string; method: string; exchanges: RadiusExchange[]; findings: Finding[] }

export interface TacacsStep { kind: string; status: string; rttMs: number; error: string; prompts: string[]; message: string; data: string; sent: string[]; received: string[] }
export interface TacacsReport { server: string; steps: TacacsStep[]; findings: Finding[] }

export interface CertInfo {
  kind: string; subject: string; issuer: string; serial: string; notBefore: string; notAfter: string; daysLeft: number | null;
  keyType: string; sigAlg: string; san: string; isCA: boolean; sha1: string; sha256: string; warnings: string[];
}

const FINDING = /^ {2}\[(.+?)\] (.*)$/;

function split(text: string) {
  const lines = text.split("\n");
  const at = lines.indexOf("Hallazgos:");
  const body = at < 0 ? lines : lines.slice(0, at);
  const findings = (at < 0 ? [] : lines.slice(at + 1)).flatMap((l) => { const m = FINDING.exec(l); return m ? [{ severity: m[1], detail: m[2] }] : []; });
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
      exchanges.push({ kind: ex[1], code: r?.[1] ?? "", rttMs: r ? Number(r[2]) : 0, attempts: r ? Number(r[3]) : 0, messageAuthenticator: r?.[4] ?? "", error: "", attrs: [] });
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
      out.push({ kind: h[1], subject: h[2], issuer: "", serial: "", notBefore: "", notAfter: "", daysLeft: null, keyType: "", sigAlg: "", san: "", isCA: false, sha1: "", sha256: "", warnings: [] });
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
