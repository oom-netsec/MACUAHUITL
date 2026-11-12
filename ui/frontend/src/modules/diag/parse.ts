// Lectura de las líneas en vivo de cada herramienta (sin API nueva). Funciones puras: reciben las líneas y devuelven datos.
// Formatos de iputils-ping, traceroute, iperf3 y nmap en Linux; lo que no reconocen lo ignoran.

export interface PingReply { seq: number; rtt: number; ttl?: number }
export interface PingResult { replies: PingReply[]; lost: number[] }

export function parsePing(lines: string[]): PingResult {
  const replies = new Map<number, PingReply>();
  const explicit = new Set<number>();
  let sent = 0;
  for (const l of lines) {
    const t = /^(\d+) packets transmitted/.exec(l);
    if (t) { sent = +t[1]; continue; }
    const r = /icmp_seq[= ](\d+).*?\bttl=(\d+).*?\btime[=<]([\d.]+) ?ms/.exec(l);
    if (r) { replies.set(+r[1], { seq: +r[1], rtt: +r[3], ttl: +r[2] }); continue; }
    // iputils -O ("no answer yet"), macOS ("Request timeout") y avisos de un router ("From x icmp_seq=7 Destination Host Unreachable").
    const e = /no answer yet for icmp_seq=(\d+)|Request timeout for icmp_seq (\d+)|^From .*icmp_seq=(\d+)/.exec(l);
    if (e) explicit.add(+(e[1] ?? e[2] ?? e[3]));
  }
  const seqs = [...replies.keys()];
  const max = Math.max(0, ...seqs);
  const lost = new Set(explicit);
  const last = sent || max - 1; // sin el resumen no se sabe si faltan paquetes después de la última respuesta
  for (let s = 1; s <= last; s++) lost.add(s); // hueco en la secuencia = respuesta que no llegó
  return { replies: seqs.sort((a, b) => a - b).map((s) => replies.get(s)!), lost: [...lost].filter((s) => !replies.has(s)).sort((a, b) => a - b) };
}

export interface PingStats { sent: number; received: number; lossPct: number; min: number; avg: number; max: number; jitter: number }

// Jitter = promedio de la diferencia absoluta entre RTT consecutivos.
export function pingStats(r: PingResult): PingStats | null {
  const sent = r.replies.length + r.lost.length;
  if (!sent) return null;
  const v = r.replies.map((x) => x.rtt);
  const lossPct = Math.round((r.lost.length / sent) * 1000) / 10;
  if (!v.length) return { sent, received: 0, lossPct, min: 0, avg: 0, max: 0, jitter: 0 };
  const diffs = v.slice(1).map((x, i) => Math.abs(x - v[i]));
  return { sent, received: v.length, lossPct, min: Math.min(...v), avg: v.reduce((a, b) => a + b, 0) / v.length, max: Math.max(...v), jitter: diffs.length ? diffs.reduce((a, b) => a + b, 0) / diffs.length : 0 };
}

export interface Hop { hop: number; host: string; address: string; rtts: number[]; stars: number }

// shortcut: las líneas de continuación (otro camino del mismo salto en una línea nueva) se ignoran; agregarlas si hace falta.
export function parseTraceroute(lines: string[]): Hop[] {
  const out: Hop[] = [];
  for (const l of lines) {
    const m = /^\s*(\d+)\s+(.*)$/.exec(l);
    if (!m) continue;
    const h: Hop = { hop: +m[1], host: "", address: "", rtts: [], stars: 0 };
    for (const t of m[2].matchAll(/(\*)|(\d+(?:\.\d+)?)\s*ms\b|([^\s()]+)\s+\(([^)]+)\)|(!\S+)|(\S+)/g)) {
      if (t[1]) h.stars++;
      else if (t[2]) h.rtts.push(+t[2]);
      else if (t[3] && !h.host) { h.host = t[3]; h.address = t[4]; }
      else if (t[6] && !h.host) { h.host = t[6]; h.address = t[6]; }
    }
    out.push(h);
  }
  return out;
}

export interface IperfPoint { end: number; mbps: number; retr?: number }
export interface IperfResult { points: IperfPoint[]; sender?: number; receiver?: number }

const UNIT: Record<string, number> = { "": 1e-6, K: 1e-3, M: 1, G: 1e3 };
const mbps = (n: string, u: string) => Math.round(+n * UNIT[u] * 1000) / 1000;

export function parseIperf(lines: string[]): IperfResult {
  const rows: (IperfPoint & { sum: boolean })[] = [];
  const res: IperfResult = { points: [] };
  for (const l of lines) {
    const m = /^\[\s*(\d+|SUM)\]\s+([\d.]+)-([\d.]+)\s+sec\s+[\d.]+\s+\w+\s+([\d.]+)\s+([KMG]?)bits\/sec(?:\s+(\d+)(?=\s|$))?/.exec(l);
    if (!m) continue;
    const role = /\b(sender|receiver)\s*$/.exec(l)?.[1] as "sender" | "receiver" | undefined;
    if (role) { if (m[1] === "SUM" || res[role] === undefined) res[role] = mbps(m[4], m[5]); continue; }
    rows.push({ end: +m[3], mbps: mbps(m[4], m[5]), retr: m[6] === undefined ? undefined : +m[6], sum: m[1] === "SUM" });
  }
  // Con flujos paralelos, [SUM] ya trae el total de cada intervalo.
  const use = rows.some((r) => r.sum) ? rows.filter((r) => r.sum) : rows;
  res.points = use.map(({ end, mbps, retr }) => ({ end, mbps, retr }));
  return res;
}

export interface NmapPort { port: number; proto: string; state: string; service: string }
export interface NmapHost { host: string; ports: NmapPort[]; hidden?: { n: number; state: string } }

export function parseNmap(lines: string[]): NmapHost[] {
  const hosts: NmapHost[] = [];
  for (const l of lines) {
    const h = /^Nmap scan report for (.+)$/.exec(l);
    if (h) { hosts.push({ host: h[1].trim(), ports: [] }); continue; }
    const cur = hosts[hosts.length - 1];
    if (!cur) continue;
    const p = /^(\d+)\/(tcp|udp|sctp)\s+(\S+)\s+(\S+)/.exec(l);
    if (p) { cur.ports.push({ port: +p[1], proto: p[2], state: p[3], service: p[4] }); continue; }
    const n = /^Not shown: (\d+) (\S+) (?:tcp |udp )?ports/.exec(l);
    if (n) cur.hidden = { n: +n[1], state: n[2] };
  }
  return hosts;
}

// Paquetes capturados: dumpcap ("Packets: 12", "Packets captured: 12") y tcpdump ("12 packets captured").
export function captureCount(lines: string[]): number | null {
  let n: number | null = null;
  for (const l of lines) {
    const m = /^Packets(?: captured)?:\s*(\d+)/i.exec(l) ?? /^(\d+) packets captured/.exec(l);
    if (m) n = +m[1];
  }
  return n;
}
