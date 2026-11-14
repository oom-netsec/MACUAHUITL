// Equipos con más tráfico, conversaciones y protocolos de una captura: del informe estructurado (fase 30b) o, sin él,
// del texto (pcapan.Report.Text), donde el conteo por protocolo se suma por las conversaciones listadas.
import type { PcapReportData } from "./api";
export interface PcapTalker { ip: string; packets: number; bytes: number }
export interface PcapConv { proto: string; a: string; b: string; packets: number; bytes: number }
export interface PcapProto { proto: string; packets: number; bytes: number }
export interface PcapSummary { talkers: PcapTalker[]; conversations: PcapConv[]; protocols: PcapProto[] }

// es: "N paquetes  N bytes"; en: "1 packet  1 byte" / "N packets  N bytes" (pcap.text.counts del núcleo).
const COUNTS = String.raw`(\d+) (?:paquetes|packets?)\s+(\d+) (?:bytes?)`;
const CONV = new RegExp(String.raw`^\s+(\S+)\s+(\S+) ↔ (\S+)\s+${COUNTS}\s*$`);
const TALKER = new RegExp(String.raw`^\s+(\S+)\s+${COUNTS}\s*$`);
// pcap.section.conversations / top_talkers, es y en.
const SEC_CONV = ["== Conversaciones", "== Top conversations"];
const SEC_TALK = ["== Equipos con más tráfico", "== Top talkers"];

export function parsePcap(text: string): PcapSummary | null {
  const talkers: PcapTalker[] = [];
  const conversations: PcapConv[] = [];
  let sec: "" | "conv" | "talk" = "";
  for (const line of text.split("\n")) {
    if (line.startsWith("== ")) {
      sec = SEC_CONV.some((s) => line.startsWith(s)) ? "conv" : SEC_TALK.some((s) => line.startsWith(s)) ? "talk" : "";
      continue;
    }
    const c = sec === "conv" ? CONV.exec(line) : null;
    if (c) conversations.push({ proto: c[1], a: c[2], b: c[3], packets: +c[4], bytes: +c[5] });
    const k = sec === "talk" ? TALKER.exec(line) : null;
    if (k) talkers.push({ ip: k[1], packets: +k[2], bytes: +k[3] });
  }
  if (!talkers.length && !conversations.length) return null;
  const by = new Map<string, PcapProto>();
  for (const c of conversations) {
    const p = by.get(c.proto) ?? { proto: c.proto, packets: 0, bytes: 0 };
    p.packets += c.packets; p.bytes += c.bytes;
    by.set(c.proto, p);
  }
  return { talkers, conversations, protocols: [...by.values()].sort((x, y) => y.bytes - x.bytes) };
}

export function pcapFromReport(d: PcapReportData): PcapSummary | null {
  return d.topTalkers.length || d.conversations.length ? { talkers: d.topTalkers, conversations: d.conversations, protocols: d.protocols } : null;
}
