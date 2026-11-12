// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
import { Events } from "@wailsio/runtime";
import type { ErrInfo } from "../../lib/coreError";

export interface DnsRequest { mode: string; name: string; type: string; servers: string[]; deep: boolean; dnssec: boolean }
/** Topes y archivo de la escucha. Cero o vacío = default del núcleo; fuera de rango, el inicio falla con el motivo. */
export interface SyslogOptions {
  ratePerSource?: number; burstPerSource?: number; // msg/s por IP de origen (default 100, 1–10000); ráfaga 2x
  rateGlobal?: number; burstGlobal?: number;       // msg/s en total (default 1000, 1–100000); ráfaga 2x
  queueSize?: number;                              // cola antes de escribir (default 4096, 64–65536)
  rotateMb?: number;                               // con save: rotar a N MB (default 50, 1–1024)
  rotateMinutes?: number;                          // con save: rotar cada N min (0 = no, 1–10080)
  nameTemplate?: string;                           // {fecha} {hora} {origen}; default syslog_{fecha}_{hora}
  maxFiles?: number;                               // archivos que se conservan (default 20, 1–1000)
  format?: "texto" | "crudo" | "jsonl";            // default texto
}
export interface SyslogSourceDrops { source: string; count: number } // IP, o "otros"
/** Acumulado desde que empezó la escucha; llega a lo más una vez por segundo y solo si cambió. */
export interface SyslogDrops { total: number; porOrigen: number; global: number; colaLlena: number; sinceMs: number; top: SyslogSourceDrops[] }
export interface SyslogEvent {
  runId: string; listening?: string; outputPath?: string; json?: string; done?: boolean; error?: string; errorInfo?: ErrInfo;
  rotatedPath?: string; // archivo nuevo abierto (con save); outputPath es la carpeta
  drops?: SyslogDrops;
}

// Fase 30b: el informe de la captura estructurado. Duraciones en ms, fechas RFC 3339 UTC. Los encabezados de sección
// llegan como clave (pcap.section.*) con su título ya en el idioma de la interfaz; protocols suma las conversaciones listadas.
export interface PcapSection { key: string; args?: Record<string, string>; title: string }
export interface PcapFlowData { client: string; server: string; count: number }
export interface PcapDnsQueryData { client: string; server: string; name: string; type: string; rcode?: string; latencyMs: number }
export interface PcapIcmpEventData { from: string; target: string; code: number }
export interface PcapReportData {
  text: string;
  summary: { file: string; packets: number; bytes: number; durationMs: number; start: string };
  conversations: { proto: string; a: string; b: string; packets: number; bytes: number }[];
  topTalkers: { ip: string; packets: number; bytes: number }[];
  protocols: { proto: string; packets: number; bytes: number }[];
  neighbors: { protocol: string; deviceId: string; port: string; platform: string; mgmtIp: string; nativeVlan: number }[];
  tcp: { handshakes: number; rttMinMs: number; rttAvgMs: number; rttMaxMs: number; retransmissions: number; zeroWindow: number; failedHandshakesTotal: number; failedHandshakes: PcapFlowData[]; resets: PcapFlowData[] };
  dns: { queries: number; responses: number; errors: PcapDnsQueryData[]; slow: PcapDnsQueryData[]; unanswered: PcapDnsQueryData[] };
  tls: { client: string; server: string; sni: string }[];
  icmp: { unreachable: PcapIcmpEventData[]; ttlExceeded: PcapIcmpEventData[] };
  arpConflicts: { ip: string; macs: string[] }[];
  fragments: number;
  warnings: { key: string; args?: Record<string, string>; text: string }[];
  sections: PcapSection[];
}

export interface ToolsAPI {
  /** Como toolsPcap, con el informe estructurado. */
  toolsPcapReport?(path: string, top: number): Promise<PcapReportData>;
  toolsPcap(path: string, top: number): Promise<string>;
  toolsDns(r: DnsRequest): Promise<string>;
  toolsTls(host: string, port: number, sni: string): Promise<string>;
  syslogStart(addr: string, proto: string, allowAny: boolean, save: boolean, opts?: SyslogOptions): Promise<string>;
  onSyslog(cb: (e: SyslogEvent) => void): () => void;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const toolsWails = (call: Call): ToolsAPI => ({
  toolsPcap: (p, t) => call("ToolsPcap", p, t),
  toolsPcapReport: (p, t) => call("ToolsPcapReport", p, t),
  toolsDns: (r) => call("ToolsDns", r),
  toolsTls: (h, p, s) => call("ToolsTls", h, p, s),
  syslogStart: (a, p, any, save, opts) => call("SyslogStart", a, p, any, save, opts ?? {}),
  onSyslog: (cb) => {
    const a = Events.On("syslog:msg", (e) => cb(e.data as SyslogEvent));
    const b = Events.On("syslog:done", (e) => cb({ ...(e.data as SyslogEvent), done: true }));
    return () => { a(); b(); };
  },
});
