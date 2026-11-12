// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
import { Events } from "@wailsio/runtime";
// Los topes, el archivo y los descartes son los mismos que los del receptor syslog (fase 28a).
import type { SyslogDrops, SyslogOptions } from "../tools/api";
import type { ErrInfo } from "../../lib/coreError";

// Destinos de visibilidad: solo el ID de la credencial de la bóveda, nunca el secreto.
export interface SnmpTarget { host: string; port: number; version: string; credentialId: string; auth: string; priv: string }
export interface GnmiTarget { host: string; port: number; credentialId: string; caPath: string; serverName: string }
export type VisKind = "snmp" | "traps" | "flows" | "gnmi";
/** Los topes cuentan mensajes en traps y datagramas de exportación en flujos; el resto, igual que syslog. */
export type VisOptions = SyslogOptions;
export interface VisEvent {
  runId: string; listening?: string; json?: string; final?: boolean; done?: boolean; error?: string; errorInfo?: ErrInfo;
  outputPath?: string; // con save: la carpeta de salida (outputs/snmp-traps u outputs/flows)
  rotatedPath?: string; // traps y flows con save: archivo nuevo abierto
  drops?: SyslogDrops;  // traps y flows: acumulado de descartes, cuando cambia
}

export interface VisibilityAPI {
  snmpGet(t: SnmpTarget, oids: string[]): Promise<string>;
  snmpWalk(t: SnmpTarget, oid: string, bulk: boolean): Promise<string>;
  snmpPollStart(t: SnmpTarget, profiles: string[], every: number): Promise<string>;
  trapsStart(addr: string, allowAny: boolean, save: boolean, v3Cred: string, auth: string, priv: string, opts?: VisOptions): Promise<string>;
  flowsStart(addr: string, allowAny: boolean, save: boolean, top: number, opts?: VisOptions): Promise<string>;
  gnmiGet(t: GnmiTarget, paths: string[], encoding: string): Promise<string>;
  gnmiSubscribeStart(t: GnmiTarget, paths: string[], mode: string, every: number): Promise<string>;
  onVis(kind: VisKind, cb: (e: VisEvent) => void): () => void;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const visibilityWails = (call: Call): VisibilityAPI => ({
  snmpGet: (t, o) => call("SnmpGet", t, o),
  snmpWalk: (t, o, b) => call("SnmpWalk", t, o, b),
  snmpPollStart: (t, p, e) => call("SnmpPollStart", t, p, e),
  trapsStart: (a, any, save, c, au, pr, opts) => call("TrapsStart", a, any, save, c, au, pr, opts ?? {}),
  flowsStart: (a, any, save, top, opts) => call("FlowsStart", a, any, save, top, opts ?? {}),
  gnmiGet: (t, p, e) => call("GnmiGet", t, p, e),
  gnmiSubscribeStart: (t, p, m, e) => call("GnmiSubscribeStart", t, p, m, e),
  onVis: (kind, cb) => {
    const a = Events.On(kind + ":msg", (e) => cb(e.data as VisEvent));
    const b = Events.On(kind + ":done", (e) => cb({ ...(e.data as VisEvent), done: true }));
    return () => { a(); b(); };
  },
});
