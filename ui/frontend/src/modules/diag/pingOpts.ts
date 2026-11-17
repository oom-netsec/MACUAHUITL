// Opciones extendidas del ping (#200, contrato en #218): validación y armado del map `options` sin claves vacías.
import type { Key } from "../../lib/i18n/es";
import type { SweepPoint } from "./api";

export interface PingForm {
  continuous: boolean; count: string; interval: string; size: string; sourceSel: string; sourceIP: string; df: boolean;
  ttl: string; timeout: string; duration: string; family: "" | "4" | "6"; dscp: string; countTouched: boolean; sweepStart: string; sweepEnd: string; sweepStep: string;
}
export const PING_FORM0: PingForm = { continuous: false, count: "4", interval: "", size: "", sourceSel: "", sourceIP: "", df: false, ttl: "", timeout: "", duration: "", family: "", dscp: "", countTouched: false, sweepStart: "", sweepEnd: "", sweepStep: "" };
export type PingErrors = Partial<Record<keyof PingForm, Key>>;

const int = (s: string, lo: number, hi: number) => /^\d{1,6}$/.test(s) && +s >= lo && +s <= hi;
const dec = (s: string, lo: number, hi: number) => /^\d+(\.\d+)?$/.test(s) && +s >= lo && +s <= hi;
/** 4 o 6 si es una IP literal válida (IPv4 por octetos, IPv6 por el analizador de URL), 0 si no. */
export function ipFamily(s: string): 0 | 4 | 6 {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return s.split(".").every((n) => +n <= 255) ? 4 : 0;
  if (!s.includes(":") || !/^[0-9a-fA-F:.]+$/.test(s)) return 0;
  try { new URL(`http://[${s}]`); return 6; } catch { return 0; }
}

/** Aplica un cambio; mientras el usuario no toque «Paquetes», vale 1 con barrido y 4 sin él. */
export function patchForm(f: PingForm, p: Partial<PingForm>): PingForm {
  const n = { ...f, ...p, countTouched: f.countTouched || "count" in p };
  if (!n.countTouched) n.count = [n.sweepStart, n.sweepEnd, n.sweepStep].some((x) => x.trim()) ? "1" : "4";
  return n;
}

export function pingOptions(f: PingForm, win: boolean): { options: Record<string, string>; errors: PingErrors; active: number } {
  const o: Record<string, string> = {};
  const e: PingErrors = {};
  const v = (k: keyof PingForm) => (f[k] as string).trim();
  const sweep = [v("sweepStart"), v("sweepEnd"), v("sweepStep")];
  const sweeping = sweep.some(Boolean);
  if (f.continuous) o.continuous = "true";
  else if (int(v("count"), 1, sweeping ? 5 : 100)) o.count = v("count");
  else e.count = sweeping ? "diag.ping.err.sweepCount" : "diag.ping.err.count";
  const num = (k: keyof PingForm, key: string, ok: (s: string) => boolean, msg: Key, val = v(k)) => { if (val) { if (ok(val)) o[key] = val; else e[k] = msg; } };
  if (!win) num("interval", "interval", (s) => dec(s, 0.2, 60), "diag.ping.err.interval");
  num("size", "size", (s) => int(s, 0, 65500), "diag.ping.err.size");
  num("ttl", "ttl", (s) => int(s, 1, 255), "diag.ping.err.ttl");
  num("timeout", "timeout", (s) => int(s, 1, 60), "diag.ping.err.timeout");
  num("duration", "duration", (s) => int(s, 1, 3600), "diag.ping.err.duration");
  if (!win && v("dscp")) { if (int(v("dscp"), 0, 63)) o.tos = String(+v("dscp") << 2); else e.dscp = "diag.ping.err.dscp"; }
  const src = v("sourceIP") || f.sourceSel;
  const srcKey = v("sourceIP") ? "sourceIP" : "sourceSel";
  if (src) {
    const fam = ipFamily(src);
    if (v("sourceIP") && !fam) e.sourceIP = "diag.ping.err.source";
    else if (!win && !v("sourceIP") || fam) { if (fam && f.family && +f.family !== fam) e[srcKey] = "diag.ping.err.sourceFamily"; else o.source = src; } // un nombre de interfaz no tiene familia
  }
  if (f.family) o.family = f.family;
  if (f.df && !(win && f.family === "6")) o.df = "true"; // Windows con v6 no admite DF; Auto lo decide el núcleo
  if (sweeping) {
    const [a, b, st] = sweep;
    const keys = ["sweepStart", "sweepEnd", "sweepStep"] as const;
    const missing = sweep.findIndex((x) => !x);
    if (missing >= 0) e[keys[missing]] = "diag.ping.err.sweepAll";
    else {
      if (!int(a, 0, 65500)) e.sweepStart = "diag.ping.err.sweepRange";
      if (!int(b, 0, 65500)) e.sweepEnd = "diag.ping.err.sweepRange";
      if (!int(st, 1, 65500)) e.sweepStep = "diag.ping.err.sweepRange";
      if (!Object.keys(e).some((k) => k.startsWith("sweep"))) {
        if (+b < +a) e.sweepEnd = "diag.ping.err.sweepOrder";
        else if (sweepPoints(f) > 100) e.sweepStep = "diag.ping.err.sweepMax";
        else Object.assign(o, { sweep_start: a, sweep_end: b, sweep_step: st });
      }
    }
    if (f.continuous) e.sweepStart = "diag.ping.err.sweepContinuous";
    if (v("size")) e.size = "diag.ping.err.sweepSize";
  }
  const active = Object.keys(o).filter((k) => k !== "count" && !k.startsWith("sweep_")).length + (o.sweep_start ? 1 : 0); // lo que realmente se manda
  return { options: o, errors: e, active };
}

/** Puntos del barrido con los valores escritos (0 si no son números). */
export function sweepPoints(f: Pick<PingForm, "sweepStart" | "sweepEnd" | "sweepStep">): number {
  const [a, b, s] = [f.sweepStart, f.sweepEnd, f.sweepStep].map((x) => (/^\d+$/.test(x.trim()) ? +x : NaN));
  return s >= 1 && b >= a ? Math.floor((b - a) / s) + 1 : 0;
}

/** Estimación (no medición) de la MTU: mayor tamaño ok antes del primer «frag» + cabeceras IP e ICMP; sin «frag» no se estima. */
export function mtuEstimate(points: SweepPoint[], v6: boolean): { size: number; mtu: number } | null {
  const sorted = [...points].sort((a, b) => a.size - b.size);
  const frag = sorted.findIndex((p) => p.result === "frag");
  const ok = (frag < 0 ? [] : sorted.slice(0, frag)).filter((p) => p.result === "ok");
  if (!ok.length) return null;
  const size = ok[ok.length - 1].size;
  return { size, mtu: size + (v6 ? 48 : 28) };
}
