// Opciones extendidas del ping (contrato provisional, #200): validación y armado del map `options` sin claves vacías.
import type { Key } from "../../lib/i18n/es";
import type { SweepPoint } from "./api";

export interface PingForm {
  continuous: boolean; count: string; interval: string; size: string; sourceSel: string; sourceIP: string; df: boolean;
  ttl: string; timeout: string; duration: string; family: "" | "4" | "6"; dscp: string; sweepStart: string; sweepEnd: string; sweepStep: string;
}
export const PING_FORM0: PingForm = { continuous: false, count: "4", interval: "", size: "", sourceSel: "", sourceIP: "", df: false, ttl: "", timeout: "", duration: "", family: "", dscp: "", sweepStart: "", sweepEnd: "", sweepStep: "" };
export type PingErrors = Partial<Record<keyof PingForm, Key>>;

const int = (s: string, lo: number, hi: number) => /^\d{1,6}$/.test(s) && +s >= lo && +s <= hi;
const dec = (s: string, lo: number, hi: number) => /^\d+(\.\d+)?$/.test(s) && +s >= lo && +s <= hi;
const ipLike = (s: string) => /^[0-9a-fA-F:.]+$/.test(s) && (s.includes(".") || s.includes(":"));

export function pingOptions(f: PingForm, win: boolean): { options: Record<string, string>; errors: PingErrors; active: number } {
  const o: Record<string, string> = {};
  const e: PingErrors = {};
  const v = (k: keyof PingForm) => (f[k] as string).trim();
  const sweep = [v("sweepStart"), v("sweepEnd"), v("sweepStep")];
  const sweeping = sweep.some(Boolean);
  if (f.continuous) o.continuous = "true";
  else if (sweeping) { if (int(v("count"), 1, 5)) o.count = v("count"); else e.count = "diag.ping.err.sweepCount"; }
  else o.count = f.count;
  const num = (k: keyof PingForm, key: string, ok: (s: string) => boolean, msg: Key, val = v(k)) => { if (val) { if (ok(val)) o[key] = val; else e[k] = msg; } };
  if (!win) num("interval", "interval", (s) => dec(s, 0.2, 60), "diag.ping.err.interval");
  num("size", "size", (s) => int(s, 0, 65500), "diag.ping.err.size");
  num("ttl", "ttl", (s) => int(s, 1, 255), "diag.ping.err.ttl");
  num("timeout", "timeout", (s) => int(s, 1, 60), "diag.ping.err.timeout");
  num("duration", "duration", (s) => int(s, 1, 3600), "diag.ping.err.duration");
  if (!win && v("dscp")) { if (int(v("dscp"), 0, 63)) o.tos = String(+v("dscp") << 2); else e.dscp = "diag.ping.err.dscp"; }
  if (v("sourceIP")) { if (ipLike(v("sourceIP"))) o.source = v("sourceIP"); else e.sourceIP = "diag.ping.err.source"; } else if (f.sourceSel && (!win || ipLike(f.sourceSel))) o.source = f.sourceSel;
  if (f.family) o.family = f.family;
  if (f.df && !(win && f.family !== "4") && !(f.family === "6")) o.df = "true";
  if (sweeping) {
    const [a, b, s] = sweep;
    if (sweep.some((x) => !x)) e.sweepStart = "diag.ping.err.sweepAll";
    else if (![a, b].every((x) => int(x, 0, 65500)) || !int(s, 1, 65500)) e[int(s, 1, 65500) ? "sweepStart" : "sweepStep"] = "diag.ping.err.sweepRange";
    else if (+b < +a) e.sweepEnd = "diag.ping.err.sweepOrder";
    else if (sweepPoints(f) > 100) e.sweepStep = "diag.ping.err.sweepMax";
    else Object.assign(o, { sweep_start: a, sweep_end: b, sweep_step: s });
    if (f.continuous) e.sweepStart = "diag.ping.err.sweepContinuous";
    if (v("size")) e.size = "diag.ping.err.sweepSize";
  }
  const active = [f.continuous, !win && v("interval"), v("size"), v("sourceIP") || f.sourceSel, f.df, v("ttl"), v("timeout"), v("duration"), f.family, !win && v("dscp"), sweeping].filter(Boolean).length;
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
