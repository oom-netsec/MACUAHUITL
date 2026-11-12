// Mensajes de syslog en vivo: normalización, grupos de severidad y conteo por minuto.
export interface WireMsg { Time?: string; From?: string; Severity?: number; Mnemonic?: string; Text?: string; Raw?: string }
export interface SysMsg { id: number; at: number; from: string; sev: number; mnemonic: string; text: string }
export type SevGroup = "all" | "err" | "warn" | "notice" | "info";

// Sin hora válida se usa la de llegada; sin PRI la severidad es -1.
export const toMsg = (w: WireMsg, id: number, now: number): SysMsg => {
  const at = Date.parse(w.Time ?? "");
  return { id, at: Number.isNaN(at) ? now : at, from: w.From ?? "", sev: typeof w.Severity === "number" ? w.Severity : -1, mnemonic: w.Mnemonic ?? "", text: w.Text || w.Raw || "" };
};

export const inGroup = (g: SevGroup, sev: number) =>
  g === "all" || (g === "err" ? sev >= 0 && sev <= 3 : g === "warn" ? sev === 4 : g === "notice" ? sev === 5 : sev >= 6);

// Mensajes por minuto en los últimos n minutos que terminan en el del último mensaje.
export function perMinute(msgs: SysMsg[], n = 30): number[] {
  if (!msgs.length) return [];
  const bucket = (at: number) => Math.floor(at / 60_000);
  const end = Math.max(...msgs.map((m) => bucket(m.at)));
  const out = new Array<number>(n).fill(0);
  for (const m of msgs) {
    const i = n - 1 - (end - bucket(m.at));
    if (i >= 0 && i < n) out[i]++;
  }
  return out;
}
