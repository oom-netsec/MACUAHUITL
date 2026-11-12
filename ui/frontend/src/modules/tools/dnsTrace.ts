// Lee el JSON de dnsq.TraceResult (el texto que devuelve el modo "traza"). Sin JSON de traza devuelve null.
export interface TraceStep { zone: string; depth: number; server: string; ip: string; rttMs: number; rcode: string; aa: boolean; referral: string; answers: string[]; error: string }
export interface Trace { name: string; type: string; rcode: string; steps: TraceStep[]; final: string[]; cnames: string[]; warnings: string[] }

const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
const str = (v: unknown) => (typeof v === "string" ? v : "");

export function parseTrace(text: string): Trace | null {
  let j: Record<string, unknown>;
  try { j = JSON.parse(text); } catch { return null; }
  if (!j || typeof j !== "object" || !Array.isArray(j.Steps)) return null;
  const steps = (j.Steps as Record<string, unknown>[]).map((s) => {
    const zone = str(s.Zone);
    return {
      zone, depth: zone.split(".").filter(Boolean).length, // "." = 0, "com." = 1, "example.com." = 2
      server: str(s.Server), ip: str(s.ServerIP), rttMs: typeof s.RTT === "number" ? Math.round(s.RTT / 1e5) / 10 : 0, // Duration de Go en ns
      rcode: str(s.RCode), aa: s.AA === true, referral: str(s.ReferralZone), answers: strs(s.Answer), error: str(s.Error),
    };
  });
  return { name: str(j.Name), type: str(j.Type), rcode: str(j.RCode), steps, final: strs(j.Final), cnames: strs(j.CNAMEs), warnings: strs(j.Warnings) };
}
