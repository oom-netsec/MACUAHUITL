// Reporte de un cambio: tipos del JSON del núcleo y su exportación a Markdown.
import type { Key } from "../../lib/i18n/es";

export interface Finding { facet: string; level: string; detail: string }
export interface DeviceReport { address: string; hostname: string; verdict: string; findings: Finding[]; config_diff: string[] }

type T = (k: Key, v?: Record<string, string | number>) => string;
export const verdictKey: Record<string, Key> = { ok: "change.verdict.ok", review: "change.verdict.review", regression: "change.verdict.regression" };
export const levelKey: Record<string, Key> = { info: "change.level.info", review: "change.level.review", regression: "change.level.regression" };

// El núcleo manda cada línea como «+ sección > línea» o «- sección > línea».
export const diffCounts = (lines: string[]) => ({ added: lines.filter((l) => l.startsWith("+")).length, removed: lines.filter((l) => l.startsWith("-")).length });
export const verdictCounts = (devs: DeviceReport[]) => ({ bad: devs.filter((d) => d.verdict === "regression").length, warn: devs.filter((d) => d.verdict === "review").length, ok: devs.filter((d) => d.verdict === "ok").length });

export function reportMarkdown(name: string, devs: DeviceReport[], note: string, t: T): string {
  const out = [`# ${name}`, "", t("change.sum.counts", verdictCounts(devs)), ""];
  for (const d of devs) {
    out.push(`## ${d.hostname || d.address} (${d.address}) · ${verdictKey[d.verdict] ? t(verdictKey[d.verdict]) : d.verdict}`, "");
    if (d.findings.length) out.push(`### ${t("change.md.findings")}`, "", ...d.findings.map((f) => `- **${levelKey[f.level] ? t(levelKey[f.level]) : f.level}** ${f.facet}: ${f.detail}`), "");
    if (d.config_diff.length) out.push(`### ${t("change.configDiff")}`, "", ...d.config_diff.map((l) => `- \`${l}\``), "");
    if (!d.findings.length && !d.config_diff.length) out.push(t("change.noFindings"), "");
  }
  if (note) out.push(`> ${note}`, "");
  return out.join("\n");
}
