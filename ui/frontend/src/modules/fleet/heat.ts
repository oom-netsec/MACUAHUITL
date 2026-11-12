// Matrices equipo × métrica para los mapas de calor de Flota. Solo agrupan lo que ya devuelve el núcleo.
import type { IfIssue, SummaryRow } from "./api";

export type Sev = IfIssue["severity"];
const RANK: Record<Sev, number> = { critica: 3, alta: 2, media: 1, baja: 0 };

// Por equipo y tipo de problema: cuántos puertos y la peor severidad. Filas: del equipo más grave al menos.
export function healthMatrix(issues: IfIssue[]) {
  const cells = new Map<string, { count: number; sev: Sev }>();
  const worst = new Map<string, number>();
  for (const i of issues) {
    worst.set(i.device, Math.max(worst.get(i.device) ?? -1, RANK[i.severity]));
    for (const p of i.problems) {
      const k = `${i.device}|${p.kind}`;
      const c = cells.get(k);
      cells.set(k, { count: (c?.count ?? 0) + 1, sev: c && RANK[c.sev] >= RANK[i.severity] ? c.sev : i.severity });
    }
  }
  const rows = [...worst.keys()].sort((a, b) => worst.get(b)! - worst.get(a)! || a.localeCompare(b));
  const cols = [...new Set(issues.flatMap((i) => i.problems.map((p) => p.kind)))].sort();
  return { rows, cols, cells };
}

// Por equipo y revisión: el valor de la alerta. Columnas: solo las revisiones con alertas, en el orden dado.
export function summaryMatrix(rows: SummaryRow[], order: readonly string[]) {
  const cells = new Map(rows.map((r) => [`${r.device}|${r.check}`, r.value]));
  const used = new Set(rows.map((r) => r.check));
  return {
    rows: [...new Set(rows.map((r) => r.device))].sort((a, b) => a.localeCompare(b)),
    cols: [...order.filter((c) => used.has(c)), ...[...used].filter((c) => !order.includes(c))],
    cells,
  };
}
