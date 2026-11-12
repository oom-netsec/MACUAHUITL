import { healthMatrix, summaryMatrix } from "./heat";
import type { IfIssue, SummaryRow } from "./api";

const at = "2026-11-06T18:00:00Z";
const issue = (device: string, port: string, severity: IfIssue["severity"], kinds: string[]): IfIssue => ({ device, port, severity, source: "x", at, problems: kinds.map((kind) => ({ kind, evidence: "" })) });

test("salud: equipos por problema, con cuántos puertos y la peor severidad; el equipo más grave primero", () => {
  const m = healthMatrix([
    issue("ACC1", "Gi1/0/1", "media", ["crc"]),
    issue("ACC1", "Gi1/0/2", "alta", ["crc", "flap"]),
    issue("DIST1", "Te1/1/1", "critica", ["err-disabled"]),
  ]);
  expect(m.rows).toEqual(["DIST1", "ACC1"]);
  expect(m.cols).toEqual(["crc", "err-disabled", "flap"]);
  expect(m.cells.get("ACC1|crc")).toEqual({ count: 2, sev: "alta" });
  expect(m.cells.get("ACC1|flap")).toEqual({ count: 1, sev: "alta" });
  expect(m.cells.get("DIST1|crc")).toBeUndefined();
});

test("tablero: una celda por equipo y alerta con su valor; las columnas siguen el orden de las alertas", () => {
  const rows: SummaryRow[] = [
    { device: "SW2", check: "ntp", value: "no sincronizado", source: "x", at },
    { device: "SW1", check: "cpu", value: "92 %", source: "x", at },
    { device: "SW2", check: "cpu", value: "88 %", source: "x", at },
  ];
  const m = summaryMatrix(rows, ["cpu", "ntp", "reboot"]);
  expect(m.rows).toEqual(["SW1", "SW2"]);
  expect(m.cols).toEqual(["cpu", "ntp"]);
  expect(m.cells.get("SW2|ntp")).toBe("no sincronizado");
});

test("sin datos las matrices salen vacías", () => {
  expect(healthMatrix([]).rows).toEqual([]);
  expect(summaryMatrix([], ["cpu"]).cols).toEqual([]);
});
