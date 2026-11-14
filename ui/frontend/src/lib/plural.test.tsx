import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { I18nProvider, useT } from "./i18n";
import { plural } from "./plural";

// Las cadenas con «(s)» pasaron a plural real: base en plural y variante ".one" para n = 1.
type Vars = Record<string, string | number>;
function Probe({ k, vars, unit }: { k?: string; vars?: Vars; unit?: [string, number] }) {
  const t = useT();
  return <p>{unit ? plural(t, unit[0] as Parameters<typeof t>[0], unit[1]) : t(k as Parameters<typeof t>[0], vars)}</p>;
}
const show = (props: Parameters<typeof Probe>[0], lang: "es" | "en") => {
  localStorage.setItem("macuahuitl.lang", lang);
  render(<I18nProvider><Probe {...props} /></I18nProvider>);
};

const cases: [string, Vars, string, string][] = [
  ["backup.saved", { n: 1 }, "1 backup saved", "1 respaldo guardado"],
  ["backup.saved", { n: 3 }, "3 backups saved", "3 respaldos guardados"],
  ["backup.savedWarn", { n: 1, warnings: "x" }, "1 backup saved. Warnings: x", "1 respaldo guardado. Avisos: x"],
  ["backup.caption", { n: 2 }, "2 backups; select two of the same device and type to compare them", "2 respaldos; marca dos del mismo equipo y tipo para compararlos"],
  ["backup.diff.summary", { n: 1, added: 1, removed: 0 }, "1 change: 1 added, 0 removed.", "1 cambio: 1 agregadas, 0 quitadas."],
  ["fleet.find.caption", { n: 1, q: "a", mode: "m", d: "1 device" }, "1 match for “a” (m) in 1 device", "1 coincidencia de «a» (m) en 1 device"],
  ["fleet.health.caption", { n: 1 }, "1 interface with problems, most severe first (counters accumulated since the last clear counters)", "1 interfaz con problema, de la más grave a la menos (contadores acumulados desde el último clear counters)"],
  ["fleet.summary.meta", { n: 1, list: "l" }, "1 device. With data: l", "1 equipo. Con dato: l"],
  ["fleet.summary.meta", { n: 4, list: "l" }, "4 devices. With data: l", "4 equipos. Con dato: l"],
  ["fleet.inv.caption", { n: 5, d: "2 devices" }, "5 items in 2 devices", "5 elementos en 2 devices"],
  ["fleet.find.count", { n: 1 }, "1 result", "1 resultado"],
  ["fleet.health.count", { n: 1 }, "1 interface", "1 interfaz"],
  ["fleet.summary.count", { n: 7 }, "7 alerts", "7 alertas"],
  ["forensic.leak.summary", { n: 1 }, "1 process analyzed.", "1 proceso analizado."],
];
test.each(cases)("%s %j en inglés", (k, vars, en) => {
  show({ k, vars }, "en");
  expect(screen.getByText(en)).toBeInTheDocument();
});
test.each(cases)("%s %j en español", (k, vars, _en, es) => {
  show({ k, vars }, "es");
  expect(screen.getByText(es)).toBeInTheDocument();
});

test("plural() usa la variante singular con 1 y la plural con otro n, en ambos idiomas", () => {
  show({ unit: ["unit.device", 1] }, "en");
  expect(screen.getByText("1 device")).toBeInTheDocument();
});
test("plural() en español", () => {
  show({ unit: ["unit.row", 2] }, "es");
  expect(screen.getByText("2 filas")).toBeInTheDocument();
});
test("plural() con 0 va en plural", () => {
  show({ unit: ["unit.interface", 0] }, "es");
  expect(screen.getByText("0 interfaces")).toBeInTheDocument();
});
