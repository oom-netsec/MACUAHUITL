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
  ["backup.savedWarn", { n: 2, warnings: "x" }, "2 backups saved. Warnings: x", "2 respaldos guardados. Avisos: x"],
  ["drift.changes", { n: 1, added: 1, removed: 0 }, "1 change: 1 added, 0 removed.", "1 cambio (líneas agregadas: 1, quitadas: 0)."],
  ["drift.changes", { n: 3, added: 2, removed: 1 }, "3 changes: 2 added, 1 removed.", "3 cambios (líneas agregadas: 2, quitadas: 1)."],
  ["fleet.find.count", { n: 2 }, "2 results", "2 resultados"],
  ["fleet.health.count", { n: 3 }, "3 interfaces", "3 interfaces"],
  ["fleet.summary.count", { n: 1 }, "1 alert", "1 alerta"],
  // Plantillas con varios números: reciben las unidades ya formadas (plural()); un placeholder renombrado quedaría crudo.
  ["forensic.flap.summary", { ifaces: "1 if", tr: "2 tr", src: "s" }, "1 if with transitions, 2 tr. Source: s.", "1 if con transiciones, 2 tr. Fuente: s."],
  ["forensic.pat.summary", { msgs: "1 m", p: "2 p", src: "s" }, "1 m in 2 p. Source: s.", "1 m en 2 p. Fuente: s."],
  ["forensic.debug.summary", { lines: "3 l", hidden: 1, blank: 0, groups: "1 g" }, "3 l: 1 hidden as noise, 0 blank, 1 g.", "3 l (ocultas por ruido: 1, en blanco: 0), 1 g."],
  ["adhoc.caption", { rows: "2 r", devices: "1 d" }, "2 r in 1 d", "2 r en 1 d"],
  // Cadenas de un solo número que antes salían «1 hosts», «1 scripts»…
  ["pcap.packets", { n: 1 }, "1 packet", "1 paquete"],
  ["hosts.data.export.done", { n: 1, path: "/p" }, "1 host exported to /p.", "Se exportó 1 host a /p."],
  ["hosts.data.export.done", { n: 2, path: "/p" }, "2 hosts exported to /p.", "Se exportaron 2 hosts a /p."],
  ["vault.backup.exported", { n: 1, path: "/p" }, "Backup of 1 credential saved to /p.", "Respaldo de 1 credencial guardado en /p."],
  ["hosts.data.import.applyNote", { n: 1 }, "Only valid rows are applied; the invalid row is skipped.", "Solo se aplican las filas válidas; la fila inválida se omite."],
  ["hosts.data.import.applyNote", { n: 2 }, "Only valid rows are applied; the 2 invalid ones are skipped.", "Solo se aplican las filas válidas; las 2 inválidas se omiten."],
  ["packs.removedFavs", { n: 1 }, "Removed 1 favorite that pointed to the pack's scripts.", "Se quitó 1 favorito de los scripts del paquete."],
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

test.each([["en", 1, "1 device"], ["en", 2, "2 devices"], ["es", 1, "1 equipo"], ["es", 2, "2 equipos"]] as const)("plural() en %s con %i", (lang, n, txt) => {
  show({ unit: ["unit.device", n] }, lang);
  expect(screen.getByText(txt)).toBeInTheDocument();
});
test("plural() en español", () => {
  show({ unit: ["unit.row", 2] }, "es");
  expect(screen.getByText("2 filas")).toBeInTheDocument();
});
test("plural() con 0 va en plural", () => {
  show({ unit: ["unit.interface", 0] }, "es");
  expect(screen.getByText("0 interfaces")).toBeInTheDocument();
});
