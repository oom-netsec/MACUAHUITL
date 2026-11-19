import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { fakeCore } from "./fake";
import { I18nProvider } from "./i18n";
import { NavContext } from "../app/activity";
import { SyslogTable } from "../modules/tools/SyslogTable";
import { TrapsTable } from "../modules/visibility/VisParts";
import { SavedHosts } from "../modules/terminal/SavedHosts";
import { DriftView } from "../modules/drift/DriftView";
import { AnalysisView } from "../modules/analysis/AnalysisView";
import { ScriptsView } from "../modules/scripts/ScriptsView";
import { PingTraceView } from "../modules/diag/PingTraceView";
import { HostsDataCard } from "../modules/settings/HostsDataCard";
import { fakeInventory, sampleHosts, sampleHostsImport } from "../modules/inventory/fake";
import { sampleScripts } from "../modules/scripts/fake";

// Texto de red o de equipo que el usuario lee para decidir: bidi y controles se ven como código, no se ejecutan ni reordenan la línea.
const RAW = "x‮y⁦⁩\u0007z";
const SHOWN = "x⟦U+202E⟧y⟦U+2066⟧⟦U+2069⟧⟦U+0007⟧z";
const noRaw = (s: string | null) => expect(s).not.toMatch(/[‮⁦⁩\u0007]/);
const wrap = (ui: React.ReactElement) => render(<I18nProvider>{ui}</I18nProvider>);
beforeEach(() => localStorage.clear());

test("Syslog: el mensaje del equipo", () => {
  wrap(<SyslogTable msgs={[{ id: 1, at: Date.now(), from: "10.0.0.1", sev: 3, mnemonic: "X", text: `hola ${RAW}` }]} />);
  const cell = screen.getByText(`hola ${SHOWN}`);
  noRaw(cell.textContent);
});

test("Trampas SNMP: el resumen", () => {
  wrap(<TrapsTable rows={[{ id: 1, at: "2026-11-01T10:00:00Z", From: "10.0.0.1:162", Name: "linkDown", Summary: `s ${RAW}` } as never]} />);
  expect(screen.getByText(`s ${SHOWN}`)).toBeVisible();
});

test("Terminal → hosts guardados: nombre en el botón y en su nombre accesible", async () => {
  const core = fakeCore({ listHosts: vi.fn(async () => [{ ...sampleHosts[0], name: `H${RAW}` }]) });
  const cred = { id: sampleHosts[0].credentialId, label: "c", username: "u", kind: "password" as const, hasEnable: false, hasSshKey: false };
  wrap(<SavedHosts core={core} creds={[cred]} busy={false} onConnect={() => {}} />);
  const b = await screen.findByRole("button", { name: `Conectar a H${SHOWN}` });
  expect(b.textContent).toBe(`H${SHOWN}`);
  noRaw(b.getAttribute("aria-label")); // el nombre accesible ya vino sin invisibles: la búsqueda por él lo comprueba
});

test("Drift: el nombre del equipo en el título", async () => {
  const rep = { dir: "/o", from: 1, to: 2, warnings: [], devices: [{ device: `SW${RAW}`, from: 1, to: 2, added: 0, removed: 0, ignored: [], changes: [] }] };
  const core = fakeCore({ driftRun: vi.fn(async () => rep) });
  wrap(<DriftView core={core} />);
  await userEvent.type(screen.getByLabelText("Trabajo o carpeta"), "/o");
  await userEvent.click(screen.getByRole("button", { name: "Comparar" }));
  const h = await screen.findByRole("heading", { name: `SW${SHOWN}` });
  noRaw(h.textContent);
});

test("Análisis (diferencias): el nombre del equipo en el título", async () => {
  const diff = { dir: "/o", from: 2, to: 3, warnings: [], devices: [{ device: `SW${RAW}`, counters: [], neighbors: [], prefixes: [], text: [] }] };
  const core = fakeCore({ analysisDiff: vi.fn(async () => diff as never) });
  wrap(<AnalysisView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Diferencias" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Trabajo (ID o carpeta)" }), "/o");
  await userEvent.click(screen.getByRole("button", { name: "Comparar" }));
  const h = await screen.findByRole("heading", { name: `SW${SHOWN}` });
  noRaw(h.textContent);
});

test("Scripts: el nombre del script seleccionado en el título", async () => {
  const core = fakeCore();
  const evil = { ...sampleScripts[1], name: `S${RAW}` };
  core.listScripts = vi.fn(async () => [evil as never]);
  render(<I18nProvider><NavContext.Provider value={{ go: vi.fn(), inbox: {} }}><ScriptsView core={core} /></NavContext.Provider></I18nProvider>);
  await userEvent.click(await screen.findByRole("button", { name: new RegExp(`^S`) }));
  const h = await screen.findByRole("heading", { name: `S${SHOWN}` });
  noRaw(h.textContent);
});

test("Diagnóstico: bidi y controles en la salida (después de quitar ANSI)", async () => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r1") });
  wrap(<PingTraceView core={core} />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalled());
  act(() => core.emitDiag({ runId: "r1", line: `\u001b[31m${RAW}\u001b[0m\r` }));
  const log = screen.getByRole("log", { name: "Ping" });
  await waitFor(() => expect(log.textContent).toContain(SHOWN));
  expect(log.textContent).not.toMatch(/\u001b|\r|⟦U\+000D⟧|\[31m/);
  noRaw(log.textContent);
});

test("Importar hosts: la etiqueta de credencial en la vista previa", async () => {
  const item = { ...sampleHostsImport.items[0], host: { ...sampleHostsImport.items[0].host, credentialLabel: `c${RAW}` } };
  const core = fakeCore({ ...fakeInventory(), pickPath: vi.fn(async () => "/h.csv"), previewHostsImport: vi.fn(async () => ({ ...sampleHostsImport, items: [item] })) });
  wrap(<HostsDataCard core={core} />);
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  const t = await screen.findByRole("table", { name: "Filas válidas del archivo" });
  expect(within(t).getByText(`c${SHOWN}`)).toBeVisible();
});
