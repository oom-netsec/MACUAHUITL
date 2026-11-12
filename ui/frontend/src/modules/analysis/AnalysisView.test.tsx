import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AnalysisView } from "./AnalysisView";
import { fakeCore } from "../../lib/fake";
import { NavContext } from "../../app/activity";
import type { AnalysisReport, DiffReport, Finding, TimelineReport } from "../../lib/core";

const f = (over: Partial<Finding>): Finding => ({
  rule: "cpu-alta", title: "CPU alta", severity: "alta", device: "SW1_10.0.0.1", round: 3, at: "2026-11-04T10:20:05Z",
  command: "show processes cpu sorted", evidence: ["CPU utilization for five seconds: 95%/4%; one minute: 93%; five minutes: 91%"],
  detail: "5 min: 91% (umbral 80%)", explanation: "El promedio supera el umbral.", action: "Revisa los procesos.", ...over,
});

const report: AnalysisReport = {
  dir: "/o/lab", devices: ["SW1_10.0.0.1"], rounds: [1, 2, 3], missing: ["show ip bgp summary"],
  warnings: [{ device: "SW1_10.0.0.1", round: 2, command: "show version", msg: "formato inesperado" }],
  findings: [f({ rule: "log-mallocfail", title: "Falla de asignación de memoria", severity: "critica", evidence: ["%SYS-2-MALLOCFAIL: x"] }), f({})],
};

async function typeJob() {
  await userEvent.type(screen.getByLabelText("Trabajo (ID o carpeta)"), "/o/lab");
}

test("hallazgos agrupados por severidad con evidencia expandible", async () => {
  const core = fakeCore({ analysisRun: vi.fn(async () => report) });
  render(<AnalysisView core={core} />);
  expect(screen.getByRole("button", { name: "Analizar" })).toBeDisabled();
  await typeJob();
  await userEvent.clear(screen.getByLabelText("Ronda (0 = todas)"));
  await userEvent.type(screen.getByLabelText("Ronda (0 = todas)"), "3");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  expect(core.analysisRun).toHaveBeenCalledWith("/o/lab", 3, "");
  const crit = await screen.findByRole("region", { name: /Crítica \(1\)/ });
  expect(within(crit).getByText(/Falla de asignación de memoria/)).toBeInTheDocument();
  const alta = screen.getByRole("region", { name: /Alta \(1\)/ });
  // La evidencia está dentro de un <details> cerrado: se abre al pulsar el resumen.
  const sum = within(alta).getByText(/CPU alta/);
  const details = sum.closest("details")!;
  expect(details.open).toBe(false);
  await userEvent.click(sum);
  expect(details.open).toBe(true);
  expect(within(details).getByText(/five minutes: 91%/)).toBeInTheDocument();
  expect(within(details).getByText(/Revisa los procesos/)).toBeInTheDocument();
  expect(screen.getByText(/show ip bgp summary/)).toBeInTheDocument();
  expect(screen.getByText(/formato inesperado/)).toBeInTheDocument();
  expect(screen.getByText(/sin validar en laboratorio/i)).toBeInTheDocument();
}, 15_000);

test("sin corridas explica de dónde salen y lleva a Patrol", async () => {
  const go = vi.fn();
  render(<NavContext.Provider value={{ go, inbox: {} }}><AnalysisView core={fakeCore()} /></NavContext.Provider>);
  expect(screen.getByText("Sin corridas analizadas")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Ir a Patrol" }));
  expect(go).toHaveBeenCalledWith("patrol");
});

test("errores del núcleo legibles", async () => {
  const core = fakeCore({ analysisRun: vi.fn(async () => { throw new Error("rpc error: code = NotFound desc = trabajo x no existe"); }) });
  render(<AnalysisView core={core} />);
  await typeJob();
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/^trabajo x no existe$/);
});

test("diff entre rondas muestra recarga, contadores, vecinos y texto", async () => {
  const diff: DiffReport = {
    dir: "/o/lab", from: 2, to: 3, warnings: [],
    devices: [{
      device: "SW1_10.0.0.1", uptime: { from: "17d04h22m", to: "0h04m", reset: true },
      counters: [{ interface: "GigabitEthernet1/0/1", counter: "crc", from: 15, to: 1515, delta: 1500 }],
      neighbors: [{ protocol: "ospf", id: "10.255.0.4", change: "desapareció", from: "FULL", to: "" }],
      prefixes: [{ neighbor: "10.0.12.1", from: 10, to: 12 }],
      text: [{ command: "show version", lines: ["- SW1 uptime is 2 weeks", "+ SW1 uptime is 4 minutes"] }],
    }],
  };
  const core = fakeCore({ analysisDiff: vi.fn(async () => diff) });
  render(<AnalysisView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Diferencias" }));
  await typeJob();
  await userEvent.clear(screen.getByLabelText("Ronda A"));
  await userEvent.type(screen.getByLabelText("Ronda A"), "2");
  await userEvent.clear(screen.getByLabelText("Ronda B"));
  await userEvent.type(screen.getByLabelText("Ronda B"), "3");
  await userEvent.click(screen.getByRole("button", { name: "Comparar" }));
  expect(core.analysisDiff).toHaveBeenCalledWith("/o/lab", 2, 3, "");
  expect(await screen.findByText(/recargó entre rondas/i)).toBeInTheDocument();
  expect(screen.getByRole("cell", { name: "+1500" })).toBeInTheDocument();
  expect(screen.getByText(/10.255.0.4 desapareció/)).toBeInTheDocument();
  expect(screen.getByText(/10.0.12.1: 10 → 12/)).toBeInTheDocument();
  expect(screen.getByText(/\+ SW1 uptime is 4 minutes/)).toBeInTheDocument();
});

test("línea de tiempo con ventana de correlación alrededor de un evento", async () => {
  const tl: TimelineReport = {
    dir: "/o/lab", warnings: [],
    events: [
      { at: "2026-11-04T10:09:18.64Z", source: "log-equipo", device: "RTR2_10.0.0.2", severity: "baja", text: "%BGP-5-ADJCHANGE: neighbor 10.0.13.1 Down", kb: "%BGP-5-ADJCHANGE: Cambió el estado de un vecino BGP. Acción: Revisa el motivo." },
      { at: "2026-11-04T10:09:19Z", source: "syslog", device: "RTR2_10.0.0.2", text: "<189>%BGP-5-ADJCHANGE", note: "reloj sin sincronizar en el equipo" },
    ],
  };
  const core = fakeCore({ analysisTimeline: vi.fn(async () => tl) });
  render(<AnalysisView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Línea de tiempo" }));
  await typeJob();
  await userEvent.type(screen.getByLabelText("Equipo (opcional)"), "RTR2");
  await userEvent.type(screen.getByLabelText("Captura pcap (opcional, ruta absoluta)"), "/c.pcap");
  await userEvent.click(screen.getByRole("button", { name: "Ver línea de tiempo" }));
  expect(core.analysisTimeline).toHaveBeenLastCalledWith("/o/lab", "", 30, "RTR2", "/c.pcap");
  const rows = await screen.findAllByRole("row");
  expect(rows).toHaveLength(3); // cabecera + 2
  expect(screen.getByText(/reloj sin sincronizar/)).toBeInTheDocument();
  expect(screen.getByText(/Base de mensajes: %BGP-5-ADJCHANGE: Cambió el estado de un vecino BGP/)).toBeInTheDocument();
  await userEvent.click(within(rows[1]).getByRole("button", { name: /±30 s/ }));
  await waitFor(() => expect(core.analysisTimeline).toHaveBeenLastCalledWith("/o/lab", "2026-11-04T10:09:18.64Z", 30, "RTR2", "/c.pcap"));
  expect(screen.getByLabelText("Alrededor de (RFC 3339)")).toHaveValue("2026-11-04T10:09:18.64Z");
});
