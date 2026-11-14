import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DnsPanel, PcapPanel, TlsPanel } from "./ToolsView";
import { fakeCore } from "../../lib/fake";
import { dnsTraceSample, tlsSample } from "./samples";
import type { PcapReportData } from "./api";

// Fase 30c: DNS y TLS salen de toolsDnsReport/toolsTlsReport (hallazgos y verifyCode estructurados), sin leer texto del núcleo.

async function dns(core: ReturnType<typeof fakeCore>) {
  render(<DnsPanel core={core} />);
  await userEvent.selectOptions(screen.getByLabelText("Modo"), "trace");
  await userEvent.type(screen.getByLabelText("Nombre"), "www.example.com");
  await userEvent.click(screen.getByLabelText(/Modo profundo/));
  await userEvent.click(screen.getByRole("button", { name: "Consultar" }));
}

// La traza no trae findings (solo transporte, higiene y zona): sus avisos son los Warnings del json, ya traducidos (30d).
test("DNS: el árbol y sus avisos salen del json del informe, sin llamar al método de texto", async () => {
  const json = JSON.stringify({ ...JSON.parse(dnsTraceSample), Warnings: ["Long CNAME chain"] });
  const core = fakeCore({ toolsDnsReport: vi.fn(async () => ({ text: "Trace report", json, findings: [] })), toolsDns: vi.fn(async () => "no") });
  await dns(core);
  expect(await screen.findByRole("list", { name: "Traza desde la raíz" })).toBeInTheDocument();
  expect(screen.getByText("Long CNAME chain")).toBeInTheDocument();
  expect(screen.getByText("Trace report")).toBeInTheDocument();
  expect(core.toolsDns).not.toHaveBeenCalled();
});

test("DNS: si el informe viene vacío cae a toolsDns", async () => {
  const core = fakeCore({ toolsDns: vi.fn(async () => dnsTraceSample) });
  await dns(core);
  expect(await screen.findByRole("list", { name: "Traza desde la raíz" })).toBeInTheDocument();
  expect(core.toolsDns).toHaveBeenCalled();
});

test("DNS: un error del informe se muestra y no se repite con el método de texto", async () => {
  const core = fakeCore({ toolsDnsReport: vi.fn(async () => { throw new Error("boom"); }), toolsDns: vi.fn(async () => "no") });
  await dns(core);
  expect(await screen.findByText(/boom/)).toBeInTheDocument();
  expect(core.toolsDns).not.toHaveBeenCalled();
});

async function tls(core: ReturnType<typeof fakeCore>) {
  render(<TlsPanel core={core} />);
  await userEvent.type(screen.getByLabelText("Host"), "a.lab");
  await userEvent.click(screen.getByRole("button", { name: "Inspeccionar" }));
}
const bad = () => JSON.stringify({ Verified: false, VerifyError: "x509: algo sin traducir", Chain: [{ Subject: "CN=a", Issuer: "CN=b", NotAfter: "2030-01-01T00:00:00Z" }] });

test("TLS: el motivo se decide por verifyCode y no se muestra verifyError", async () => {
  const core = fakeCore({ toolsTlsReport: vi.fn(async () => ({ text: "t", json: bad(), findings: [], verifyCode: "unknown_authority" })), toolsTls: vi.fn(async () => "no") });
  await tls(core);
  expect(await screen.findByText("Autoridad desconocida")).toBeInTheDocument();
  expect(screen.queryByText(/x509/)).not.toBeInTheDocument();
  expect(core.toolsTls).not.toHaveBeenCalled();
});

test("TLS: un verifyCode que la vista no conoce cae a other", async () => {
  const core = fakeCore({ toolsTlsReport: vi.fn(async () => ({ text: "t", json: bad(), findings: [], verifyCode: "nuevo" })) });
  await tls(core);
  expect(await screen.findByText("No se pudo verificar la cadena")).toBeInTheDocument();
});

test("TLS: cadena verificada no muestra motivo", async () => {
  const core = fakeCore({ toolsTlsReport: vi.fn(async () => ({ text: "t", json: tlsSample, findings: [] })) });
  await tls(core);
  expect(await screen.findByText("Cadena verificada")).toBeInTheDocument();
  expect(screen.queryByText("Autoridad desconocida")).not.toBeInTheDocument();
});

test("TLS: informe vacío cae a toolsTls", async () => {
  const core = fakeCore({ toolsTls: vi.fn(async () => tlsSample) });
  await tls(core);
  expect(await screen.findByRole("list", { name: "Cadena de certificados" })).toBeInTheDocument();
});

test("TLS: un error del informe se muestra y no se repite", async () => {
  const core = fakeCore({ toolsTlsReport: vi.fn(async () => { throw new Error("boom"); }), toolsTls: vi.fn(async () => "no") });
  await tls(core);
  expect(await screen.findByText(/boom/)).toBeInTheDocument();
  expect(core.toolsTls).not.toHaveBeenCalled();
});

const base = { text: "Capture: x", summary: { file: "x", packets: 3, bytes: 30, durationMs: 1, start: "" }, neighbors: [],
  tcp: { handshakes: 0, rttMinMs: 0, rttAvgMs: 0, rttMaxMs: 0, retransmissions: 0, zeroWindow: 0, failedHandshakesTotal: 0, failedHandshakes: [], resets: [] },
  dns: { queries: 0, responses: 0, errors: [], slow: [], unanswered: [] }, tls: [], icmp: { unreachable: [], ttlExceeded: [] }, arpConflicts: [], fragments: 0, warnings: [], sections: [] };
const rep: PcapReportData = { ...base, conversations: [], topTalkers: [{ ip: "10.0.0.5", packets: 3, bytes: 30 }], protocols: [] };

test("pcap: las tarjetas de una corrida no sobreviven a la siguiente que cae al texto", async () => {
  const core = fakeCore({ toolsPcapReport: vi.fn().mockResolvedValueOnce(rep).mockResolvedValueOnce({ ...base, text: "" }), toolsPcap: vi.fn(async () => "segunda") });
  render(<PcapPanel core={core} />);
  await userEvent.type(screen.getByLabelText("Archivo de captura"), "/x.pcap");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  await screen.findByRole("list", { name: "Equipos con más tráfico" });
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  await screen.findByText("segunda");
  expect(screen.queryByRole("list", { name: "Equipos con más tráfico" })).not.toBeInTheDocument();
});
