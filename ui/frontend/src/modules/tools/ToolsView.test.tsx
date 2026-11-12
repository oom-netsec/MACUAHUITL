import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DnsPanel, PcapPanel, SyslogPanel, TlsPanel } from "./ToolsView";
import { fakeCore } from "../../lib/fake";

test("pcap analiza la ruta indicada y muestra el resumen", async () => {
  const core = fakeCore({ toolsPcap: vi.fn(async () => "26 paquetes\nRST: 1") });
  render(<PcapPanel core={core} />);
  await userEvent.type(screen.getByLabelText("Archivo de captura"), "/home/x/cap.pcapng");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  expect(await screen.findByText(/26 paquetes/)).toBeInTheDocument();
  expect(core.toolsPcap).toHaveBeenCalledWith("/home/x/cap.pcapng", 20);
});

test("los modos DNS profundos exigen autorización explícita", async () => {
  const core = fakeCore({ toolsDns: vi.fn(async () => "{}") });
  render(<DnsPanel core={core} />);
  await userEvent.selectOptions(screen.getByLabelText("Modo"), "trace");
  await userEvent.type(screen.getByLabelText("Nombre"), "example.com");
  expect(screen.getByRole("button", { name: "Consultar" })).toBeDisabled();
  await userEvent.click(screen.getByLabelText(/Modo profundo/));
  await userEvent.click(screen.getByRole("button", { name: "Consultar" }));
  await waitFor(() => expect(core.toolsDns).toHaveBeenCalledWith(expect.objectContaining({ mode: "trace", name: "example.com", deep: true, servers: [] })));
});

test("dns con servidores escritos y error legible", async () => {
  const core = fakeCore({ toolsDns: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = dnsq: servidor inválido"); }) });
  render(<DnsPanel core={core} />);
  await userEvent.type(screen.getByLabelText("Nombre"), "example.com");
  await userEvent.type(screen.getByLabelText(/Servidores/), "1.1.1.1, tls://9.9.9.9");
  await userEvent.click(screen.getByRole("button", { name: "Consultar" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/^dnsq: servidor inválido$/);
  expect(core.toolsDns).toHaveBeenCalledWith(expect.objectContaining({ servers: ["1.1.1.1", "tls://9.9.9.9"] }));
});

test("tls inspecciona host y puerto", async () => {
  const core = fakeCore({ toolsTls: vi.fn(async () => "vence-pronto") });
  render(<TlsPanel core={core} />);
  await userEvent.type(screen.getByLabelText("Host"), "ise.lab");
  await userEvent.clear(screen.getByLabelText("Puerto"));
  await userEvent.type(screen.getByLabelText("Puerto"), "8443");
  await userEvent.click(screen.getByRole("button", { name: "Inspeccionar" }));
  expect(await screen.findByText("vence-pronto")).toBeInTheDocument();
  expect(core.toolsTls).toHaveBeenCalledWith("ise.lab", 8443, "");
});

test("syslog muestra mensajes de su ejecución y se detiene", async () => {
  const core = fakeCore({ syslogStart: vi.fn(async () => "s1") });
  render(<SyslogPanel core={core} />);
  await userEvent.click(screen.getByRole("button", { name: "Escuchar" }));
  expect(core.syslogStart).toHaveBeenCalledWith("127.0.0.1:5514", "udp", false, false, {});
  core.emitSyslog({ runId: "s1", listening: "127.0.0.1:5514" });
  core.emitSyslog({ runId: "s1", json: JSON.stringify({ From: "10.0.0.2:514", Severity: 3, Mnemonic: "LINK-3-UPDOWN", Raw: "<187>%LINK-3-UPDOWN: Gi1/0/7 down" }) });
  core.emitSyslog({ runId: "otro", json: JSON.stringify({ Raw: "ajeno" }) });
  expect(await screen.findByRole("cell", { name: /Gi1\/0\/7 down/ })).toBeInTheDocument();
  expect(screen.getByText(/Escuchando en 127.0.0.1:5514/)).toBeInTheDocument();
  expect(screen.getByText("1 mensaje")).toBeInTheDocument();
  expect(screen.queryByText(/ajeno/)).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Detener" }));
  expect(core.diagCancel).toHaveBeenCalledWith("s1");
});

test("tls explica qué hacer antes de la primera inspección y la salida va en una terminal", async () => {
  const core = fakeCore({ toolsTls: vi.fn(async () => "TLS 1.3") });
  render(<TlsPanel core={core} />);
  expect(screen.getByText("Sin inspecciones todavía")).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("Host"), "ise.lab");
  await userEvent.click(screen.getByRole("button", { name: "Inspeccionar" }));
  expect(await screen.findByRole("log", { name: "Salida" })).toHaveTextContent("TLS 1.3");
  expect(screen.queryByText("Sin inspecciones todavía")).not.toBeInTheDocument();
});

test("pcap elige el archivo con el diálogo nativo filtrando capturas", async () => {
  const core = fakeCore({ pickPath: vi.fn(async () => "/home/x/elegida.pcap"), toolsPcap: vi.fn(async () => "ok") });
  render(<PcapPanel core={core} />);
  await userEvent.click(screen.getByRole("button", { name: /Examinar/ }));
  expect(core.pickPath).toHaveBeenCalledWith(expect.objectContaining({ filters: [{ name: "Capturas de paquetes", pattern: "*.pcap;*.pcapng" }] }));
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  expect(core.toolsPcap).toHaveBeenCalledWith("/home/x/elegida.pcap", 20);
});
