import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DiagView } from "./DiagView";
import { fakeCore } from "../../lib/fake";

test("ejecuta ping, muestra la salida en vivo y la ruta al terminar", async () => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r1") });
  render(<DiagView core={core} tool="ping" />);
  expect(screen.getByRole("heading", { name: "Ping" })).toBeInTheDocument();
  expect(screen.getByLabelText("Destino")).toHaveAccessibleDescription("Nombre de host o dirección IP.");
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.clear(screen.getByLabelText("Paquetes"));
  await userEvent.type(screen.getByLabelText("Paquetes"), "6");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("ping", ["10.0.0.1"], { count: "6" }));
  act(() => core.emitDiag({ runId: "r1", line: "64 bytes from 10.0.0.1" }));
  act(() => core.emitDiag({ runId: "otro", line: "no es mío" }));
  expect(await screen.findByRole("log", { name: "Salida" })).toHaveTextContent(/64 bytes from 10\.0\.0\.1/);
  expect(screen.queryByText(/no es mío/)).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Cancelar" }));
  expect(core.diagCancel).toHaveBeenCalledWith("r1");
  act(() => core.emitDiag({ runId: "r1", done: true, exitCode: 0, outputPath: "/home/u/out/diag_ping_x.txt" }));
  expect(await screen.findByText(/diag_ping_x\.txt/)).toBeInTheDocument();
});

test("la captura pide interfaz y manda el filtro tal cual", async () => {
  const core = fakeCore({
    diagRun: vi.fn(async () => "r2"),
    listInterfaces: vi.fn(async () => [
      { name: "eth0", up: true, loopback: false, addresses: ["192.0.2.10/24"], hardwareAddr: "00:11:22:33:44:55" },
      { name: "wlan0", up: false, loopback: false, addresses: [], hardwareAddr: "" },
    ]),
  });
  render(<DiagView core={core} tool="pcap" />);
  const iface = screen.getByLabelText("Interfaz");
  expect(iface).toHaveValue("any");
  expect(await screen.findByRole("option", { name: "eth0 · 192.0.2.10/24" })).toBeInTheDocument();
  expect(screen.getByRole("option", { name: "wlan0 · inactiva" })).toBeInTheDocument();
  await userEvent.selectOptions(iface, "eth0");
  await userEvent.type(screen.getByLabelText("Filtro BPF"), "tcp port 22");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("pcap", [], expect.objectContaining({ interface: "eth0", filter: "tcp port 22" })));
});

test("un fallo inmediato (herramienta no instalada) no deja la vista atorada", async () => {
  let resolveRun: (id: string) => void = () => {};
  const core = fakeCore({ diagRun: vi.fn(() => new Promise<string>((r) => { resolveRun = r; })) });
  render(<DiagView core={core} tool="nmap" />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  // El evento llega antes de que la promesa del ID se resuelva.
  act(() => core.emitDiag({ runId: "r9", done: true, exitCode: -1, error: "rpc error: code = FailedPrecondition desc = diag: herramienta no instalada: nmap (instala: sudo apt install nmap)" }));
  act(() => resolveRun("r9"));
  expect(await screen.findByRole("alert")).toHaveTextContent(/sudo apt install nmap/);
  expect(screen.getByRole("button", { name: "Ejecutar" })).toBeEnabled();
});

test("iperf3 en modo servidor no manda segundos", async () => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r3") });
  render(<DiagView core={core} tool="iperf3" />);
  await userEvent.selectOptions(screen.getByLabelText("Modo"), "server");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("iperf3", [], { mode: "server" }));
});

test("el botón de ejecutar queda deshabilitado hasta que hay destino", async () => {
  render(<DiagView core={fakeCore()} tool="ping" />);
  expect(screen.getByRole("button", { name: /Ejecutar/ })).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  expect(screen.getByRole("button", { name: /Ejecutar/ })).toBeEnabled();
});

test("cancelar no es un fallo: estado neutro «Cancelado» y sin mensaje de error", async () => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r1") });
  render(<DiagView core={core} tool="ping" />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalled());
  await userEvent.click(await screen.findByRole("button", { name: "Cancelar" }));
  act(() => core.emitDiag({ runId: "r1", done: true, exitCode: -1, canceled: true }));
  expect(await screen.findByText("Cancelado")).toBeInTheDocument();
  expect(screen.getByText("Cancelado por el usuario.")).toBeInTheDocument();
  expect(screen.queryByText(/Con error|Error:/)).not.toBeInTheDocument();
});

test("dos clics seguidos en Ejecutar no lanzan dos ejecuciones", async () => {
  const core = fakeCore({ diagRun: vi.fn(() => new Promise<string>(() => {})) });
  render(<DiagView core={core} tool="ping" />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  const run = screen.getByRole("button", { name: /Ejecutar/ });
  await userEvent.click(run);
  await userEvent.click(run);
  expect(core.diagRun).toHaveBeenCalledTimes(1);
});
