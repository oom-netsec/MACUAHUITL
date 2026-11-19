import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DiagView } from "./DiagView";
import { fakeCore } from "../../lib/fake";

const nics = [{ name: "eth0", up: true, loopback: false, addresses: ["192.168.3.10/24"], hardwareAddr: "aa:bb" }];
const sum = (d: HTMLElement) => d.querySelector("summary")!;

test("iperf3 servidor: el puerto va plegado, cuenta y se abre solo si es inválido; el modo queda fuera", async () => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r3"), listInterfaces: vi.fn(async () => nics) });
  render(<DiagView core={core} tool="iperf3" />);
  expect(screen.queryByLabelText("Puerto")).not.toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText("Modo"), "server");
  await screen.findByLabelText("Escuchar en");
  const port = screen.getByLabelText("Puerto");
  const d = port.closest("details")!;
  expect(d.open).toBe(false);
  expect(d).not.toContainElement(screen.getByLabelText("Modo"));
  expect(d).not.toContainElement(screen.getByLabelText("Escuchar en"));
  await userEvent.clear(port);
  await userEvent.type(port, "80");
  expect(d.open).toBe(true);
  await userEvent.clear(port);
  await userEvent.type(port, "6000");
  expect(sum(d)).toHaveTextContent("cambiadas: 1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("iperf3", [], { mode: "server", bind: "192.168.3.10", port: "6000" }));
});

test("captura: el filtro BPF va plegado, cuenta y se sigue enviando; la interfaz queda fuera", async () => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r2"), listInterfaces: vi.fn(async () => nics) });
  render(<DiagView core={core} tool="pcap" />);
  const f = screen.getByLabelText("Filtro BPF");
  const d = f.closest("details")!;
  expect(d.open).toBe(false);
  expect(d).not.toContainElement(screen.getByLabelText("Interfaz"));
  await userEvent.type(f, "tcp port 22");
  expect(sum(d)).toHaveTextContent("cambiadas: 1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("pcap", [], expect.objectContaining({ filter: "tcp port 22" })));
});
