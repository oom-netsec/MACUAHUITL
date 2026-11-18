import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PcapPanel, TlsPanel } from "./ToolsView";
import { fakeCore } from "../../lib/fake";

const sum = (d: HTMLElement) => d.querySelector("summary")!;

test("tls: puerto y SNI van plegados, cuentan y se siguen enviando; el host queda fuera", async () => {
  const core = fakeCore({ toolsTls: vi.fn(async () => "ok") });
  render(<TlsPanel core={core} />);
  const d = screen.getByLabelText("Puerto").closest("details")!;
  expect(d.open).toBe(false);
  expect(d).toContainElement(screen.getByLabelText(/^SNI/));
  expect(d).not.toContainElement(screen.getByLabelText("Host"));
  expect(d).not.toContainElement(screen.getByRole("button", { name: "Inspeccionar" }));
  await userEvent.type(screen.getByLabelText("Host"), "ise.lab");
  await userEvent.clear(screen.getByLabelText("Puerto"));
  await userEvent.type(screen.getByLabelText("Puerto"), "8443");
  await userEvent.type(screen.getByLabelText(/^SNI/), "a.lab");
  expect(sum(d)).toHaveTextContent("cambiadas: 2");
  await userEvent.click(screen.getByRole("button", { name: "Inspeccionar" }));
  expect(core.toolsTls).toHaveBeenCalledWith("ise.lab", 8443, "a.lab");
});

test("pcap: «Elementos por lista» va plegado, cuenta y se sigue enviando; el archivo queda fuera", async () => {
  const core = fakeCore({ toolsPcap: vi.fn(async () => "1 paquetes") });
  render(<PcapPanel core={core} />);
  const d = screen.getByLabelText("Elementos por lista").closest("details")!;
  expect(d.open).toBe(false);
  expect(d).not.toContainElement(screen.getByLabelText("Archivo de captura"));
  await userEvent.type(screen.getByLabelText("Archivo de captura"), "/x.pcap");
  await userEvent.clear(screen.getByLabelText("Elementos por lista"));
  await userEvent.type(screen.getByLabelText("Elementos por lista"), "5");
  expect(sum(d)).toHaveTextContent("cambiadas: 1");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  expect(core.toolsPcap).toHaveBeenCalledWith("/x.pcap", 5);
});
