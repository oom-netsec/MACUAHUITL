import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PcapPanel } from "./ToolsView";
import { fakeCore } from "../../lib/fake";
import { pcapSample } from "./samples";

test("pcap muestra equipos, protocolos y conversaciones, y deja el informe completo en la terminal", async () => {
  const core = fakeCore({ toolsPcap: vi.fn(async () => pcapSample) });
  render(<PcapPanel core={core} />);
  await userEvent.type(screen.getByLabelText("Archivo de captura"), "/home/x/cap.pcapng");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  const talkers = await screen.findByRole("list", { name: "Equipos con más tráfico" });
  const rows = within(talkers).getAllByRole("listitem");
  expect(rows[0]).toHaveTextContent("10.10.1.25");
  expect(rows[0]).toHaveTextContent("10400 paquetes");
  expect(within(rows[0]).getByRole("button", { name: "Copiar 10.10.1.25" })).toBeInTheDocument();
  expect(within(screen.getByRole("list", { name: "Protocolos" })).getAllByRole("listitem")[0]).toHaveTextContent("tcp");
  const conv = screen.getByRole("table", { name: "Conversaciones con más bytes" });
  expect(within(conv).getAllByRole("row")).toHaveLength(6);
  expect(screen.getByRole("log", { name: "Informe completo" })).toHaveTextContent("Captura: /home/netops");
});
