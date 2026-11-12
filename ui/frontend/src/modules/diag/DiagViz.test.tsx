import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CoreContext, ModuleIdContext, NavContext, type Delivery } from "../../app/activity";
import type { CoreAPI } from "../../lib/core";
import { fakeCore } from "../../lib/fake";

vi.mock("uplot", () => ({
  default: class {
    setSize() {} destroy() {} setData() {}
    get ctx() { return { canvas: { toDataURL: () => "" } }; }
  },
}));

import { DiagView, type ToolName } from "./DiagView";

async function start(tool: ToolName, target = "10.0.0.1") {
  const core = fakeCore({ diagRun: vi.fn(async () => "r1") });
  render(<CoreContext.Provider value={core as unknown as CoreAPI}><DiagView core={core} tool={tool} /></CoreContext.Provider>);
  if (tool !== "pcap") await userEvent.type(screen.getByLabelText("Destino"), target);
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalled());
  const emit = (...lines: string[]) => act(() => lines.forEach((line) => core.emitDiag({ runId: "r1", line })));
  return { core, emit };
}

test("ping: gráfica de RTT en vivo y cifras de mín, prom, máx, jitter y pérdida", async () => {
  const { emit } = await start("ping");
  emit(
    "64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.4 ms",
    "64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=0.5 ms",
    "no answer yet for icmp_seq=3",
    "64 bytes from 10.0.0.1: icmp_seq=4 ttl=64 time=0.3 ms",
  );
  const fig = await screen.findByRole("figure", { name: "RTT por paquete" });
  expect(fig).toHaveTextContent("RTT: mín 0.3 ms, prom 0.4 ms, máx 0.5 ms, último 0.3 ms");
  const stats = screen.getByRole("region", { name: "Estadísticas del ping" });
  expect(within(stats).getByText("Mínimo").nextSibling).toHaveTextContent("0.3 ms");
  expect(within(stats).getByText("Máximo").nextSibling).toHaveTextContent("0.5 ms");
  expect(within(stats).getByText("Jitter").nextSibling).toHaveTextContent("0.15 ms");
  expect(within(stats).getByText("Pérdida").nextSibling).toHaveTextContent("25 % (1 de 4)");
  expect(within(stats).getByText("Paquetes perdidos").nextSibling).toHaveTextContent("3");
});

test("traceroute: tabla de saltos con barra de RTT y los saltos sin respuesta resaltados", async () => {
  const { emit } = await start("traceroute", "8.8.8.8");
  emit(
    "traceroute to dns.google (8.8.8.8), 30 hops max, 60 byte packets",
    " 1  _gateway (192.168.1.1)  0.412 ms  0.388 ms  0.401 ms",
    " 2  * * *",
    " 3  dns.google (8.8.8.8)  14.2 ms  13.9 ms  14.8 ms",
  );
  const table = await screen.findByRole("table", { name: "Saltos" });
  const rows = within(table).getAllByRole("row");
  expect(rows).toHaveLength(4);
  expect(within(rows[1]).getByRole("meter", { name: "RTT del salto 1" })).toHaveAttribute("aria-valuenow", "0.4");
  expect(within(rows[3]).getByRole("meter", { name: "RTT del salto 3" })).toHaveAttribute("aria-valuenow", "14.3");
  expect(rows[2]).toHaveAttribute("data-state", "bad");
  expect(within(rows[2]).getByText("Sin respuesta")).toBeInTheDocument();
  expect(within(rows[2]).queryByRole("meter")).not.toBeInTheDocument();
});

test("iperf3: rendimiento por intervalo y promedio del enlace", async () => {
  const { emit } = await start("iperf3");
  emit(
    "[  5]   0.00-1.00   sec   112 MBytes   941 Mbits/sec    0    412 KBytes",
    "[  5]   1.00-2.00   sec   111 MBytes   930 Mbits/sec    3    398 KBytes",
  );
  const fig = await screen.findByRole("figure", { name: "Rendimiento" });
  expect(fig).toHaveTextContent("Rendimiento: mín 930 Mbps, prom 935.5 Mbps, máx 941 Mbps, último 930 Mbps");
  expect(screen.getByRole("region", { name: "Estadísticas de iperf3" })).toHaveTextContent("Retransmisiones3");
});

test("nmap: tabla de puertos con el estado en texto", async () => {
  const { emit } = await start("nmap");
  emit(
    "Nmap scan report for sw-core-1 (10.0.0.1)", "Not shown: 995 closed tcp ports (conn-refused)", "PORT     STATE         SERVICE",
    "22/tcp   open          ssh", "443/tcp  filtered      https", "161/udp  open|filtered snmp", "23/tcp   closed        telnet",
  );
  const table = await screen.findByRole("table", { name: "Puertos de sw-core-1 (10.0.0.1)" });
  const row = (re: RegExp) => within(table).getByRole("row", { name: re });
  expect(row(/^22\/tcp/)).toHaveTextContent("Abierto");
  expect(row(/^443\/tcp/)).toHaveTextContent("Filtrado");
  expect(row(/^161\/udp/)).toHaveTextContent("Abierto / Filtrado");
  expect(row(/^23\/tcp/)).toHaveTextContent("Cerrado");
  expect(row(/^22\/tcp/)).toHaveTextContent("ssh");
  expect(screen.getByText("995 puertos cerrados no se muestran")).toBeInTheDocument();
});

test("captura: contador en vivo y, al terminar, la ruta del PCAP con copiar", async () => {
  const { core, emit } = await start("pcap");
  emit("File: /home/u/out/cap.pcapng", "Packets: 12", "Packets: 40");
  expect(await screen.findByText("Paquetes capturados")).toBeInTheDocument();
  expect(screen.getByRole("status", { name: "Paquetes capturados" })).toHaveTextContent("40");
  expect(screen.queryByText("Archivo PCAP")).not.toBeInTheDocument();
  act(() => core.emitDiag({ runId: "r1", done: true, exitCode: 0, outputPath: "/home/u/out/cap.pcapng" }));
  const file = await screen.findByRole("region", { name: "Archivo PCAP" });
  expect(file).toHaveTextContent("/home/u/out/cap.pcapng");
  await userEvent.click(within(file).getByRole("button", { name: "Copiar ruta del PCAP" }));
  expect(core.copyText).toHaveBeenCalledWith("/home/u/out/cap.pcapng");
});

function renderWith(id: string, tool: ToolName, inbox: Record<string, Delivery>) {
  const core = fakeCore();
  return render(
    <NavContext.Provider value={{ go: () => {}, inbox }}>
      <ModuleIdContext.Provider value={id}><DiagView core={core} tool={tool} /></ModuleIdContext.Provider>
    </NavContext.Provider>,
  );
}

test("el menú de equipo rellena el destino de ping", async () => {
  renderWith("ping", "ping", { ping: { data: "10.1.1.1", n: 1 } });
  expect(screen.getByLabelText("Destino")).toHaveValue("10.1.1.1");
});

test("una entrega para otro módulo no se toma", async () => {
  renderWith("traceroute", "traceroute", { ping: { data: "10.1.1.1", n: 1 } });
  expect(screen.getByLabelText("Destino")).toHaveValue("");
});
