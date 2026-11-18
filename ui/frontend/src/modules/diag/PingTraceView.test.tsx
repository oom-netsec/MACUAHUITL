import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PingTraceView } from "./PingTraceView";
import { fakeCore } from "../../lib/fake";
import { NavContext } from "../../app/activity";

const ids = () => { let n = 0; return vi.fn(async () => `r${++n}`); };
const both = async () => {
  await userEvent.type(screen.getByLabelText("Destino"), "sw1.lab");
  await userEvent.click(screen.getByRole("checkbox", { name: "Traceroute" }));
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
};

test("por omisión solo Ping está marcado: sus opciones se ven y las de traceroute no", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  expect(screen.getByRole("checkbox", { name: "Ping" })).toBeChecked();
  expect(screen.getByRole("checkbox", { name: "Traceroute" })).not.toBeChecked();
  expect(screen.getByLabelText("Paquetes")).toBeInTheDocument();
  expect(screen.queryByText("Saltos máximos")).not.toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledTimes(1));
  expect(core.diagRun).toHaveBeenCalledWith("ping", ["10.0.0.1"], { count: "4" });
});

test("sin ninguna casilla no se puede ejecutar y lo dice", async () => {
  render(<PingTraceView core={fakeCore()} />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("checkbox", { name: "Ping" }));
  expect(screen.getByRole("button", { name: "Ejecutar" })).toBeDisabled();
  expect(screen.getByText(/marcar Ping o Traceroute/)).toBeInTheDocument();
});

test("con las dos marcadas lanza dos diagRun y cada panel recibe solo su salida", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  await both();
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledTimes(2));
  expect(core.diagRun).toHaveBeenCalledWith("ping", ["sw1.lab"], { count: "4" });
  expect(core.diagRun).toHaveBeenCalledWith("traceroute", ["sw1.lab"], { max_hops: "30" });
  await screen.findAllByRole("log");
  act(() => core.emitDiag({ runId: "r1", line: "64 bytes from ping" }));
  act(() => core.emitDiag({ runId: "r2", line: " 1  10.0.0.254  1.2 ms" }));
  await waitFor(() => expect(screen.getByRole("log", { name: "Ping" })).toHaveTextContent("64 bytes from ping"));
  expect(screen.getByRole("log", { name: "Ping" })).not.toHaveTextContent("10.0.0.254");
  expect(screen.getByRole("log", { name: "Traceroute" })).toHaveTextContent("10.0.0.254");
});

test("Detener en el panel de ping corta solo el ping (r1) y traceroute sigue corriendo y habilitado", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  await both();
  await screen.findAllByRole("log");
  const ping = screen.getByRole("log", { name: "Ping" }).closest<HTMLElement>("[data-tool]")!;
  const trace = screen.getByRole("log", { name: "Traceroute" }).closest<HTMLElement>("[data-tool]")!;
  await userEvent.click(within(ping).getByRole("button", { name: "Detener ping" }));
  expect(core.diagCancel).toHaveBeenCalledTimes(1);
  expect(core.diagCancel).toHaveBeenCalledWith("r1");
  act(() => core.emitDiag({ runId: "r1", done: true, exitCode: -1, canceled: true }));
  expect(within(trace).getByRole("button", { name: "Detener traceroute" })).toBeEnabled();
  expect(within(ping).getByRole("button", { name: "Detener ping" })).toBeDisabled();
});

const continuousBoth = async (over = {}) => {
  const core = fakeCore({ diagRun: ids(), ...over });
  render(<PingTraceView core={core} />);
  await userEvent.type(screen.getByLabelText("Destino"), "sw1.lab");
  await userEvent.click(screen.getByRole("checkbox", { name: "Traceroute" }));
  await userEvent.click(screen.getByText("Opciones extendidas"));
  await userEvent.click(screen.getByLabelText("Continuo (hasta detener)"));
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await screen.findAllByRole("log");
  return core;
};

test("ping continuo: Detener ping usa diagStop(r1) y traceroute sigue corriendo", async () => {
  const core = await continuousBoth();
  const trace = screen.getByRole("log", { name: "Traceroute" }).closest<HTMLElement>("[data-tool]")!;
  await userEvent.click(screen.getByRole("button", { name: "Detener ping" }));
  expect(core.diagStop).toHaveBeenCalledWith("r1");
  expect(core.diagCancel).not.toHaveBeenCalled();
  expect(within(trace).getByRole("button", { name: "Detener traceroute" })).toBeEnabled();
});

test("ping continuo: si diagStop falla, Cancelar ping sigue disponible y llama a diagCancel", async () => {
  const core = await continuousBoth({ diagStop: vi.fn().mockRejectedValue(new Error("boom")) });
  await userEvent.click(screen.getByRole("button", { name: "Detener ping" }));
  await act(async () => {});
  await userEvent.click(screen.getByRole("button", { name: "Cancelar ping" }));
  expect(core.diagCancel).toHaveBeenCalledWith("r1");
});

test("un ping sin continuo ni duración no tiene Cancelar aparte; traceroute tampoco", async () => {
  render(<PingTraceView core={fakeCore({ diagRun: ids() })} />);
  await both();
  await screen.findAllByRole("log");
  expect(screen.queryByRole("button", { name: /^Cancelar/ })).not.toBeInTheDocument();
});

test("Limpiar tiene un nombre distinto por panel", async () => {
  render(<PingTraceView core={fakeCore({ diagRun: ids() })} />);
  await both();
  await screen.findAllByRole("log");
  expect(screen.getByRole("button", { name: "Limpiar ping" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Limpiar traceroute" })).toBeInTheDocument();
});

test("al ejecutar solo traceroute a otro destino no quedan el panel de ping ni su IP resuelta viejos", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  await userEvent.type(screen.getByLabelText("Destino"), "sw1.lab");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await screen.findByRole("log", { name: "Ping" });
  act(() => core.emitDiag({ runId: "r1", resolved: { name: "sw1.lab", ip: "192.0.2.1", family: "ipv4" } }));
  act(() => core.emitDiag({ runId: "r1", done: true, exitCode: 0 }));
  await screen.findByText(/sw1\.lab → 192\.0\.2\.1/);
  await userEvent.click(screen.getByRole("checkbox", { name: "Ping" }));
  await userEvent.click(screen.getByRole("checkbox", { name: "Traceroute" }));
  await userEvent.clear(screen.getByLabelText("Destino"));
  await userEvent.type(screen.getByLabelText("Destino"), "sw2.lab");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await screen.findByRole("log", { name: "Traceroute" });
  expect(screen.queryByRole("log", { name: "Ping" })).not.toBeInTheDocument();
  expect(screen.queryByText(/sw1\.lab/)).not.toBeInTheDocument();
});

test("la IP resuelta va arriba como «nombre → IP»; si cada herramienta resuelve distinto salen las dos", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  await both();
  await screen.findAllByRole("log");
  act(() => core.emitDiag({ runId: "r1", resolved: { name: "sw1.lab", ip: "192.0.2.1", family: "ipv4" } }));
  act(() => core.emitDiag({ runId: "r2", resolved: { name: "sw1.lab", ip: "192.0.2.1", family: "ipv4" } }));
  const box = await screen.findByLabelText("IP resuelta");
  expect(box).toHaveTextContent("sw1.lab → 192.0.2.1 (IPv4)");
  expect(box).not.toHaveTextContent("Traceroute");
  act(() => core.emitDiag({ runId: "r2", resolved: { name: "sw1.lab", ip: "2001:db8::1", family: "ipv6" } }));
  await waitFor(() => expect(screen.getByLabelText("IP resuelta")).toHaveTextContent("Ping: sw1.lab → 192.0.2.1 (IPv4) Traceroute: sw1.lab → 2001:db8::1 (IPv6)"));
});

test("si el destino ya era una IP (name = ip) no se muestra nada", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await screen.findByRole("log");
  act(() => core.emitDiag({ runId: "r1", resolved: { name: "10.0.0.1", ip: "10.0.0.1", family: "ipv4" } }));
  expect(screen.queryByLabelText("IP resuelta")).not.toBeInTheDocument();
});

test("el menú de equipo con «traceroute» deja el destino y marca solo Traceroute", async () => {
  const core = fakeCore();
  const inbox = { ping: { data: "10.20.3.11", n: 1 }, "ping-tool": { data: "traceroute", n: 1 } };
  render(<NavContext.Provider value={{ go: () => {}, inbox }}><PingTraceView core={core} /></NavContext.Provider>);
  expect(screen.getByLabelText("Destino")).toHaveValue("10.20.3.11");
  expect(screen.getByRole("checkbox", { name: "Traceroute" })).toBeChecked();
  expect(screen.getByRole("checkbox", { name: "Ping" })).not.toBeChecked();
  expect(screen.getByLabelText("Destino")).toBeInTheDocument();
});

test("Traceroute desde el menú y luego Ping deja marcado solo Ping", async () => {
  const core = fakeCore();
  const Wrap = ({ inbox }: { inbox: Record<string, { data: string; n: number }> }) =>
    <NavContext.Provider value={{ go: () => {}, inbox }}><PingTraceView core={core} /></NavContext.Provider>;
  const { rerender } = render(<Wrap inbox={{ ping: { data: "10.0.0.1", n: 1 }, "ping-tool": { data: "traceroute", n: 1 } }} />);
  expect(screen.getByRole("checkbox", { name: "Ping" })).not.toBeChecked();
  rerender(<Wrap inbox={{ ping: { data: "10.0.0.2", n: 2 }, "ping-tool": { data: "ping", n: 2 } }} />);
  expect(screen.getByRole("checkbox", { name: "Ping" })).toBeChecked();
  expect(screen.getByRole("checkbox", { name: "Traceroute" })).not.toBeChecked();
});
