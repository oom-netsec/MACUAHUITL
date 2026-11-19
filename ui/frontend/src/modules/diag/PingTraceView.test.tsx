import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PingTraceView } from "./PingTraceView";
import { fakeCore } from "../../lib/fake";
import { I18nProvider, useSetLang } from "../../lib/i18n";
import { CoreContext, NavContext } from "../../app/activity";
import type { CoreAPI } from "../../lib/core";
import { setOSForTests } from "../../lib/platform";

const made: unknown[][] = [];
vi.mock("uplot", () => ({
  default: class {
    constructor(_o: unknown, d: unknown[][]) { made.push(d); }
    setSize() {} destroy() {} setData() {}
    get ctx() { return { canvas: { toDataURL: () => "" } }; }
  },
}));

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

// Movidas desde DiagView al quitarle ping y traceroute.
test("ping: el destino tiene su ayuda, «Paquetes» se manda y la ruta del archivo sale al terminar", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  expect(screen.getByLabelText("Destino")).toHaveAccessibleDescription("Nombre de host o dirección IP.");
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.clear(screen.getByLabelText("Paquetes"));
  await userEvent.type(screen.getByLabelText("Paquetes"), "6");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("ping", ["10.0.0.1"], { count: "6" }));
  act(() => core.emitDiag({ runId: "r1", done: true, exitCode: 0, outputPath: "/home/u/out/diag_ping_x.txt" }));
  expect(await screen.findByText(/diag_ping_x\.txt/)).toBeInTheDocument();
});

test("Ejecutar nombra el destino que falta y deja de hacerlo al escribirlo", async () => {
  render(<PingTraceView core={fakeCore()} />);
  const go = () => screen.getByRole("button", { name: "Ejecutar" });
  expect(go()).toBeDisabled();
  expect(go()).toHaveAccessibleDescription("Falta: indicar el equipo.");
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  expect(go()).toBeEnabled();
  expect(go()).not.toHaveAccessibleDescription();
});

test("cancelar no es un fallo: estado «Cancelado» y sin mensaje de error", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await userEvent.click(await screen.findByRole("button", { name: "Detener ping" }));
  expect(core.diagCancel).toHaveBeenCalledWith("r1");
  act(() => core.emitDiag({ runId: "r1", done: true, exitCode: -1, canceled: true }));
  expect(await screen.findByText("Cancelado")).toBeInTheDocument();
  expect(screen.getByText("Cancelado por el usuario.")).toBeInTheDocument();
  expect(screen.queryByText(/Con error|Error:/)).not.toBeInTheDocument();
});

test("dos clics seguidos en Ejecutar no lanzan dos ejecuciones", async () => {
  const core = fakeCore({ diagRun: vi.fn(() => new Promise<string>(() => {})) });
  render(<PingTraceView core={core} />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  const run = screen.getByRole("button", { name: /Ejecutar/ });
  await userEvent.click(run);
  await userEvent.click(run);
  expect(core.diagRun).toHaveBeenCalledTimes(1);
});

test("500 líneas seguidas llegan en orden y done no pierde las pendientes del lote", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalled());
  act(() => {
    for (let i = 0; i < 500; i++) core.emitDiag({ runId: "r1", line: `fila-${i}` });
    core.emitDiag({ runId: "r1", done: true, exitCode: 0 });
  });
  const rows = (screen.getByRole("log", { name: "Ping" }).textContent ?? "").split("\n").filter((x) => x.startsWith("fila-"));
  expect(rows).toHaveLength(500);
  expect(rows[0]).toBe("fila-0");
  expect(rows[499]).toBe("fila-499");
});

test("Copiar solo aparece con salida; copia el texto completo y anuncia Copiado", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<CoreContext.Provider value={core as unknown as CoreAPI}><PingTraceView core={core} /></CoreContext.Provider>);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await screen.findByRole("log", { name: "Ping" });
  expect(screen.queryByRole("button", { name: "Copiar Ping" })).not.toBeInTheDocument();
  act(() => { core.emitDiag({ runId: "r1", line: "linea uno" }); core.emitDiag({ runId: "r1", line: "linea dos" }); });
  await userEvent.click(await screen.findByRole("button", { name: "Copiar Ping" }));
  expect(core.copyText).toHaveBeenCalledWith("linea uno\nlinea dos");
  expect(await screen.findByText("Copiado")).toBeInTheDocument();
});

test("ping: gráfica de RTT en vivo y cifras de mín, prom, máx, jitter y pérdida", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await screen.findByRole("log", { name: "Ping" });
  act(() => ["64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.4 ms", "64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=0.5 ms",
    "no answer yet for icmp_seq=3", "64 bytes from 10.0.0.1: icmp_seq=4 ttl=64 time=0.3 ms"].forEach((line) => core.emitDiag({ runId: "r1", line })));
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
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  await userEvent.click(screen.getByRole("checkbox", { name: "Ping" }));
  await userEvent.click(screen.getByRole("checkbox", { name: "Traceroute" }));
  await userEvent.type(screen.getByLabelText("Destino"), "8.8.8.8");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await screen.findByRole("log", { name: "Traceroute" });
  act(() => ["traceroute to dns.google (8.8.8.8), 30 hops max, 60 byte packets", " 1  _gateway (192.168.1.1)  0.412 ms  0.388 ms  0.401 ms",
    " 2  * * *", " 3  dns.google (8.8.8.8)  14.2 ms  13.9 ms  14.8 ms"].forEach((line) => core.emitDiag({ runId: "r1", line })));
  const rows = within(await screen.findByRole("table", { name: "Saltos" })).getAllByRole("row");
  expect(rows).toHaveLength(4);
  expect(within(rows[1]).getByRole("meter", { name: "RTT del salto 1" })).toHaveAttribute("aria-valuenow", "0.4");
  expect(within(rows[3]).getByRole("meter", { name: "RTT del salto 3" })).toHaveAttribute("aria-valuenow", "14.3");
  expect(rows[2]).toHaveAttribute("data-state", "bad");
  expect(within(rows[2]).getByText("Sin respuesta")).toBeInTheDocument();
  expect(within(rows[2]).queryByRole("meter")).not.toBeInTheDocument();
});

test("traceroute: «Saltos máximos» va plegado, cuenta y se sigue enviando; destino queda fuera", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  await userEvent.click(screen.getByRole("checkbox", { name: "Ping" }));
  await userEvent.click(screen.getByRole("checkbox", { name: "Traceroute" }));
  const d = screen.getByLabelText("Saltos máximos").closest("details")!;
  expect(d.open).toBe(false);
  expect(d).not.toContainElement(screen.getByLabelText("Destino"));
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.clear(screen.getByLabelText("Saltos máximos"));
  await userEvent.type(screen.getByLabelText("Saltos máximos"), "12");
  expect(d.querySelector("summary")).toHaveTextContent("cambiadas: 1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("traceroute", ["10.0.0.1"], { max_hops: "12" }));
});

test("el eje de tiempo del ping escala con el intervalo elegido", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByText("Opciones extendidas"));
  await userEvent.type(screen.getByLabelText("Intervalo (0.2-60 s)"), "5");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalled());
  act(() => ["1", "2", "3"].forEach((q) => core.emitDiag({ runId: "r1", line: `64 bytes from 10.0.0.1: icmp_seq=${q} ttl=64 time=0.4 ms` })));
  await screen.findByRole("figure", { name: "RTT por paquete" });
  const times = made.at(-1)![0] as number[];
  expect(times.map((x) => x - times[0])).toEqual([0, 5, 10]);
});

test("un evento posterior al cambio de idioma se escribe en el idioma vigente", async () => {
  const Switch = () => { const set = useSetLang(); return <button onClick={() => set("en")}>a-en</button>; };
  const core = fakeCore({ diagRun: ids() });
  render(<I18nProvider><Switch /><PingTraceView core={core} /></I18nProvider>);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: /Ejecutar/ }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalled());
  await userEvent.click(screen.getByRole("button", { name: "a-en" }));
  act(() => core.emitDiag({ runId: "r1", done: true, exitCode: -1, canceled: true }));
  expect(await screen.findByText("Canceled by the user.")).toBeInTheDocument();
});

// Ping extendido (#200, contrato en #218)
const openExt = async () => userEvent.click(screen.getByText("Opciones extendidas"));
const pingView = async (over = {}) => {
  const core = fakeCore({ diagRun: ids(), ...over });
  render(<PingTraceView core={core} />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  return core;
};

test("ping extendido: sección cerrada con el número de opciones activas; manda solo las claves con valor", async () => {
  const core = await pingView();
  const sum = screen.getByText("Opciones extendidas").closest("details")!;
  expect(sum).not.toHaveAttribute("open");
  await openExt();
  await userEvent.type(screen.getByLabelText("TTL (1-255)"), "5");
  await userEvent.click(screen.getByLabelText("No fragmentar (DF)"));
  expect(sum).toHaveTextContent("2 activas");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("ping", ["10.0.0.1"], { count: "4", ttl: "5", df: "true" }));
});

test("ping extendido: valor fuera de rango muestra el mensaje y no deja ejecutar", async () => {
  await pingView();
  await openExt();
  await userEvent.type(screen.getByLabelText("TTL (1-255)"), "300");
  expect(screen.getByLabelText("TTL (1-255)")).toBeInvalid();
  expect(screen.getByText("El TTL va de 1 a 255.")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Ejecutar" })).toBeDisabled();
});

test("en Windows se ocultan intervalo y DSCP", async () => {
  setOSForTests("windows");
  try {
    await pingView();
    await openExt();
    expect(screen.queryByLabelText("Intervalo (0.2-60 s)")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("DSCP (0-63)")).not.toBeInTheDocument();
    expect(screen.getByLabelText("TTL (1-255)")).toBeInTheDocument();
  } finally { setOSForTests(undefined); }
});

test("continuo: Detener ping usa diagStop; NotFound al detener no muestra error y Cancelar ping sigue cortando", async () => {
  const diagStop = vi.fn().mockRejectedValue(Object.assign(new Error("x"), { cause: { code: "NotFound", reason: "run.notfound" } }));
  const core = await pingView({ diagStop });
  await openExt();
  await userEvent.click(screen.getByLabelText("Continuo (hasta detener)"));
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("ping", ["10.0.0.1"], { continuous: "true" }));
  await userEvent.click(await screen.findByRole("button", { name: "Detener ping" }));
  expect(diagStop).toHaveBeenCalledWith("r1");
  await act(async () => {});
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Cancelar ping" }));
  expect(core.diagCancel).toHaveBeenCalledWith("r1");
});

test("Cancelar ping desaparece al terminar el ping continuo y si el arranque falla", async () => {
  const core = await pingView();
  await openExt();
  await userEvent.click(screen.getByLabelText("Continuo (hasta detener)"));
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await screen.findByRole("button", { name: "Cancelar ping" });
  act(() => core.emitDiag({ runId: "r1", done: true, exitCode: 0 }));
  await waitFor(() => expect(screen.queryByRole("button", { name: "Cancelar ping" })).not.toBeInTheDocument());
});

test("Cancelar ping no aparece si diagRun falla", async () => {
  await pingView({ diagRun: vi.fn().mockRejectedValue(new Error("boom")) });
  await openExt();
  await userEvent.click(screen.getByLabelText("Continuo (hasta detener)"));
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await screen.findByRole("alert");
  expect(screen.queryByRole("button", { name: "Cancelar ping" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Detener ping" })).toBeDisabled();
});

test("paquetes inválido se ve con la sección cerrada; otros errores salen en el resumen", async () => {
  await pingView();
  await userEvent.clear(screen.getByLabelText("Paquetes"));
  expect(screen.getByLabelText("Paquetes")).toBeInvalid();
  expect(screen.getByText("Los paquetes van de 1 a 100.")).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("Paquetes"), "4");
  await openExt();
  await userEvent.type(screen.getByLabelText("TTL (1-255)"), "300");
  expect(screen.getByText("Opciones extendidas").closest("summary")).toHaveTextContent("1 con error");
});

test("con barrido, Paquetes pasa a 1 hasta que el usuario lo toca", async () => {
  await pingView();
  await openExt();
  await userEvent.type(screen.getByLabelText("Inicio"), "0");
  expect(screen.getByLabelText("Paquetes")).toHaveValue(1);
});

test("MTU: con familia Auto y un nombre de host no hay cifra, solo el aviso", async () => {
  const core = fakeCore({ diagRun: ids() });
  render(<PingTraceView core={core} />);
  await userEvent.type(screen.getByLabelText("Destino"), "router.example");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalled());
  act(() => {
    core.emitDiag({ runId: "r1", sweepPoint: { size: 1400, sent: 1, received: 1, result: "ok" } });
    core.emitDiag({ runId: "r1", sweepPoint: { size: 1500, sent: 1, received: 0, result: "frag" } });
  });
  expect(await screen.findByText(/No se puede estimar la MTU/)).toBeInTheDocument();
  expect(screen.queryByText(/MTU estimada de la ruta/)).not.toBeInTheDocument();
});

test("también se detiene con duración, y un error distinto de NotFound se muestra", async () => {
  await pingView({ diagStop: vi.fn().mockRejectedValue(new Error("boom")) });
  await openExt();
  await userEvent.type(screen.getByLabelText("Duración total (1-3600 s)"), "30");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await userEvent.click(await screen.findByRole("button", { name: "Detener ping" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("boom");
});

test("resumen y barrido: tarjeta, tabla ordenada y MTU estimada", async () => {
  const core = await pingView();
  await openExt();
  await userEvent.type(screen.getByLabelText("Inicio"), "1400");
  await userEvent.type(screen.getByLabelText("Fin"), "1500");
  await userEvent.type(screen.getByLabelText("Paso"), "50");
  expect(screen.getByText("3 puntos (máximo 100)")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("ping", ["10.0.0.1"], { count: "1", sweep_start: "1400", sweep_end: "1500", sweep_step: "50" }));
  act(() => {
    core.emitDiag({ runId: "r1", sweepPoint: { size: 1500, sent: 4, received: 0, result: "frag" } });
    core.emitDiag({ runId: "r1", sweepPoint: { size: 1400, sent: 4, received: 4, result: "ok" } });
    core.emitDiag({ runId: "r1", sweepPoint: { size: 1450, sent: 4, received: 4, result: "ok" } });
    core.emitDiag({ runId: "r1", done: true, exitCode: 0, pingSummary: { sent: 12, received: 8, lossPct: 33.33, minMs: 1, avgMs: 2, maxMs: 3.5, mdevMs: 0.7 } });
  });
  const table = await screen.findByRole("table", { name: "Barrido de tamaños" });
  expect([...table.querySelectorAll("tbody th")].map((x) => x.textContent)).toEqual(["1400", "1450", "1500"]);
  expect(screen.getByText(/MTU estimada de la ruta: 1478/)).toBeInTheDocument();
  expect(screen.getByText(/Es una estimación/)).toBeInTheDocument();
  const sum = screen.getByRole("region", { name: "Resumen del ping" });
  expect(sum).toHaveTextContent("Enviados12");
  expect(sum).toHaveTextContent("33.33 %");
  expect(sum).toHaveTextContent("Desviación (mdev)0.7 ms");
});

test("si el núcleo rechaza una opción en Windows se muestra su texto con la clave", async () => {
  const diagRun = vi.fn().mockRejectedValue(Object.assign(new Error("x"), { cause: { code: "InvalidArgument", reason: "diag.err.opt_windows", metadata: { key: "tos" } } }));
  await pingView({ diagRun });
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Esta opción no está disponible en Windows: tos");
});
