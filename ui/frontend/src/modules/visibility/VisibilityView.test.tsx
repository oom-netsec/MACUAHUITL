import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { VisibilityView } from "./VisibilityView";
import { fakeCore } from "../../lib/fake";
import { CoreContext } from "../../app/activity";
import type { CoreAPI } from "../../lib/core";

// jsdom no tiene canvas: uPlot se sustituye y se revisan las opciones y los datos que recibe.
const made: { opts: Record<string, unknown>; data: unknown[][] }[] = [];
vi.mock("uplot", () => ({
  default: class {
    entry: { opts: Record<string, unknown>; data: unknown[][] };
    constructor(opts: Record<string, unknown>, data: unknown[][]) { this.entry = { opts, data }; made.push(this.entry); }
    setSize() {} destroy() {} setData(d: unknown[][]) { this.entry.data = d; } // los datos en vivo llegan por setData
    get ctx() { return { canvas: { toDataURL: () => "data:image/png;base64,QUJD" } }; }
  },
}));
beforeEach(() => { made.length = 0; });

const creds = [{ id: "c1", label: "snmp-lab", username: "snmp", hasEnable: false, hasSshKey: false }];

test("topología: construye desde una carpeta, dibuja el SVG y ofrece exportar", async () => {
  const core = fakeCore({ topoBuild: vi.fn(async () => ({ text: "Hallazgos:\n  [error] VLAN nativa distinta", json: '{"nodes":[]}', svg: '<svg xmlns="http://www.w3.org/2000/svg"></svg>' })) });
  render(<VisibilityView core={core} />);
  await userEvent.type(screen.getByLabelText(/Trabajo o carpeta/), "/home/x/outputs/caso_20261104");
  await userEvent.click(screen.getByRole("button", { name: "Construir" }));
  expect(core.topoBuild).toHaveBeenCalledWith("/home/x/outputs/caso_20261104", "");
  // La salida va resaltada (palabras clave en <span>): se busca en el <pre> completo.
  expect(await screen.findByText((_, el) => el?.tagName === "PRE" && /VLAN nativa distinta/.test(el.textContent ?? ""))).toBeInTheDocument();
  expect(screen.getByRole("img", { name: "Topología" }).getAttribute("src")).toMatch(/^data:image\/svg\+xml/);
  expect(screen.getByRole("link", { name: "Exportar SVG" })).toHaveAttribute("download", "topologia.svg");
  expect(screen.getByRole("link", { name: "Exportar JSON" })).toHaveAttribute("download", "topologia.json");
});

test("snmp: get con la credencial de la bóveda y sondeo en vivo", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), snmpGet: vi.fn(async () => ".1.3.6.1.2.1.1.5.0 = OctetString: SW1"), snmpPollStart: vi.fn(async () => "p1") });
  render(<VisibilityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "SNMP" }));
  await userEvent.type(screen.getByLabelText("Equipo"), "10.0.0.1");
  await screen.findByRole("option", { name: "snmp-lab (snmp)" });
  await userEvent.selectOptions(screen.getByLabelText(/Credencial/), "c1");
  await userEvent.type(screen.getByLabelText(/OID/), "1.3.6.1.2.1.1.5.0");
  await userEvent.click(screen.getByRole("button", { name: "Get" }));
  expect(await screen.findByText(/OctetString: SW1/)).toBeInTheDocument();
  expect(core.snmpGet).toHaveBeenCalledWith({ host: "10.0.0.1", port: 161, version: "2c", credentialId: "c1", auth: "SHA", priv: "AES" }, ["1.3.6.1.2.1.1.5.0"]);
  await userEvent.click(screen.getByRole("button", { name: "Sondear" }));
  expect(core.snmpPollStart).toHaveBeenCalledWith(expect.objectContaining({ host: "10.0.0.1" }), ["sistema", "interfaces"], 10);
  act(() => core.emitVis("snmp", { runId: "p1", json: JSON.stringify({ Time: "2026-11-04T10:00:00Z", Interfaces: [{ Name: "Gi1/0/1", Oper: "up", InBps: 2500000, OutBps: null }] }) }));
  expect(await screen.findByRole("row", { name: /Gi1\/0\/1/ })).toHaveTextContent("2.50 Mb/s");
});

test("traps: escucha en 1162, muestra solo su ejecución y se detiene", async () => {
  const core = fakeCore({ trapsStart: vi.fn(async () => "t1") });
  render(<VisibilityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Traps" }));
  await userEvent.click(screen.getByRole("button", { name: "Escuchar" }));
  expect(core.trapsStart).toHaveBeenCalledWith("127.0.0.1:1162", false, false, "", "SHA", "AES", {});
  act(() => {
    core.emitVis("traps", { runId: "t1", listening: "127.0.0.1:1162" });
    core.emitVis("traps", { runId: "t1", json: JSON.stringify({ From: "10.0.0.2:5000", Name: "linkDown", Summary: "linkDown GigabitEthernet1/0/7 oper down" }) });
    core.emitVis("traps", { runId: "otro", json: JSON.stringify({ Name: "ajeno" }) });
  });
  expect(await screen.findByRole("cell", { name: /GigabitEthernet1\/0\/7 oper down/ })).toBeInTheDocument();
  expect(screen.queryByRole("cell", { name: /ajeno/ })).not.toBeInTheDocument();
  expect(screen.getByText(/escuchando en 127.0.0.1:1162/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Detener" }));
  expect(core.diagCancel).toHaveBeenCalledWith("t1");
  act(() => core.emitVis("traps", { runId: "t1", done: true }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Escuchar" })).toBeEnabled());
});

test("flujos: muestra top talkers del resumen en vivo", async () => {
  const core = fakeCore({ flowsStart: vi.fn(async () => "f1") });
  render(<VisibilityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Flujos" }));
  await userEvent.click(screen.getByRole("button", { name: "Escuchar" }));
  expect(core.flowsStart).toHaveBeenCalledWith("127.0.0.1:2055", false, false, 10, {});
  act(() => core.emitVis("flows", { runId: "f1", json: JSON.stringify({ Flows: 3, Bytes: 6000, Talkers: [{ Key: "10.0.0.1", Bytes: 6000, Packets: 5, Flows: 2 }], Conversations: [], Ports: [], Protocols: [], Exporters: [] }) }));
  expect(await screen.findByRole("list", { name: "Top talkers" })).toHaveTextContent(/10\.0\.0\.1.*5\.9 KiB/);
  expect(screen.getByText(/3 flujos/)).toBeInTheDocument();
});

const poll = (time: string, ins: (number | null)[]) => JSON.stringify({ Time: time, Interfaces: ins.map((v, i) => ({ Name: `Gi1/0/${i + 1}`, Oper: v == null ? "down" : "up", InBps: v, OutBps: v == null ? null : 1_000_000 })) });

test("snmp: el sondeo en vivo grafica entrada y salida por interfaz, con el cursor sincronizado por sondeo y un resumen en texto", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), snmpPollStart: vi.fn(async () => "p1") });
  render(<VisibilityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "SNMP" }));
  await userEvent.type(screen.getByLabelText("Equipo"), "10.0.0.1");
  await screen.findByRole("option", { name: "snmp-lab (snmp)" });
  await userEvent.selectOptions(screen.getByLabelText(/Credencial/), "c1");
  await userEvent.click(screen.getByRole("button", { name: "Sondear" }));
  act(() => core.emitVis("snmp", { runId: "p1", json: poll("2026-11-04T10:00:00Z", [2_000_000, null]) }));
  act(() => core.emitVis("snmp", { runId: "p1", json: poll("2026-11-04T10:00:10Z", [4_000_000, null]) }));
  const fig = await screen.findByRole("figure", { name: "Gi1/0/1 entrada y salida" });
  expect(fig).toHaveTextContent("Entrada: mín 2 Mb/s, prom 3 Mb/s, máx 4 Mb/s, último 4 Mb/s");
  await waitFor(() => expect(made.length).toBeGreaterThan(0));
  const last = made[made.length - 1];
  expect((last.opts.cursor as { sync: { key: string } }).sync.key).toBe("snmp-p1");
  await waitFor(() => expect(last.data[0]).toHaveLength(2));
  // La interfaz caída no se grafica sola, pero se puede pedir.
  expect(screen.queryByRole("figure", { name: "Gi1/0/2 entrada y salida" })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Graficar Gi1/0/2" }));
  expect(await screen.findByRole("figure", { name: "Gi1/0/2 entrada y salida" })).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Graficar Gi1/0/1" }));
  expect(screen.queryByRole("figure", { name: "Gi1/0/1 entrada y salida" })).not.toBeInTheDocument();
});

test("snmp: cada fila lleva su minigráfica de tendencia de entrada", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), snmpPollStart: vi.fn(async () => "p1") });
  render(<VisibilityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "SNMP" }));
  await userEvent.type(screen.getByLabelText("Equipo"), "10.0.0.1");
  await screen.findByRole("option", { name: "snmp-lab (snmp)" });
  await userEvent.selectOptions(screen.getByLabelText(/Credencial/), "c1");
  await userEvent.click(screen.getByRole("button", { name: "Sondear" }));
  act(() => core.emitVis("snmp", { runId: "p1", json: poll("2026-11-04T10:00:00Z", [2_000_000]) }));
  act(() => core.emitVis("snmp", { runId: "p1", json: poll("2026-11-04T10:00:10Z", [6_000_000]) }));
  const row = await screen.findByRole("row", { name: /Gi1\/0\/1/ });
  expect(within(row).getByRole("img", { name: /Gi1\/0\/1.*mín 2.*máx 6/ })).toBeInTheDocument();
});

test("flujos: los principales emisores van en barras ordenadas, con el valor en texto y copiar IP", async () => {
  const core = fakeCore({ flowsStart: vi.fn(async () => "f1") });
  render(<CoreContext.Provider value={core as unknown as CoreAPI}><VisibilityView core={core} /></CoreContext.Provider>);
  await userEvent.click(screen.getByRole("tab", { name: "Flujos" }));
  await userEvent.click(screen.getByRole("button", { name: "Escuchar" }));
  const talkers = [{ Key: "10.0.0.7", Bytes: 1000, Packets: 5, Flows: 1 }, { Key: "10.0.0.5", Bytes: 6000, Packets: 9, Flows: 2 }, { Key: "10.0.0.6", Bytes: 3000, Packets: 7, Flows: 1 }];
  act(() => core.emitVis("flows", { runId: "f1", json: JSON.stringify({ Flows: 4, Bytes: 10000, Talkers: talkers, Conversations: [], Ports: [], Protocols: [], Exporters: [] }) }));
  const list = await screen.findByRole("list", { name: "Top talkers" });
  const items = within(list).getAllByRole("listitem");
  expect(items.map((i) => /10\.0\.0\.\d/.exec(i.textContent ?? "")?.[0])).toEqual(["10.0.0.5", "10.0.0.6", "10.0.0.7"]);
  expect(items[0]).toHaveTextContent("5.9 KiB");
  expect(items[0]).toHaveTextContent("60 %");
  expect(within(items[0]).getByRole("meter", { name: "10.0.0.5" })).toHaveAttribute("aria-valuenow", "6000");
  await userEvent.click(within(items[0]).getByRole("button", { name: "Copiar IP 10.0.0.5" }));
  expect(core.copyText).toHaveBeenCalledWith("10.0.0.5");
});

test("traps: la bitácora es una tabla con severidad en texto y se puede filtrar", async () => {
  const core = fakeCore({ trapsStart: vi.fn(async () => "t1") });
  render(<VisibilityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Traps" }));
  await userEvent.click(screen.getByRole("button", { name: "Escuchar" }));
  act(() => {
    core.emitVis("traps", { runId: "t1", json: JSON.stringify({ From: "10.0.0.2:5000", Name: "linkDown", Summary: "linkDown Gi1/0/7 oper down" }) });
    core.emitVis("traps", { runId: "t1", json: JSON.stringify({ From: "10.0.0.3:5001", Name: "linkUp", Summary: "linkUp Gi1/0/9 oper up" }) });
    core.emitVis("traps", { runId: "t1", json: JSON.stringify({ From: "10.0.0.4:5002", Name: "coldStart", Summary: "coldStart" }) });
  });
  const table = await screen.findByRole("table", { name: "Eventos" });
  expect(await within(table).findByText("3 · Error")).toBeInTheDocument(); // los traps se vuelcan cada ~100 ms
  expect(within(table).getByText("6 · Informativo")).toBeInTheDocument();
  expect(within(table).getByText("5 · Notificación")).toBeInTheDocument();
  await userEvent.type(screen.getByRole("textbox", { name: "Buscar en la tabla" }), "Gi1/0/7");
  expect(within(table).getAllByRole("row")).toHaveLength(2); // encabezado + 1
  expect(within(table).getByRole("cell", { name: /Gi1\/0\/7 oper down/ })).toBeInTheDocument();
});

test("gnmi: get y suscripción con actualizaciones en vivo", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), gnmiGet: vi.fn(async () => '[{"Path":"/system"}]'), gnmiSubscribeStart: vi.fn(async () => "g1") });
  render(<VisibilityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "gNMI" }));
  await userEvent.type(screen.getByLabelText("Equipo"), "10.0.0.9");
  await userEvent.clear(screen.getByLabelText(/Rutas/));
  await userEvent.type(screen.getByLabelText(/Rutas/), "/system/memory/state");
  await userEvent.click(screen.getByRole("button", { name: "Get" }));
  expect(core.gnmiGet).toHaveBeenCalledWith({ host: "10.0.0.9", port: 9339, credentialId: "", caPath: "", serverName: "" }, ["/system/memory/state"], "");
  await userEvent.click(screen.getByRole("button", { name: "Suscribir" }));
  expect(core.gnmiSubscribeStart).toHaveBeenCalledWith(expect.objectContaining({ host: "10.0.0.9" }), ["/system/memory/state"], "sample", 10);
  act(() => core.emitVis("gnmi", { runId: "g1", json: JSON.stringify({ Path: "/system/memory/state/used", Value: 1234 }) }));
  expect(await screen.findByText(/\/system\/memory\/state\/used = 1234/)).toBeInTheDocument();
});

test("cambiar de pestaña con una escucha de traps en curso no pierde la vista, el Detener ni lo recibido", async () => {
  const core = fakeCore({ trapsStart: vi.fn(async () => "t1") });
  render(<VisibilityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Traps" }));
  await userEvent.click(screen.getByRole("button", { name: "Escuchar" }));
  expect(await screen.findByRole("tab", { name: "Traps · en curso" })).toBeInTheDocument(); // el estado va en texto, no solo en color
  await userEvent.click(screen.getByRole("tab", { name: "Flujos" }));
  expect(screen.getByRole("button", { name: "Detener" })).toBeDisabled(); // el visible es el de Flujos; el de Traps sigue vivo, oculto
  act(() => core.emitVis("traps", { runId: "t1", json: JSON.stringify({ From: "10.0.0.2:5000", Name: "linkDown", Summary: "linkDown GigabitEthernet1/0/9 oper down" }) }));
  expect(screen.getByRole("tab", { name: "Traps · en curso" })).toBeInTheDocument();
  await userEvent.click(screen.getByRole("tab", { name: "Traps · en curso" }));
  expect(await screen.findByRole("cell", { name: /GigabitEthernet1\/0\/9 oper down/ })).toBeInTheDocument(); // llegó con la pestaña oculta
  const stop = screen.getByRole("button", { name: "Detener" });
  expect(stop).toBeEnabled();
  await userEvent.click(stop);
  expect(core.diagCancel).toHaveBeenCalledWith("t1"); // sigue siendo la misma ejecución
  expect(core.trapsStart).toHaveBeenCalledTimes(1);
  act(() => core.emitVis("traps", { runId: "t1", done: true }));
  expect(await screen.findByRole("tab", { name: "Traps" })).toBeInTheDocument(); // sin «en curso»
});

test("un sondeo SNMP en curso sigue al volver de otra pestaña y marca su pestaña", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), snmpPollStart: vi.fn(async () => "p1") });
  render(<VisibilityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "SNMP" }));
  await userEvent.type(screen.getByLabelText("Equipo"), "10.0.0.1");
  await screen.findByRole("option", { name: "snmp-lab (snmp)" });
  await userEvent.selectOptions(screen.getByLabelText(/Credencial/), "c1");
  await userEvent.click(screen.getByRole("button", { name: "Sondear" }));
  expect(await screen.findByRole("tab", { name: "SNMP · en curso" })).toBeInTheDocument();
  await userEvent.click(screen.getByRole("tab", { name: "gNMI" }));
  await userEvent.click(screen.getByRole("tab", { name: "SNMP · en curso" }));
  expect(screen.getByRole("button", { name: "Detener" })).toBeEnabled();
  expect(core.snmpPollStart).toHaveBeenCalledTimes(1);
});
