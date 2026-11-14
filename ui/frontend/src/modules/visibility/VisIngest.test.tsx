import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { VisibilityView } from "./VisibilityView";
import { fakeCore } from "../../lib/fake";
import { sampleSyslogDrops } from "../tools/fake";
import { I18nProvider } from "../../lib/i18n";

// Opciones, estado, descartes y juntado de eventos de traps y flujos: las mismas piezas que syslog, con los defaults de cada uno.
const trapMsg = (n: number, extra: object = {}) => JSON.stringify({ From: `10.0.0.${n % 250}:5000`, Name: "linkDown", Summary: `linkDown Gi1/0/${n}`, ...extra });
const snap = (flows: number) => JSON.stringify({ Flows: flows, Bytes: flows * 100, Talkers: [], Conversations: [], Ports: [], Protocols: [], Exporters: [] });

async function setup(tab: "Traps" | "Flujos", over: Record<string, unknown> = {}) {
  const core = fakeCore({ trapsStart: vi.fn(async () => "t1"), flowsStart: vi.fn(async () => "f1"), ...over });
  render(<VisibilityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: tab }));
  return core;
}
const listen = () => userEvent.click(screen.getByRole("button", { name: "Escuchar" }));
const openOpts = () => userEvent.click(screen.getByText("Opciones"));
const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 160)); });

test("traps: sin tocar las opciones se pide la escucha con {} y con lo escrito, solo eso", async () => {
  const core = await setup("Traps");
  await listen();
  expect(core.trapsStart).toHaveBeenCalledWith("127.0.0.1:1162", false, false, "", "SHA", "AES", {});
  act(() => core.emitVis("traps", { runId: "t1", done: true }));
  await openOpts();
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  await userEvent.type(screen.getByLabelText("Tasa por origen (traps/s)"), "50");
  await userEvent.type(screen.getByLabelText("Archivos que se conservan"), "5");
  await userEvent.selectOptions(screen.getByLabelText("Formato"), "jsonl");
  await userEvent.type(screen.getByLabelText("Plantilla del nombre"), "cap_{{fecha}");
  await listen();
  expect(core.trapsStart).toHaveBeenLastCalledWith("127.0.0.1:1162", false, true, "", "SHA", "AES", { ratePerSource: 50, maxFiles: 5, format: "jsonl", nameTemplate: "cap_{fecha}" });
});

test("flujos: el top sigue siendo un argumento y las opciones van al final", async () => {
  const core = await setup("Flujos");
  await listen();
  expect(core.flowsStart).toHaveBeenCalledWith("127.0.0.1:2055", false, false, 10, {});
  act(() => core.emitVis("flows", { runId: "f1", done: true }));
  await userEvent.click(screen.getByLabelText("Guardar cada flujo en archivo"));
  await openOpts();
  await userEvent.type(screen.getByLabelText("Tasa global (datagramas/s)"), "9000");
  await listen();
  expect(core.flowsStart).toHaveBeenLastCalledWith("127.0.0.1:2055", false, true, 10, { rateGlobal: 9000 });
});

test("traps: defaults de syslog en tasa y plantilla propia con su ejemplo", async () => {
  await setup("Traps");
  await openOpts();
  expect(screen.getByLabelText("Tasa por origen (traps/s)")).toHaveAccessibleDescription("Por defecto 100 · Rango 1 a 10000.");
  expect(screen.getByLabelText("Tasa global (traps/s)")).toHaveAccessibleDescription("Por defecto 1000 · Rango 1 a 100000.");
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  expect(screen.getByLabelText("Plantilla del nombre")).toHaveAttribute("placeholder", "traps_{fecha}_{hora}");
  expect(screen.getByText(/^Ejemplo: traps_\d{8}_\d{6}\.log$/)).toBeInTheDocument();
  expect(screen.getByText(/IP del agente/)).toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText("Formato"), "jsonl");
  expect(screen.getByText(/^Ejemplo: traps_\d{8}_\d{6}\.jsonl$/)).toBeInTheDocument();
});

test("flujos: defaults de 1000 por exportador y 5000 global, plantilla flujos_ y la tasa cuenta datagramas", async () => {
  await setup("Flujos");
  await userEvent.click(screen.getByLabelText("Guardar cada flujo en archivo"));
  await openOpts();
  expect(screen.getByLabelText("Tasa por exportador (datagramas/s)")).toHaveAccessibleDescription("Por defecto 1000 · Rango 1 a 10000.");
  expect(screen.getByLabelText("Tasa global (datagramas/s)")).toHaveAccessibleDescription("Por defecto 5000 · Rango 1 a 100000.");
  expect(screen.getByLabelText("Tasa global (datagramas/s)")).toHaveAttribute("placeholder", "5000");
  expect(screen.getByText(/La tasa cuenta datagramas de exportación/)).toBeInTheDocument();
  expect(screen.getByLabelText("Plantilla del nombre")).toHaveAttribute("placeholder", "flujos_{fecha}_{hora}");
  expect(screen.getByText(/^Ejemplo: flujos_\d{8}_\d{6}\.log$/)).toBeInTheDocument();
  expect(screen.getByText(/IP del exportador/)).toBeInTheDocument();
});

test("flujos: sin guardar en archivo no hay tope, así que no hay campos de tasa ni se mandan", async () => {
  const core = await setup("Flujos");
  await openOpts();
  await userEvent.click(screen.getByLabelText("Guardar cada flujo en archivo"));
  await userEvent.type(screen.getByLabelText("Tasa global (datagramas/s)"), "9000");
  await userEvent.click(screen.getByLabelText("Guardar cada flujo en archivo"));
  expect(screen.queryByLabelText("Tasa global (datagramas/s)")).not.toBeInTheDocument();
  expect(screen.getByText(/no hay tope ni descartes/)).toBeInTheDocument();
  await listen();
  expect(core.flowsStart).toHaveBeenCalledWith("127.0.0.1:2055", false, false, 10, {});
});

test("valida en línea como syslog: marca el campo y no inicia", async () => {
  const core = await setup("Traps");
  await openOpts();
  await userEvent.type(screen.getByLabelText("Tasa por origen (traps/s)"), "0");
  await listen();
  expect(core.trapsStart).not.toHaveBeenCalled();
  expect(screen.getByLabelText("Tasa por origen (traps/s)")).toHaveAccessibleDescription(/Debe estar entre 1 y 10000/);
  expect(screen.getByRole("alert")).toHaveTextContent("No se inició");
});

test("traps: la línea de estado cuenta lo recibido y sigue el archivo actual (rotatedPath)", async () => {
  const core = await setup("Traps");
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  await listen();
  act(() => core.emitVis("traps", { runId: "t1", listening: "127.0.0.1:1162", outputPath: "/home/x/outputs/snmp-traps" }));
  expect(screen.getByText("Archivo actual: aún ninguno (se crea con el primer trap)")).toBeInTheDocument();
  act(() => {
    core.emitVis("traps", { runId: "t1", rotatedPath: "/home/x/outputs/snmp-traps/traps_20261107_091500.log" });
    core.emitVis("traps", { runId: "t1", json: trapMsg(1) });
    core.emitVis("traps", { runId: "t1", json: trapMsg(2) });
  });
  await flush();
  const st = screen.getByRole("group", { name: "Estado de la escucha" });
  expect(st).toHaveTextContent("Traps recibidos en la app: 2");
  expect(st).toHaveTextContent("Archivo actual: traps_20261107_091500.log");
});

test("traps: con {origen} dice que hay un archivo por origen en la carpeta", async () => {
  const core = await setup("Traps");
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  await openOpts();
  await userEvent.type(screen.getByLabelText("Plantilla del nombre"), "t_{{origen}_{{hora}");
  await listen();
  act(() => core.emitVis("traps", { runId: "t1", listening: "127.0.0.1:1162", outputPath: "/home/x/outputs/snmp-traps" }));
  expect(screen.getByRole("group", { name: "Estado de la escucha" })).toHaveTextContent("Un archivo por origen en /home/x/outputs/snmp-traps");
});

test("traps: descartes en la región viva con frase fija y las cifras y el top fuera", async () => {
  const core = await setup("Traps");
  await listen();
  act(() => core.emitVis("traps", { runId: "t1", listening: "127.0.0.1:1162" }));
  const since = new Date(2026, 10, 7, 9, 5, 3).getTime();
  act(() => core.emitVis("traps", { runId: "t1", drops: { ...sampleSyslogDrops, sinceMs: since } }));
  const live = screen.getByText("Se están descartando traps por exceso de tasa");
  expect(live).toHaveAttribute("role", "status");
  expect(live.textContent).not.toMatch(/\d/);
  expect(screen.getByText(/Se descartaron/)).toHaveTextContent("Se descartaron 1200 traps (por origen 1100, global 80, cola llena 20) desde 09:05:03");
  const rows = within(screen.getByRole("table", { name: "Orígenes con más descartes" })).getAllByRole("row");
  expect(rows[1]).toHaveTextContent("10.0.0.9");
});

test("flujos: descartes en datagramas con exportadores y rotatedPath como archivo actual", async () => {
  const core = await setup("Flujos");
  await userEvent.click(screen.getByLabelText("Guardar cada flujo en archivo"));
  await listen();
  act(() => core.emitVis("flows", { runId: "f1", listening: "127.0.0.1:2055", outputPath: "/home/x/outputs/flows" }));
  act(() => {
    core.emitVis("flows", { runId: "f1", rotatedPath: "/home/x/outputs/flows/flujos_20261107_091500.log" });
    core.emitVis("flows", { runId: "f1", drops: sampleSyslogDrops });
  });
  expect(screen.getByText("Se están descartando datagramas por exceso de tasa")).toHaveAttribute("role", "status");
  expect(screen.getByText(/Se descartaron/)).toHaveTextContent("Se descartaron 1200 datagramas de exportación (por exportador 1100");
  expect(screen.getByRole("table", { name: "Exportadores con más descartes" })).toBeInTheDocument();
  expect(screen.getByRole("group", { name: "Estado de la escucha" })).toHaveTextContent("Archivo actual: flujos_20261107_091500.log");
});

test("un error de inicio que llega como done{error} se marca junto a su campo y abre las opciones (traps)", async () => {
  const core = await setup("Traps");
  await listen();
  act(() => core.emitVis("traps", { runId: "t1", done: true, error: "rpc error: code = InvalidArgument desc = la cola debe estar entre 64 y 65536 (0 = default), no 70000" }));
  expect(screen.getByText("Opciones").closest("details")).toHaveAttribute("open");
  expect(screen.getByLabelText("Cola de escritura")).toHaveAccessibleDescription(/la cola debe estar entre 64 y 65536/);
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Escuchar" })).toBeEnabled();
});

test("un done{error} de dirección marca la dirección y uno sin campo va en un aviso (flujos)", async () => {
  const core = await setup("Flujos");
  await listen();
  act(() => core.emitVis("flows", { runId: "f1", done: true, error: "rpc error: code = InvalidArgument desc = flows: dirección de escucha inválida \"x\": address x: missing port in address" }));
  expect(screen.getByLabelText("Dirección de escucha")).toHaveAccessibleDescription(/dirección de escucha inválida/);
  expect(screen.getByText("Opciones").closest("details")).not.toHaveAttribute("open");
  await listen();
  act(() => core.emitVis("flows", { runId: "f1", done: true, error: "rpc error: code = Internal desc = no se pudo crear la carpeta de salida: permiso denegado" }));
  expect(screen.getByRole("alert")).toHaveTextContent("permiso denegado");
});

test("un rechazo del inicio con un campo fuera de rango (flujos) también se marca junto al campo", async () => {
  await setup("Flujos", { flowsStart: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = la tasa global debe estar entre 1 y 100000 (0 = default), no 200000"); }) });
  await userEvent.click(screen.getByLabelText("Guardar cada flujo en archivo"));
  await listen();
  expect(screen.getByLabelText("Tasa global (datagramas/s)")).toHaveAccessibleDescription(/la tasa global debe estar entre 1 y 100000/);
});

test("mientras escucha, las opciones y guardar en archivo quedan deshabilitadas", async () => {
  const core = await setup("Traps");
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  await listen();
  act(() => core.emitVis("traps", { runId: "t1", listening: "127.0.0.1:1162" }));
  await openOpts();
  expect(screen.getByLabelText("Cola de escritura")).toBeDisabled();
  expect(screen.getByLabelText("Guardar en archivo")).toBeDisabled();
});

test("flujos: los resúmenes se juntan; solo el último se pinta cada ~100 ms y el conteo lo sigue", async () => {
  const core = await setup("Flujos");
  await listen();
  act(() => {
    core.emitVis("flows", { runId: "f1", json: snap(5) });
    core.emitVis("flows", { runId: "f1", json: snap(7) });
    core.emitVis("flows", { runId: "f1", json: snap(9) });
  });
  expect(screen.queryByText(/9 flujos ·/)).not.toBeInTheDocument(); // aún no se vuelca
  await flush();
  expect(screen.getByText(/9 flujos ·/)).toBeInTheDocument();
  expect(screen.getByRole("group", { name: "Estado de la escucha" })).toHaveTextContent("Flujos contados en la app: 9");
});

test("traps: una ráfaga se junta y la lista queda acotada con el conteo completo y el aviso", async () => {
  const core = await setup("Traps");
  await listen();
  act(() => { for (let i = 0; i < 6000; i++) core.emitVis("traps", { runId: "t1", json: trapMsg(i) }); });
  expect(screen.getByRole("group", { name: "Estado de la escucha" })).toHaveTextContent("Traps recibidos en la app: 0");
  await flush();
  expect(screen.getByRole("group", { name: "Estado de la escucha" })).toHaveTextContent("Traps recibidos en la app: 6000");
  expect(screen.getByText(/Se muestran los últimos 5000 traps; los anteriores ya no están/)).toBeInTheDocument();
});

test("traps: un v3 sin decodificar se ve con la etiqueta traducida y el motivo del núcleo", async () => {
  const core = await setup("Traps");
  await listen();
  act(() => core.emitVis("traps", { runId: "t1", json: JSON.stringify({ From: "10.0.0.2:5000", Version: "3", Error: "v3 sin decodificar (87 bytes): usuario USM desconocido" }) }));
  await flush();
  expect(await screen.findByRole("cell", { name: "v3 sin decodificar (87 bytes): usuario USM desconocido" })).toBeInTheDocument();
});

test("en inglés el v3 muestra solo la etiqueta traducida: el motivo del núcleo (en español) no se mezcla", async () => {
  localStorage.setItem("macuahuitl.lang", "en");
  try {
    const core = fakeCore({ trapsStart: vi.fn(async () => "t1") });
    render(<I18nProvider><VisibilityView core={core} /></I18nProvider>);
    await userEvent.click(screen.getByRole("tab", { name: "Traps" }));
    await userEvent.click(screen.getByRole("button", { name: "Listen" }));
    act(() => core.emitVis("traps", { runId: "t1", json: JSON.stringify({ From: "10.0.0.2:5000", Version: "3", Error: "v3 sin decodificar (87 bytes): usuario USM desconocido" }) }));
    await flush();
    expect(await screen.findByRole("cell", { name: "v3 undecoded (87 bytes)" })).toBeInTheDocument();
    expect(screen.queryByText(/usuario USM desconocido/)).not.toBeInTheDocument();
  } finally {
    localStorage.removeItem("macuahuitl.lang");
  }
});
