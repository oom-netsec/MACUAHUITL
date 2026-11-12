import { Profiler } from "react";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SyslogPanel } from "./ToolsView";
import { fakeCore } from "../../lib/fake";
import { sampleSyslogDrops } from "./fake";

const msg = (n: number) => JSON.stringify({ Time: "2026-11-06T18:00:00Z", From: `10.0.0.${n % 250}:514`, Severity: 6, Mnemonic: "SYS-6-X", Text: `evento ${n}` });

function setup(start = vi.fn(async () => "s1")) {
  const core = fakeCore({ syslogStart: start });
  render(<SyslogPanel core={core} />);
  return core;
}
const listen = () => userEvent.click(screen.getByRole("button", { name: "Escuchar" }));
// Los mensajes se juntan y se vuelcan a la lista cada ~100 ms.
const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 160)); });
const openOpts = () => userEvent.click(screen.getByText("Opciones"));

test("sin tocar las opciones se pide la escucha con los defaults ({})", async () => {
  const core = setup();
  await listen();
  expect(core.syslogStart).toHaveBeenCalledWith("127.0.0.1:5514", "udp", false, false, {});
});

test("las opciones están en un bloque plegado con los defaults como marcador", async () => {
  setup();
  const d = screen.getByText("Opciones").closest("details")!;
  expect(d).not.toHaveAttribute("open");
  await openOpts();
  expect(d).toHaveAttribute("open");
  expect(screen.getByLabelText("Tasa por origen (msg/s)")).toHaveAttribute("placeholder", "100");
  expect(screen.getByLabelText("Tasa global (msg/s)")).toHaveAttribute("placeholder", "1000");
  expect(screen.getByLabelText("Cola de escritura")).toHaveAttribute("placeholder", "4096");
  expect(screen.getByLabelText("Ráfaga por origen")).toHaveAttribute("placeholder", "2× la tasa");
});

test("cada campo dice su default y su rango, y los numéricos piden teclado numérico", async () => {
  setup();
  await openOpts();
  expect(screen.getByLabelText("Tasa por origen (msg/s)")).toHaveAccessibleDescription("Por defecto 100 · Rango 1 a 10000.");
  expect(screen.getByLabelText("Ráfaga global")).toHaveAccessibleDescription("Por defecto 2× la tasa · Rango 1 a 1000000.");
  expect(screen.getByLabelText("Cola de escritura")).toHaveAttribute("inputmode", "numeric");
  expect(screen.getByLabelText("Dirección de escucha")).not.toHaveAttribute("inputmode");
});

test("manda solo lo que se cambió", async () => {
  const core = setup();
  await openOpts();
  await userEvent.type(screen.getByLabelText("Tasa por origen (msg/s)"), "50");
  await userEvent.type(screen.getByLabelText("Cola de escritura"), "8192");
  await listen();
  expect(core.syslogStart).toHaveBeenCalledWith("127.0.0.1:5514", "udp", false, false, { ratePerSource: 50, queueSize: 8192 });
});

test("el grupo Archivos solo aparece con «Guardar en archivo» y sus opciones se mandan", async () => {
  const core = setup();
  await openOpts();
  expect(screen.queryByText("Archivos")).not.toBeInTheDocument();
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  expect(screen.getByText("Archivos")).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("Rotar cada (MB)"), "10");
  await userEvent.type(screen.getByLabelText("Rotar cada (minutos)"), "30");
  await userEvent.type(screen.getByLabelText("Archivos que se conservan"), "5");
  await userEvent.selectOptions(screen.getByLabelText("Formato"), "jsonl");
  await listen();
  expect(core.syslogStart).toHaveBeenCalledWith("127.0.0.1:5514", "udp", false, true, { rotateMb: 10, rotateMinutes: 30, maxFiles: 5, format: "jsonl" });
});

test("el formato elegido explica en una línea qué guarda", async () => {
  setup();
  await openOpts();
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  expect(screen.getByLabelText("Formato")).toHaveAccessibleDescription(/hora, origen y mensaje/);
  await userEvent.selectOptions(screen.getByLabelText("Formato"), "crudo");
  expect(screen.getByLabelText("Formato")).toHaveAccessibleDescription(/solo el mensaje/i);
});

test("la plantilla muestra en vivo el nombre que resulta y los tokens", async () => {
  setup();
  await openOpts();
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  const tpl = screen.getByLabelText("Plantilla del nombre");
  expect(screen.getByText(/^Ejemplo: syslog_\d{8}_\d{6}\.log$/)).toBeInTheDocument();
  expect(tpl).toHaveAccessibleDescription(/\{fecha\}.*\{hora\}.*\{origen\}/);
  await userEvent.type(tpl, "cap_{{origen}_{{fecha}");
  await userEvent.selectOptions(screen.getByLabelText("Formato"), "jsonl");
  expect(screen.getByText(/^Ejemplo: cap_10\.0\.0\.9_\d{8}\.jsonl$/)).toBeInTheDocument();
});

test("valida en línea: marca el campo, abre las opciones y no inicia", async () => {
  const core = setup();
  await openOpts();
  await userEvent.type(screen.getByLabelText("Cola de escritura"), "10");
  await userEvent.type(screen.getByLabelText("Tasa global (msg/s)"), "abc");
  expect(screen.getByLabelText("Cola de escritura")).toHaveAccessibleDescription(/Debe estar entre 64 y 65536/);
  expect(screen.getByLabelText("Tasa global (msg/s)")).toHaveAccessibleDescription(/número entero/);
  expect(screen.getByLabelText("Cola de escritura")).toBeInvalid();
  await listen();
  expect(core.syslogStart).not.toHaveBeenCalled();
  expect(screen.getByRole("alert")).toHaveTextContent("No se inició: corrige los campos marcados.");
});

test("valida la plantilla con la regla del núcleo", async () => {
  setup();
  await openOpts();
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  await userEvent.type(screen.getByLabelText("Plantilla del nombre"), "../{{fecha}");
  expect(screen.getByLabelText("Plantilla del nombre")).toHaveAccessibleDescription(/letras, dígitos/);
});

test("un error de inicio que nombra un campo se muestra junto a ese campo y abre las opciones", async () => {
  const core = setup(vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = syslogd: la cola debe estar entre 64 y 65536 (0 = default), no 70000"); }));
  await listen();
  expect(core.syslogStart).toHaveBeenCalled();
  expect(screen.getByText("Opciones").closest("details")).toHaveAttribute("open");
  expect(screen.getByLabelText("Cola de escritura")).toHaveAccessibleDescription(/la cola debe estar entre 64 y 65536/);
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

test("un error de inicio que no nombra campo va en un aviso", async () => {
  setup(vi.fn(async () => { throw new Error("syslogd: archivo de salida: permiso denegado"); }));
  await listen();
  expect(screen.getByRole("alert")).toHaveTextContent("permiso denegado");
});

test("con la escucha activa, el conteo y el archivo actual se actualizan con cada evento", async () => {
  const core = setup();
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  await listen();
  act(() => core.emitSyslog({ runId: "s1", listening: "127.0.0.1:5514", outputPath: "/home/u/outputs/syslog" }));
  const bar = screen.getByRole("group", { name: "Estado de la escucha" });
  expect(bar).toHaveTextContent("Archivo actual: aún ninguno");
  act(() => { core.emitSyslog({ runId: "s1", json: msg(1) }); core.emitSyslog({ runId: "s1", json: msg(2) }); });
  act(() => core.emitSyslog({ runId: "s1", rotatedPath: "/home/u/outputs/syslog/syslog_20261107_120000.log" }));
  await flush();
  expect(bar).toHaveTextContent("Recibidos en la app: 2");
  expect(bar).toHaveTextContent("Archivo actual: syslog_20261107_120000.log");
  act(() => core.emitSyslog({ runId: "s1", rotatedPath: "/home/u/outputs/syslog/syslog_20261107_130000.log" }));
  expect(bar).toHaveTextContent("Archivo actual: syslog_20261107_130000.log");
});

test("con {origen} en la plantilla la línea dice que hay un archivo por origen en la carpeta", async () => {
  const core = setup();
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  await openOpts();
  await userEvent.type(screen.getByLabelText("Plantilla del nombre"), "{{origen}_{{fecha}");
  await listen();
  act(() => core.emitSyslog({ runId: "s1", listening: "127.0.0.1:5514", outputPath: "/home/u/outputs/syslog" }));
  const bar = screen.getByRole("group", { name: "Estado de la escucha" });
  expect(bar).toHaveTextContent("Un archivo por origen en /home/u/outputs/syslog; último creado: ninguno todavía");
  act(() => core.emitSyslog({ runId: "s1", rotatedPath: "/home/u/outputs/syslog/10.0.0.9_20261107.log" }));
  expect(bar).toHaveTextContent("último creado: 10.0.0.9_20261107.log");
  expect(bar).not.toHaveTextContent("Archivo actual");
});

test("con {origen} la estimación de disco suma los archivos abiertos a la vez", async () => {
  setup();
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  await openOpts();
  expect(screen.getByText(/^Tope aproximado en disco: 1000 MB\.$/)).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("Plantilla del nombre"), "{{origen}_{{fecha}");
  expect(screen.getByText(/Tope aproximado en disco: 1000 MB.*hasta 64 archivos abiertos.*3.1 GB/)).toBeInTheDocument();
});

test("la región viva solo dice una frase fija; las cifras y la hora van fuera y se actualizan", async () => {
  const core = setup();
  await listen();
  act(() => core.emitSyslog({ runId: "s1", listening: "127.0.0.1:5514" }));
  expect(screen.queryByText(/Se descartaron/)).not.toBeInTheDocument();
  const since = new Date(2026, 10, 7, 9, 5, 3).getTime();
  act(() => core.emitSyslog({ runId: "s1", drops: { ...sampleSyslogDrops, sinceMs: since } }));
  const live = screen.getByText("Se están descartando mensajes por exceso de tasa");
  expect(live).toHaveAttribute("role", "status");
  expect(live.textContent).not.toMatch(/\d/);
  const detail = screen.getByText(/Se descartaron/);
  expect(detail.closest("[role=status]")).toBeNull();
  expect(detail).toHaveTextContent("Se descartaron 1200 mensajes (por origen 1100, global 80, cola llena 20) desde 09:05:03");
  act(() => core.emitSyslog({ runId: "s1", drops: { ...sampleSyslogDrops, total: 1500, porOrigen: 1400, sinceMs: since } }));
  expect(screen.getAllByText(/Se descartaron/)).toHaveLength(1);
  expect(detail).toHaveTextContent("Se descartaron 1500 mensajes (por origen 1400");
  expect(screen.getAllByText("Se están descartando mensajes por exceso de tasa")).toHaveLength(1);
});

test("el top de orígenes que descartaron se despliega como tabla", async () => {
  const core = setup();
  await listen();
  act(() => core.emitSyslog({ runId: "s1", drops: sampleSyslogDrops }));
  const table = screen.getByRole("table", { name: "Orígenes con más descartes" });
  const rows = within(table).getAllByRole("row");
  expect(rows).toHaveLength(3);
  expect(rows[1]).toHaveTextContent("10.0.0.9");
  expect(rows[1]).toHaveTextContent("1100");
  expect(rows[2]).toHaveTextContent("otros");
});

test("la lista en pantalla tiene tope, el conteo sigue y avisa qué pasa con los archivos", async () => {
  const core = setup();
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  await openOpts();
  await userEvent.type(screen.getByLabelText("Archivos que se conservan"), "7");
  await listen();
  act(() => { for (let i = 0; i < 5300; i++) core.emitSyslog({ runId: "s1", json: msg(i) }); });
  await flush();
  const bar = screen.getByRole("group", { name: "Estado de la escucha" });
  expect(bar).toHaveTextContent("Recibidos en la app: 5300");
  expect(await screen.findByText("Todas (5000)")).toBeInTheDocument();
  expect(screen.getByText("Se muestran los últimos 5000 mensajes; los archivos guardan todo lo recibido (salvo los que borra la retención al pasar de 7 archivos).")).toBeInTheDocument();
});

test("una ráfaga de 2000 eventos se junta: pocos renders y la lista final correcta y acotada", async () => {
  const core = fakeCore({ syslogStart: vi.fn(async () => "s1") });
  const renders = vi.fn();
  render(<Profiler id="syslog" onRender={renders}><SyslogPanel core={core} /></Profiler>);
  await listen();
  renders.mockClear();
  for (let i = 0; i < 2000; i++) act(() => core.emitSyslog({ runId: "s1", json: msg(i) })); // cada evento en su propio turno, como llegan del puente
  expect(renders).not.toHaveBeenCalled(); // nada se pinta mientras llega la ráfaga
  await flush();
  expect(renders.mock.calls.length).toBeLessThanOrEqual(3);
  expect(await screen.findByText("Todas (2000)")).toBeInTheDocument();
  expect(screen.getByRole("group", { name: "Estado de la escucha" })).toHaveTextContent("Recibidos en la app: 2000");
});

test("un error de inicio que llega como done{error} se marca junto al campo y abre las opciones", async () => {
  const core = setup();
  await listen();
  act(() => core.emitSyslog({ runId: "s1", done: true, error: "rpc error: code = InvalidArgument desc = syslogd: la cola debe estar entre 64 y 65536 (0 = default), no 70000" }));
  expect(screen.getByText("Opciones").closest("details")).toHaveAttribute("open");
  expect(screen.getByLabelText("Cola de escritura")).toHaveAccessibleDescription(/la cola debe estar entre 64 y 65536/);
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Escuchar" })).toBeEnabled();
});

test("un done{error} de dirección marca la dirección sin abrir las opciones", async () => {
  const core = setup();
  await listen();
  act(() => core.emitSyslog({ runId: "s1", done: true, error: "rpc error: code = InvalidArgument desc = syslogd: el puerto 80 es privilegiado; usa uno alto" }));
  expect(screen.getByLabelText("Dirección de escucha")).toHaveAccessibleDescription(/el puerto 80 es privilegiado/);
  expect(screen.getByText("Opciones").closest("details")).not.toHaveAttribute("open");
});

test("un done{error} de dirección con errorInfo muestra el texto del núcleo, que dice qué hacer", async () => {
  const core = setup();
  await listen();
  act(() => core.emitSyslog({ runId: "s1", done: true, error: "rpc error: code = InvalidArgument desc = syslogd: port 514 is privileged; use a high one (e.g. 5514)",
    errorInfo: { code: "InvalidArgument", reason: "ingest.invalid", metadata: { field: "addr", port: "514" } } }));
  expect(screen.getByLabelText("Dirección de escucha")).toHaveAccessibleDescription("port 514 is privileged; use a high one (e.g. 5514)");
});

test("un done{error} que no nombra campo va en un aviso", async () => {
  const core = setup();
  await listen();
  act(() => core.emitSyslog({ runId: "s1", done: true, error: "rpc error: code = Unknown desc = syslogd: archivo de salida: disco lleno" }));
  expect(screen.getByRole("alert")).toHaveTextContent("archivo de salida: disco lleno");
});

test("mientras escucha, las opciones y «Guardar en archivo» quedan deshabilitadas con su ayuda", async () => {
  const core = setup();
  await userEvent.click(screen.getByLabelText("Guardar en archivo"));
  await listen();
  act(() => core.emitSyslog({ runId: "s1", listening: "127.0.0.1:5514" }));
  expect(screen.getByLabelText("Guardar en archivo")).toBeDisabled();
  await openOpts();
  for (const l of ["Tasa por origen (msg/s)", "Cola de escritura", "Rotar cada (MB)", "Plantilla del nombre", "Formato"]) expect(screen.getByLabelText(l)).toBeDisabled();
  expect(screen.getAllByText(/Detén la escucha para cambiarlas/).length).toBeGreaterThan(0);
  act(() => core.emitSyslog({ runId: "s1", done: true }));
  expect(screen.getByLabelText("Guardar en archivo")).toBeEnabled();
  expect(screen.getByLabelText("Cola de escritura")).toBeEnabled();
});
