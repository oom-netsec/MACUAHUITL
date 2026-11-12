import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ForensicView } from "./ForensicView";
import { PatternsSection } from "./PatternsSection";
import { fakeCore } from "../../lib/fake";
import { sampleMsg } from "./fake";
import type { CrashReport, DebugReport, FlappingReport, LeaksReport, LogPattern, PatternsReport } from "./api";

test("busca un mensaje y muestra su ficha con comandos de lectura", async () => {
  const core = fakeCore({ forensicMsg: vi.fn(async () => [sampleMsg()]) });
  render(<ForensicView core={core} />);
  await userEvent.type(screen.getByLabelText("Mnemónico o patrón"), " %SYS-2-MALLOCFAIL ");
  await userEvent.click(screen.getByRole("button", { name: "Buscar" }));
  expect(core.forensicMsg).toHaveBeenCalledWith("%SYS-2-MALLOCFAIL");
  const card = await screen.findByRole("region", { name: "%SYS-2-MALLOCFAIL" });
  expect(within(card).getByText(/severidad 2 crítica/)).toBeInTheDocument();
  expect(within(card).getByText("show memory statistics")).toBeInTheDocument();
  expect(within(card).getByText(/sin validar en laboratorio/)).toBeInTheDocument();
});

test("sin coincidencias lo dice, y un error del núcleo es una alerta", async () => {
  const core = fakeCore({ forensicMsg: vi.fn().mockResolvedValueOnce([]).mockRejectedValueOnce(new Error("rpc error: code = InvalidArgument desc = la consulta excede 128 caracteres")) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("button", { name: "Buscar" }));
  expect(await screen.findByText("Sin coincidencias en la base de mensajes.")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Buscar" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("la consulta excede 128 caracteres");
  expect(screen.queryByText("Sin coincidencias en la base de mensajes.")).not.toBeInTheDocument();
});

const crash: CrashReport = { kind: "crashinfo", binary: false, bytes: 900, reason: "error - a SegV exception", pc: "0x1A2B3C4", process: "IP Input", pid: 58, traceback: ["0x1A2B3C4", "0x1A2C0F8"],
  host: "sw-lab", model: "C3560CX", version: "15.2(7)E3", uptime: "2 weeks", memory: { total: 100, free: 5, free_pct: 4.7 }, messages: [sampleMsg()] };

test("crashinfo: manda el texto, o la ruta sin texto, y muestra el resumen con las fichas", async () => {
  const core = fakeCore({ forensicCrashinfo: vi.fn(async () => crash) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Crashinfo" }));
  const btn = screen.getByRole("button", { name: "Analizar" });
  expect(btn).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Texto del crashinfo"), "System returned");
  await userEvent.click(btn);
  expect(core.forensicCrashinfo).toHaveBeenLastCalledWith("System returned", "");
  expect(await screen.findByText("IP Input (pid 58)")).toBeInTheDocument();
  expect(screen.getByText("4.7% libre")).toBeInTheDocument();
  expect(screen.getByRole("region", { name: "%SYS-2-MALLOCFAIL" })).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("o ruta del archivo"), " /tmp/crashinfo_1 ");
  await userEvent.click(btn);
  expect(core.forensicCrashinfo).toHaveBeenLastCalledWith("", "/tmp/crashinfo_1");
});

test("un core binario se identifica sin tabla y con el aviso", async () => {
  const core = fakeCore({ forensicCrashinfo: vi.fn(async () => ({ kind: "core", binary: true, bytes: 10, hint: "volcado binario: abre un caso con TAC", messages: [] }) as CrashReport) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Crashinfo" }));
  await userEvent.type(screen.getByLabelText("o ruta del archivo"), "/tmp/x.core");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  expect(await screen.findByRole("status")).toHaveTextContent("abre un caso con TAC");
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
});

const pat = (over: Partial<LogPattern>): LogPattern => ({ pattern: "%LINK-3-UPDOWN: Interface <if>, changed state to down", mnemonic: "%LINK-3-UPDOWN", severity: 3, count: 9, hosts: ["192.0.2.1"], host_count: 1, example: "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down", peak: 9, episodes: 1, burst: true, unstable: false, ...over });
const prep = (patterns: LogPattern[]): PatternsReport => ({ kb: { "%LINK-3-UPDOWN": sampleMsg({ id: "%LINK-3-UPDOWN", meaning: "El enlace subió o bajó.", action: "Revisa el cable." }) }, source: "texto pegado", entries: 12, with_time: 12, patterns, burst_count: 5, burst_window: "1m0s", warnings: ["3 mensaje(s) sin hora"], stats: { lines: 12, parsed: 12, with_time: 12, skipped: 0 } });

test("syslog: pega texto, manda la fuente y el umbral, y marca ráfagas e inestabilidad", async () => {
  const core = fakeCore({ forensicPatterns: vi.fn(async () => prep([pat({ unstable: true, episodes: 2 }), pat({ pattern: "%SYS-5-CONFIG_I: x", mnemonic: "%SYS-5-CONFIG_I", count: 1, burst: false, peak: 1, episodes: 0 })])) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Syslog" }));
  const btn = screen.getByRole("button", { name: "Agrupar" });
  expect(btn).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Texto (show logging o syslog)"), "algo");
  await userEvent.clear(screen.getByLabelText("Ráfaga: mensajes"));
  await userEvent.type(screen.getByLabelText("Ráfaga: mensajes"), "7");
  await userEvent.click(btn);
  expect(core.forensicPatterns).toHaveBeenCalledWith({ text: "algo" }, 7, 60);
  const first = await screen.findByRole("group", { name: "patrón 1" });
  expect(within(first).getByText("[INESTABLE]", { exact: false })).toBeInTheDocument();
  expect(within(first).getByText(/Base de mensajes: El enlace subió o bajó\./)).toBeInTheDocument();
  expect(within(screen.getByRole("group", { name: "patrón 2" })).queryByText(/RÁFAGA|INESTABLE/)).not.toBeInTheDocument();
  expect(screen.getByText(/Aviso: 3 mensaje\(s\) sin hora/)).toBeInTheDocument();
});

test("syslog: la captura del receptor no necesita texto; un trabajo exige su ID", async () => {
  const core = fakeCore({ forensicPatterns: vi.fn(async () => prep([])) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Syslog" }));
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "job");
  expect(screen.getByRole("button", { name: "Agrupar" })).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Trabajo (ID o carpeta)"), "j1");
  await userEvent.type(screen.getByLabelText("Equipo (opcional)"), "sw1");
  await userEvent.click(screen.getByRole("button", { name: "Agrupar" }));
  expect(core.forensicPatterns).toHaveBeenLastCalledWith({ job: "j1", device: "sw1" }, 5, 60);
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "capture");
  await userEvent.click(screen.getByRole("button", { name: "Agrupar" }));
  expect(core.forensicPatterns).toHaveBeenLastCalledWith({ capture: true }, 5, 60);
});

test("syslog: el error del núcleo borra el resultado anterior", async () => {
  const core = fakeCore({ forensicPatterns: vi.fn().mockResolvedValueOnce(prep([pat({})])).mockRejectedValueOnce(new Error("rpc error: code = InvalidArgument desc = elige exactamente una fuente")) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Syslog" }));
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "capture");
  await userEvent.click(screen.getByRole("button", { name: "Agrupar" }));
  await screen.findByRole("group", { name: "patrón 1" });
  await userEvent.click(screen.getByRole("button", { name: "Agrupar" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("elige exactamente una fuente");
  expect(screen.queryByRole("group", { name: "patrón 1" })).not.toBeInTheDocument();
});

const flapRep = (over: Partial<FlappingReport> = {}): FlappingReport => ({
  kb: { "%LINK-3-UPDOWN": sampleMsg({ id: "%LINK-3-UPDOWN", action: "Revisa el cable." }) }, source: "show logging del trabajo /o/job", interfaces: 2, transitions: 8, count: 3, window: "1m0s", warnings: [],
  flaps: [{ host: "SW1_192.0.2.1", interface: "Gi0/3", layer: "link", total: 6, peak: 6, episodes: 1, sequence: "down up down up down up", mnemonic: "%LINK-3-UPDOWN" },
    { host: "SW2", interface: "Gi0/9", layer: "link", total: 4, peak: 0, episodes: 0, sequence: "down down down down", no_time: true }],
  counter_jumps: [{ host: "SW1_192.0.2.1", interface: "Gi0/3", counter: "interface resets", from_round: 1, to_round: 2, from: 1, to: 9, delta: 8, per_hour: 48 }], ...over });

test("flapping: arranca con la fuente de un trabajo, manda umbrales y muestra interfaces y saltos de contadores", async () => {
  const core = fakeCore({ forensicFlapping: vi.fn(async () => flapRep()) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Flapping" }));
  expect(screen.getByLabelText("Fuente")).toHaveValue("job");
  const btn = screen.getByRole("button", { name: "Buscar flapping" });
  expect(btn).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Trabajo (ID o carpeta)"), "/o/job");
  await userEvent.clear(screen.getByLabelText("Flapping: transiciones"));
  await userEvent.type(screen.getByLabelText("Flapping: transiciones"), "4");
  await userEvent.click(btn);
  expect(core.forensicFlapping).toHaveBeenCalledWith({ job: "/o/job", device: "" }, 4, 60, 3);
  const flaps = await screen.findByRole("table", { name: "Interfaces con flapping" });
  expect(within(flaps).getByText("down up down up down up")).toBeInTheDocument();
  expect(within(flaps).getByText("Revisa el cable.")).toBeInTheDocument();
  expect(within(flaps).getByText("sin hora")).toBeInTheDocument();
  const jumps = screen.getByRole("table", { name: "Saltos de contadores entre rondas" });
  expect(within(jumps).getByText("1 → 9 (+8)")).toBeInTheDocument();
  expect(within(jumps).getByText("48.0")).toBeInTheDocument();
});

test("flapping: sin flaps lo dice y no pinta la tabla de saltos; un error borra el resultado", async () => {
  const core = fakeCore({ forensicFlapping: vi.fn().mockResolvedValueOnce(flapRep({ flaps: [], counter_jumps: [] })).mockRejectedValueOnce(new Error("rpc error: code = FailedPrecondition desc = sin salidas")) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Flapping" }));
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "capture");
  await userEvent.click(screen.getByRole("button", { name: "Buscar flapping" }));
  expect(await screen.findByText("Ninguna interfaz con flapping.")).toBeInTheDocument();
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Buscar flapping" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("sin salidas");
  expect(screen.queryByText("Ninguna interfaz con flapping.")).not.toBeInTheDocument();
});

const dbg: DebugReport = { lines: 70, blank: 2, hidden: 6, noise: ["cdp-pa"], groups_total: 3,
  groups: [{ pattern: "OSPF-<n> ADJ   <if>: Rcv hello from <ip>", count: 60, example: "x" }, { pattern: "OSPF-<n> ADJ   <if>: Nbr <ip> is dead", count: 1, example: "y" }],
  anomalies: [{ line: 68, text: "OSPF-1 ADJ Gi0/1: Nbr 10.0.0.2 is dead", reason: "rara dentro de una familia frecuente; contiene una palabra de alarma", family: "OSPF-<n>", family_count: 62 }] };

test("debugs: manda el ruido línea por línea, los umbrales y muestra anomalías y patrones", async () => {
  const core = fakeCore({ forensicDebugs: vi.fn(async () => dbg) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Debugs" }));
  const btn = screen.getByRole("button", { name: "Filtrar" });
  expect(btn).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Texto del debug"), "OSPF-1 ADJ");
  await userEvent.type(screen.getByLabelText("Ruido a ocultar (un texto por línea)"), "cdp-pa{Enter}  {Enter}ntp");
  await userEvent.click(btn);
  expect(core.forensicDebugs).toHaveBeenCalledWith("OSPF-1 ADJ", "", ["cdp-pa", "ntp"], 20, 2, 0);
  expect(await screen.findByText(/70 línea\(s\): 6 ocultas por ruido/)).toBeInTheDocument();
  expect(screen.getByText(/Línea 68/)).toBeInTheDocument();
  const t = screen.getByRole("table", { name: "Patrones más frecuentes" });
  expect(within(t).getByText("60")).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("o ruta del archivo"), "/tmp/d.txt");
  await userEvent.click(btn);
  expect(core.forensicDebugs).toHaveBeenLastCalledWith("", "/tmp/d.txt", ["cdp-pa", "ntp"], 20, 2, 0);
});

test("debugs: sin anomalías lo dice; un error borra el resultado", async () => {
  const core = fakeCore({ forensicDebugs: vi.fn().mockResolvedValueOnce({ ...dbg, anomalies: [] }).mockRejectedValueOnce(new Error("rpc error: code = InvalidArgument desc = la ruta del archivo debe ser absoluta")) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Debugs" }));
  await userEvent.type(screen.getByLabelText("o ruta del archivo"), "d.txt");
  await userEvent.click(screen.getByRole("button", { name: "Filtrar" }));
  expect(await screen.findByText("Sin anomalías.")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Filtrar" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("debe ser absoluta");
  expect(screen.queryByText("Sin anomalías.")).not.toBeInTheDocument();
});

const leakRep: LeaksReport = { job: "/o/job", processes: 12, min_rounds: 3, min_growth: 1048576, warnings: ["SW2: solo 2 ronda(s)"],
  leaks: [{ host: "SW1_192.0.2.1", process: "BGP Router", pid: 312, rounds: 3, from_round: 1, to_round: 3, series: [10485760, 12582912, 15728640], growth: 5242880, per_hour: 2621440 }] };

test("memoria: pide el trabajo con los umbrales y muestra el proceso con su serie", async () => {
  const core = fakeCore({ forensicLeaks: vi.fn(async () => leakRep) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Memoria" }));
  const btn = screen.getByRole("button", { name: "Buscar fugas" });
  expect(btn).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Trabajo o carpeta"), " /o/job ");
  await userEvent.clear(screen.getByLabelText("Rondas seguidas sin bajar"));
  await userEvent.type(screen.getByLabelText("Rondas seguidas sin bajar"), "4");
  await userEvent.click(btn);
  expect(core.forensicLeaks).toHaveBeenCalledWith("/o/job", "", 4, 1024);
  const t = await screen.findByRole("table", { name: "Procesos con memoria creciente" });
  expect(within(t).getByText("+5.0 MiB")).toBeInTheDocument();
  expect(within(t).getByText("10.0 MiB → 12.0 MiB → 15.0 MiB")).toBeInTheDocument();
  expect(screen.getByText(/Aviso: SW2: solo 2 ronda/)).toBeInTheDocument();
});

test("memoria: sin fugas lo dice y un error borra el resultado", async () => {
  const core = fakeCore({ forensicLeaks: vi.fn().mockResolvedValueOnce({ ...leakRep, leaks: [] }).mockRejectedValueOnce(new Error("rpc error: code = FailedPrecondition desc = el trabajo aún no tiene salidas")) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Memoria" }));
  await userEvent.type(screen.getByLabelText("Trabajo o carpeta"), "j1");
  await userEvent.click(screen.getByRole("button", { name: "Buscar fugas" }));
  expect(await screen.findByText("Ningún proceso con memoria creciente.")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Buscar fugas" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("aún no tiene salidas");
  expect(screen.queryByText("Ningún proceso con memoria creciente.")).not.toBeInTheDocument();
});

test("syslog en vivo: con la captura y la casilla marcada vuelve a leerla sola; al desmarcar o salir se detiene", async () => {
  const core = fakeCore({ forensicPatterns: vi.fn(async () => prep([])) });
  const { unmount } = render(<PatternsSection core={core} refreshMs={20} />);
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "capture");
  await userEvent.click(screen.getByLabelText(/En vivo: releer la captura/));
  await waitFor(() => expect(vi.mocked(core.forensicPatterns).mock.calls.length).toBeGreaterThanOrEqual(3));
  await userEvent.click(screen.getByLabelText(/En vivo: releer la captura/));
  await new Promise((r) => setTimeout(r, 60)); // deja terminar una lectura en curso
  const n = vi.mocked(core.forensicPatterns).mock.calls.length;
  await new Promise((r) => setTimeout(r, 100));
  expect(vi.mocked(core.forensicPatterns).mock.calls.length).toBe(n);
  await userEvent.click(screen.getByLabelText(/En vivo: releer la captura/));
  await waitFor(() => expect(vi.mocked(core.forensicPatterns).mock.calls.length).toBeGreaterThan(n));
  unmount();
  await new Promise((r) => setTimeout(r, 60));
  const m = vi.mocked(core.forensicPatterns).mock.calls.length;
  await new Promise((r) => setTimeout(r, 100));
  expect(vi.mocked(core.forensicPatterns).mock.calls.length).toBe(m);
});

test("syslog en vivo: no apila peticiones (con una en curso se salta el tic) y pide solo el final de la captura", async () => {
  let enVuelo = 0, maxVuelo = 0;
  const core = fakeCore({
    forensicPatterns: vi.fn(async () => { enVuelo++; maxVuelo = Math.max(maxVuelo, enVuelo); await new Promise((r) => setTimeout(r, 120)); enVuelo--; return prep([]); }),
  });
  const { unmount } = render(<PatternsSection core={core} refreshMs={10} />);
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "capture");
  await userEvent.click(screen.getByLabelText(/En vivo: releer la captura/));
  await waitFor(() => expect(vi.mocked(core.forensicPatterns).mock.calls.length).toBeGreaterThanOrEqual(2), { timeout: 2000 });
  expect(maxVuelo).toBe(1);
  expect(vi.mocked(core.forensicPatterns).mock.calls[0][0]).toEqual({ capture: true, max_kib: 4096 });
  unmount();
});

test("syslog: sin el modo en vivo la captura se pide entera", async () => {
  const core = fakeCore({ forensicPatterns: vi.fn(async () => prep([])) });
  render(<PatternsSection core={core} />);
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "capture");
  await userEvent.click(screen.getByRole("button", { name: "Agrupar" }));
  await waitFor(() => expect(core.forensicPatterns).toHaveBeenCalledWith({ capture: true }, 5, 60));
});

test("syslog en vivo: la casilla solo aparece con la captura del receptor", async () => {
  render(<PatternsSection core={fakeCore()} />);
  expect(screen.queryByLabelText(/En vivo/)).not.toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "capture");
  expect(screen.getByLabelText("En vivo: releer la captura cada 10 s")).not.toBeChecked();
});

test("syslog en vivo: al cambiar a otra fuente deja de releer aunque la casilla siga marcada", async () => {
  const core = fakeCore({ forensicPatterns: vi.fn(async () => prep([])) });
  render(<PatternsSection core={core} refreshMs={20} />);
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "path");
  await userEvent.type(screen.getByLabelText("Ruta absoluta del archivo"), "/tmp/syslog.log");
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "capture");
  await userEvent.click(screen.getByLabelText(/En vivo: releer la captura/));
  await waitFor(() => expect(vi.mocked(core.forensicPatterns).mock.calls.length).toBeGreaterThanOrEqual(1));
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "path");
  await new Promise((r) => setTimeout(r, 60));
  const n = vi.mocked(core.forensicPatterns).mock.calls.length;
  await new Promise((r) => setTimeout(r, 100));
  expect(vi.mocked(core.forensicPatterns).mock.calls.length).toBe(n);
});

test("cada herramienta dice qué hacer antes del primer análisis", async () => {
  render(<ForensicView core={fakeCore()} />);
  expect(screen.getByText("Sin análisis todavía")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("tab", { name: "Memoria" }));
  expect(screen.getByText(/Indicar un trabajo de Patrol con varias rondas/)).toBeInTheDocument();
});

test("syslog: con cientos de patrones dibuja los primeros y pide «Mostrar más» para el resto", async () => {
  const many = Array.from({ length: 250 }, (_, i) => pat({ pattern: `%X-1-Y${i}`, mnemonic: undefined, count: 250 - i }));
  const core = fakeCore({ forensicPatterns: vi.fn(async () => prep(many)) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Syslog" }));
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "capture");
  await userEvent.click(screen.getByRole("button", { name: "Agrupar" }));
  await screen.findByRole("group", { name: "patrón 1" });
  expect(screen.getAllByRole("group", { name: /^patrón / })).toHaveLength(100);
  await userEvent.click(screen.getByRole("button", { name: "Mostrar más (150 restantes)" }));
  expect(screen.getAllByRole("group", { name: /^patrón / })).toHaveLength(200);
});

test("memoria: con miles de procesos solo se dibujan las filas visibles", async () => {
  const leaks = Array.from({ length: 1500 }, (_, i) => ({ host: "SW1", process: `P${i}`, pid: i, rounds: 3, from_round: 1, to_round: 3, series: [1, 2, 3], growth: 2 << 20, per_hour: 1 << 20 }));
  const core = fakeCore({ forensicLeaks: vi.fn(async () => ({ ...leakRep, leaks })) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Memoria" }));
  await userEvent.type(screen.getByLabelText("Trabajo o carpeta"), "j1");
  await userEvent.click(screen.getByRole("button", { name: "Buscar fugas" }));
  const table = await screen.findByRole("table", { name: "Procesos con memoria creciente" });
  expect(table).toHaveAttribute("aria-rowcount", "1501");
  expect(within(table).getAllByRole("row").length).toBeLessThan(100);
});
