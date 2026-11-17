import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DiagView } from "./DiagView";
import { fakeCore } from "../../lib/fake";
import { I18nProvider, useSetLang } from "../../lib/i18n";
import { setOSForTests } from "../../lib/platform";

test("ejecuta ping, muestra la salida en vivo y la ruta al terminar", async () => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r1") });
  render(<DiagView core={core} tool="ping" />);
  expect(screen.getByRole("heading", { name: "Ping" })).toBeInTheDocument();
  expect(screen.getByLabelText("Destino")).toHaveAccessibleDescription("Nombre de host o dirección IP.");
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.clear(screen.getByLabelText("Paquetes"));
  await userEvent.type(screen.getByLabelText("Paquetes"), "6");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("ping", ["10.0.0.1"], { count: "6" }));
  act(() => core.emitDiag({ runId: "r1", line: "64 bytes from 10.0.0.1" }));
  act(() => core.emitDiag({ runId: "otro", line: "no es mío" }));
  expect(await screen.findByRole("log", { name: "Salida" })).toHaveTextContent(/64 bytes from 10\.0\.0\.1/);
  expect(screen.queryByText(/no es mío/)).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Cancelar" }));
  expect(core.diagCancel).toHaveBeenCalledWith("r1");
  act(() => core.emitDiag({ runId: "r1", done: true, exitCode: 0, outputPath: "/home/u/out/diag_ping_x.txt" }));
  expect(await screen.findByText(/diag_ping_x\.txt/)).toBeInTheDocument();
});

test("la captura pide interfaz y manda el filtro tal cual", async () => {
  const core = fakeCore({
    diagRun: vi.fn(async () => "r2"),
    listInterfaces: vi.fn(async () => [
      { name: "eth0", up: true, loopback: false, addresses: ["192.0.2.10/24"], hardwareAddr: "00:11:22:33:44:55" },
      { name: "wlan0", up: false, loopback: false, addresses: [], hardwareAddr: "" },
    ]),
  });
  render(<DiagView core={core} tool="pcap" />);
  const iface = screen.getByLabelText("Interfaz");
  expect(iface).toHaveValue("any");
  expect(await screen.findByRole("option", { name: "eth0 · 192.0.2.10/24" })).toBeInTheDocument();
  expect(screen.getByRole("option", { name: "wlan0 · inactiva" })).toBeInTheDocument();
  await userEvent.selectOptions(iface, "eth0");
  await userEvent.type(screen.getByLabelText("Filtro BPF"), "tcp port 22");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("pcap", [], expect.objectContaining({ interface: "eth0", filter: "tcp port 22" })));
});

test("un fallo inmediato (herramienta no instalada) no deja la vista atorada", async () => {
  let resolveRun: (id: string) => void = () => {};
  const core = fakeCore({ diagRun: vi.fn(() => new Promise<string>((r) => { resolveRun = r; })) });
  render(<DiagView core={core} tool="nmap" />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  // El evento llega antes de que la promesa del ID se resuelva.
  act(() => core.emitDiag({ runId: "r9", done: true, exitCode: -1, error: "rpc error: code = FailedPrecondition desc = diag: herramienta no instalada: nmap (instala: sudo apt install nmap)" }));
  act(() => resolveRun("r9"));
  expect(await screen.findByRole("alert")).toHaveTextContent(/sudo apt install nmap/);
  expect(screen.getByRole("button", { name: "Ejecutar" })).toBeEnabled();
});

// Desde la auditoría de seguridad el núcleo exige bind (una IP de esta máquina, ni 0.0.0.0 ni link-local) y puerto ≥ 1024.
const nics = [
  { name: "lo", up: true, loopback: true, addresses: ["127.0.0.1/8", "::1/128"], hardwareAddr: "" },
  { name: "eth0", up: true, loopback: false, addresses: ["192.168.3.10/24", "fe80::1/64", "169.254.9.9/16"], hardwareAddr: "aa:bb" },
  { name: "eth1", up: false, loopback: false, addresses: ["10.9.9.9/24"], hardwareAddr: "cc:dd" },
];
const server = async (over = {}) => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r3"), listInterfaces: vi.fn(async () => nics), ...over });
  render(<DiagView core={core} tool="iperf3" />);
  await userEvent.selectOptions(screen.getByLabelText("Modo"), "server");
  return core;
};

test("iperf3 servidor: elige una IP local (sin link-local ni interfaces caídas) y manda bind y puerto, sin segundos", async () => {
  const core = await server();
  const bind = await screen.findByLabelText("Escuchar en");
  expect([...bind.querySelectorAll("option")].map((o) => o.getAttribute("value"))).toEqual(["192.168.3.10", "127.0.0.1", "::1"]);
  expect(bind).toHaveValue("192.168.3.10");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("iperf3", [], { mode: "server", bind: "192.168.3.10", port: "5201" }));
});

test("iperf3 servidor: un puerto menor que 1024, con ceros a la izquierda o no entero no arranca", async () => {
  const core = await server();
  await screen.findByLabelText("Escuchar en");
  const port = screen.getByLabelText("Puerto");
  for (const bad of ["80", "", "5201.5", "70000", "05201"]) {
    await userEvent.clear(port);
    if (bad) await userEvent.type(port, bad);
    expect(screen.getByRole("button", { name: "Ejecutar" })).toBeDisabled();
    expect(port).toBeInvalid();
    expect(screen.getByText("Un entero de 1024 a 65535.")).toBeInTheDocument();
  }
  expect(core.diagRun).not.toHaveBeenCalled();
});

test("iperf3 servidor en Windows: acepta el 1-65535 con sus textos; sigue rechazando ceros a la izquierda y no enteros", async () => {
  setOSForTests("windows");
  try {
    const core = await server();
    await screen.findByLabelText("Escuchar en");
    const port = screen.getByLabelText("Puerto");
    expect(port).toHaveAccessibleDescription("De 1 a 65535; 5201 es el de iperf3.");
    await userEvent.clear(port);
    await userEvent.type(port, "162");
    expect(port).toBeValid();
    await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
    await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("iperf3", [], { mode: "server", bind: "192.168.3.10", port: "162" }));
    for (const bad of ["0", "", "5201.5", "70000", "05201"]) {
      await userEvent.clear(port);
      if (bad) await userEvent.type(port, bad);
      expect(port).toBeInvalid();
      expect(screen.getByText("Un entero de 1 a 65535.")).toBeInTheDocument();
    }
  } finally { setOSForTests(undefined); }
});

test("iperf3 servidor: se puede elegir otra IP y se manda esa", async () => {
  const core = await server();
  await userEvent.selectOptions(await screen.findByLabelText("Escuchar en"), "127.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("iperf3", [], { mode: "server", bind: "127.0.0.1", port: "5201" }));
});

test("iperf3 servidor: si la IP ya no es de la máquina al ejecutar, lo dice y no arranca", async () => {
  const listInterfaces = vi.fn().mockResolvedValueOnce(nics).mockResolvedValueOnce(nics).mockResolvedValue([nics[0]]);
  const core = await server({ listInterfaces });
  await screen.findByLabelText("Escuchar en");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  expect(await screen.findByText(/La IP 192.168.3.10 ya no es de esta máquina/)).toBeInTheDocument();
  expect(core.diagRun).not.toHaveBeenCalled();
});

test("iperf3 servidor: dos disparos seguidos (mientras se leen las interfaces) lanzan diagRun una sola vez", async () => {
  let release: (l: typeof nics) => void = () => {};
  const listInterfaces = vi.fn().mockResolvedValueOnce(nics).mockReturnValue(new Promise<typeof nics>((r) => { release = r; }));
  const core = await server({ listInterfaces });
  await screen.findByLabelText("Escuchar en");
  const btn = screen.getByRole("button", { name: "Ejecutar" });
  btn.click(); btn.click(); // sin act entre los dos: el botón aún no se apagó
  release(nics);
  await waitFor(() => expect(core.diagRun).toHaveBeenCalled());
  await new Promise((r) => setTimeout(r, 20));
  expect(core.diagRun).toHaveBeenCalledTimes(1);
});

test("iperf3 servidor: si no se pueden leer las interfaces lo dice (no que falte una IP)", async () => {
  await server({ listInterfaces: vi.fn(async () => { throw new Error("x"); }) });
  expect(await screen.findByText(/No se pudieron leer las interfaces/)).toBeInTheDocument();
  expect(screen.queryByText(/No hay una IP local/)).not.toBeInTheDocument();
});

test("iperf3 cliente: no manda bind ni puerto y sigue mandando segundos y destino", async () => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r4"), listInterfaces: vi.fn(async () => nics) });
  render(<DiagView core={core} tool="iperf3" />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.9");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("iperf3", ["10.0.0.9"], { mode: "client", seconds: "10" }));
});

test("iperf3 servidor: sin IP local disponible lo dice y no arranca", async () => {
  await server({ listInterfaces: vi.fn(async () => [nics[2]]) });
  expect(await screen.findByText(/No hay una IP local/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Ejecutar" })).toBeDisabled();
});

test("el botón de ejecutar queda deshabilitado hasta que hay destino", async () => {
  render(<DiagView core={fakeCore()} tool="ping" />);
  expect(screen.getByRole("button", { name: /Ejecutar/ })).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  expect(screen.getByRole("button", { name: /Ejecutar/ })).toBeEnabled();
});

test("cancelar no es un fallo: estado neutro «Cancelado» y sin mensaje de error", async () => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r1") });
  render(<DiagView core={core} tool="ping" />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalled());
  await userEvent.click(await screen.findByRole("button", { name: "Cancelar" }));
  act(() => core.emitDiag({ runId: "r1", done: true, exitCode: -1, canceled: true }));
  expect(await screen.findByText("Cancelado")).toBeInTheDocument();
  expect(screen.getByText("Cancelado por el usuario.")).toBeInTheDocument();
  expect(screen.queryByText(/Con error|Error:/)).not.toBeInTheDocument();
});

test("dos clics seguidos en Ejecutar no lanzan dos ejecuciones", async () => {
  const core = fakeCore({ diagRun: vi.fn(() => new Promise<string>(() => {})) });
  render(<DiagView core={core} tool="ping" />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  const run = screen.getByRole("button", { name: /Ejecutar/ });
  await userEvent.click(run);
  await userEvent.click(run);
  expect(core.diagRun).toHaveBeenCalledTimes(1);
});

test("un evento posterior al cambio de idioma se escribe en el idioma vigente, no en el del primer render", async () => {
  const Switch = () => { const set = useSetLang(); return <button onClick={() => set("en")}>a-en</button>; };
  const core = fakeCore({ diagRun: vi.fn(async () => "r1") });
  render(<I18nProvider><Switch /><DiagView core={core} tool="ping" /></I18nProvider>);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: /Ejecutar/ }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalled());
  await userEvent.click(screen.getByRole("button", { name: "a-en" }));
  act(() => core.emitDiag({ runId: "r1", done: true, exitCode: -1, canceled: true }));
  expect(await screen.findByText("Canceled by the user.")).toBeInTheDocument();
});

// ADR 0012 (i): en Windows el SYN de nmap necesita Npcap, que no es parte del producto; la beta lo esconde.
test("nmap en Windows no ofrece el escaneo SYN; en Linux sí", () => {
  setOSForTests("windows");
  try {
    const { unmount } = render(<DiagView core={fakeCore()} tool="nmap" />);
    const opts = () => screen.getAllByRole("option").map((o) => o.getAttribute("value"));
    expect(opts()).not.toContain("syn");
    expect(opts()).toEqual(expect.arrayContaining(["connect", "udp", "ping"]));
    unmount();
  } finally { setOSForTests(undefined); }
  render(<DiagView core={fakeCore()} tool="nmap" />);
  expect(screen.getAllByRole("option").map((o) => o.getAttribute("value"))).toContain("syn");
});

// Ping extendido (#200, contrato provisional)
const openExt = async () => userEvent.click(screen.getByText("Opciones extendidas"));
const pingView = async (over = {}) => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r1"), ...over });
  render(<DiagView core={core} tool="ping" />);
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

test("continuo: Detener usa diagStop y Cancelar sigue cortando; NotFound al detener no muestra error", async () => {
  const diagStop = vi.fn().mockRejectedValue(Object.assign(new Error("x"), { cause: { code: "NotFound", reason: "run.notfound" } }));
  const core = await pingView({ diagStop });
  await openExt();
  await userEvent.click(screen.getByLabelText("Continuo (hasta detener)"));
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("ping", ["10.0.0.1"], { continuous: "true" }));
  await userEvent.click(await screen.findByRole("button", { name: "Detener" }));
  expect(diagStop).toHaveBeenCalledWith("r1");
  await act(async () => {});
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Cancelar" }));
  expect(core.diagCancel).toHaveBeenCalledWith("r1");
});

test("otro error de diagStop sí se muestra; sin continuo ni duración no hay Detener", async () => {
  const core = await pingView({ diagStop: vi.fn().mockRejectedValue(new Error("boom")) });
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await screen.findByRole("button", { name: "Cancelar", hidden: false });
  expect(screen.queryByRole("button", { name: "Detener" })).not.toBeInTheDocument();
  expect(core.diagStop).not.toHaveBeenCalled();
});

test("también se detiene con duración, y un error distinto de NotFound se muestra", async () => {
  await pingView({ diagStop: vi.fn().mockRejectedValue(new Error("boom")) });
  await openExt();
  await userEvent.type(screen.getByLabelText("Duración total (1-3600 s)"), "30");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await userEvent.click(await screen.findByRole("button", { name: "Detener" }));
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
  await waitFor(() => expect(core.diagRun).toHaveBeenCalledWith("ping", ["10.0.0.1"], { count: "4", sweep_start: "1400", sweep_end: "1500", sweep_step: "50" }));
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
