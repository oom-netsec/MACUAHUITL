import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AdhocView, parseTarget } from "./AdhocView";
import { fakeCore } from "../../lib/fake";
import { CoreContext } from "../../app/activity";

const cred = { id: "c1", label: "lab", username: "admin", hasEnable: true, hasSshKey: false };
const report = { commands: ["show clock"], devices: 2, rows: [
  { device: "SW1", address: "192.0.2.1", command: "show clock", ok: true, output: "10:00:00" },
  { device: "SW2", address: "192.0.2.2", command: "show clock", ok: false, output: "", note: "tiempo agotado" },
] };

test("el destino acepta host y host:puerto", () => {
  expect(parseTarget("192.0.2.1")).toEqual({ address: "192.0.2.1", port: 0 });
  expect(parseTarget("sw1:2222")).toEqual({ address: "sw1", port: 2222 });
  expect(parseTarget("2001:db8::1")).toEqual({ address: "2001:db8::1", port: 0 });
  // IPv6 con puerto: la forma entre corchetes.
  expect(parseTarget("[2001:db8::1]:2222")).toEqual({ address: "2001:db8::1", port: 2222 });
  expect(parseTarget("[2001:db8::1]")).toEqual({ address: "2001:db8::1", port: 0 });
});

test("ejecuta el lote, espera el resultado y muestra por equipo, tabla, CSV y Markdown", async () => {
  const adhocResult = vi.fn().mockResolvedValueOnce({ state: "armed", done: false, report: null, text: "", csv: "", markdown: "" })
    .mockResolvedValueOnce({ state: "completed", done: true, report, text: "== SW1 (192.0.2.1) ==\n10:00:00", csv: "equipo,direccion\nSW1,192.0.2.1\n", markdown: "| Equipo |" });
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocResult });
  render(<AdhocView core={core} pollMs={1} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1 sw2:2222");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  await userEvent.click(await screen.findByRole("button", { name: "Por equipo" }));
  expect(await screen.findByText(/== SW1/)).toBeInTheDocument();
  expect(core.adhocStart).toHaveBeenCalledWith([{ address: "192.0.2.1", port: 0 }, { address: "sw2", port: 2222 }], "c1", expect.stringContaining("show version"), [], []);
  expect(adhocResult).toHaveBeenCalledTimes(2);
  await userEvent.click(screen.getByRole("button", { name: "Tabla" }));
  expect(screen.getByText("tiempo agotado")).toBeInTheDocument();
  expect(screen.getByText("sin salida")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "CSV" }));
  expect(screen.getByLabelText("CSV")).toHaveValue("equipo,direccion\nSW1,192.0.2.1\n");
  await userEvent.click(screen.getByRole("button", { name: "Markdown" }));
  expect(screen.getByLabelText("Markdown")).toHaveValue("| Equipo |");
});

const matrixReport = { commands: ["show clock", "show version"], devices: 2, rows: [
  { device: "SW1", address: "192.0.2.1", command: "show clock", ok: true, output: "10:00:00.123 UTC" },
  { device: "SW1", address: "192.0.2.1", command: "show version", ok: true, output: "" },
  { device: "SW2", address: "192.0.2.2", command: "show clock", ok: false, output: "", note: "tiempo agotado" },
  { device: "SW2", address: "192.0.2.2", command: "show version", ok: true, output: "Cisco IOS XE 17.9" },
] };

async function runMatrix() {
  const core = fakeCore({
    listCredentials: vi.fn(async () => [cred]),
    adhocResult: vi.fn(async () => ({ state: "completed", done: true, report: matrixReport, text: "", csv: "equipo,comando\nSW1,show clock\n", markdown: "| Equipo | Comando |" })),
  });
  render(<CoreContext.Provider value={core}><AdhocView core={core} pollMs={1} /></CoreContext.Provider>);
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1 192.0.2.2");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  return { core, grid: await screen.findByRole("table", { name: "Matriz de equipos por comando" }) };
}

test("la matriz muestra un estado por equipo y comando, con texto además del color", async () => {
  const { grid } = await runMatrix();
  expect(within(grid).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Equipo", "show clock", "show version"]);
  expect(within(grid).getByRole("button", { name: "SW1 show clock: Correcto" })).toBeInTheDocument();
  expect(within(grid).getByRole("button", { name: "SW1 show version: Vacío" })).toBeInTheDocument();
  expect(within(grid).getByRole("button", { name: "SW2 show clock: Error" })).toBeInTheDocument();
});

test("elegir una celda abre su salida en la terminal; un error muestra la nota del equipo", async () => {
  const { grid } = await runMatrix();
  expect(screen.getByText("Elegir una celda de la matriz para ver su salida.")).toBeInTheDocument();
  await userEvent.click(within(grid).getByRole("button", { name: "SW2 show version: Correcto" }));
  const out = screen.getByRole("region", { name: "SW2 · show version" });
  expect(within(out).getByLabelText("Salida de SW2 · show version")).toHaveTextContent("Cisco IOS XE 17.9");
  await userEvent.click(within(grid).getByRole("button", { name: "SW2 show clock: Error" }));
  expect(within(screen.getByRole("region", { name: "SW2 · show clock" })).getByLabelText("Salida de SW2 · show clock")).toHaveTextContent("tiempo agotado");
});

test("la matriz se exporta a CSV y Markdown con lo que entregó el núcleo", async () => {
  const { core } = await runMatrix();
  await userEvent.click(screen.getByRole("button", { name: "Exportar" }));
  await userEvent.click(screen.getByRole("menuitem", { name: "CSV (.csv)" }));
  expect(core.saveFile).toHaveBeenCalledWith("lote.csv", "equipo,comando\nSW1,show clock\n", "utf8");
  await userEvent.click(screen.getByRole("button", { name: "Exportar" }));
  await userEvent.click(screen.getByRole("menuitem", { name: "Markdown (.md)" }));
  expect(core.saveFile).toHaveBeenLastCalledWith("lote.md", "| Equipo | Comando |", "utf8");
});

const login = (o: object = {}) => ({ target: "192.0.2.1:22", passed: false, failedStep: "LOGIN_TEST_STEP_HOST_KEY", detail: "llave de host", platform: "", fingerprint: "SHA256:abc", reason: "transport.hostkey.unknown", args: { key_type: "ssh-ed25519" }, ...o });

test("un lote sin armar por llave de host muestra la huella y solo con «Confiar y reintentar» arma con ella", async () => {
  const adhocStart = vi.fn().mockResolvedValueOnce({ jobId: "j9", armed: false, detail: "Login Test falló: llave de host SHA256:abc" });
  const loginTest = vi.fn(async () => [login()]);
  const armJob = vi.fn(async () => ({ windowEndsAt: "", missingInhibitors: [] }));
  const adhocResult = vi.fn(async () => ({ state: "completed", done: true, report: { commands: [], devices: 0, rows: [] }, text: "", csv: "", markdown: "" }));
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocStart, loginTest, armJob, adhocResult });
  render(<AdhocView core={core} pollMs={1} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  expect(screen.queryByLabelText(/Huellas SHA256 aceptadas/)).not.toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  expect(await screen.findByText("SHA256:abc")).toBeInTheDocument();
  expect(loginTest).toHaveBeenCalledWith("j9");
  expect(screen.getByText("ssh-ed25519")).toBeInTheDocument();
  expect(screen.getByText("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")).toBeInTheDocument();
  expect(armJob).not.toHaveBeenCalled(); // sin clic no se acepta nada
  await userEvent.click(screen.getByRole("button", { name: "Confiar y reintentar" }));
  await screen.findByRole("button", { name: "Tabla" });
  // Se arma el mismo trabajo (ya tiene sus comandos); no se crea otro.
  expect(armJob).toHaveBeenCalledWith("j9", [], [{ host: "192.0.2.1:22", fingerprint: "SHA256:abc" }], []); // un par atado al equipo, no la lista suelta
  expect(adhocStart).toHaveBeenCalledTimes(1);
  expect(adhocResult).toHaveBeenCalledWith("j9");
  expect(screen.queryByRole("button", { name: "Confiar y reintentar" })).not.toBeInTheDocument();
});

test("si armar el mismo trabajo falla, el panel de confianza vuelve con lo que diga el Login Test y el error se ve", async () => {
  const adhocStart = vi.fn().mockResolvedValueOnce({ jobId: "j9", armed: false, detail: "llave de host" });
  const loginTest = vi.fn(async () => [login()]);
  const armJob = vi.fn(async () => { throw new Error("login test failed: B: HOST_KEY"); });
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocStart, loginTest, armJob });
  render(<AdhocView core={core} pollMs={1} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  await userEvent.click(await screen.findByRole("button", { name: "Confiar y reintentar" }));
  expect(await screen.findByText(/login test failed/)).toBeInTheDocument();
  expect(await screen.findByRole("button", { name: "Confiar y reintentar" })).toBeInTheDocument();
  expect(loginTest).toHaveBeenCalledTimes(2);
  expect(adhocStart).toHaveBeenCalledTimes(1);
});

test("en un lote con varios equipos con huella, solo se aceptan los marcados; una cambiada avisa peligro", async () => {
  const adhocStart = vi.fn().mockResolvedValueOnce({ jobId: "j9", armed: false, detail: "x" });
  const loginTest = vi.fn(async () => [login(), login({ target: "192.0.2.2:22", fingerprint: "SHA256:def", reason: "transport.hostkey.changed" }), login({ target: "192.0.2.3:22", fingerprint: "", failedStep: "LOGIN_TEST_STEP_AUTH", reason: "" })]);
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocStart, loginTest });
  render(<AdhocView core={core} pollMs={1} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1\n192.0.2.2\n192.0.2.3");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  expect(await screen.findAllByRole("checkbox")).toHaveLength(2); // el de auth no ofrece huella
  expect(screen.getByRole("alert")).toHaveTextContent("CAMBIÓ");
  expect(screen.getByRole("button", { name: "Confiar y reintentar" })).toBeDisabled();
  await userEvent.click(screen.getByRole("checkbox", { name: /192\.0\.2\.1:22/ }));
  await userEvent.click(screen.getByRole("button", { name: "Confiar y reintentar" }));
  await screen.findByRole("button", { name: "Tabla" });
  expect(core.armJob).toHaveBeenCalledWith("j9", [], [{ host: "192.0.2.1:22", fingerprint: "SHA256:abc" }], []); // solo el marcado, con su equipo
});

test("si el Login Test no se puede obtener, se avisa que no hay huella (no queda en silencio)", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocStart: vi.fn(async () => ({ jobId: "j9", armed: false, detail: "x" })), loginTest: vi.fn(async () => { throw new Error("sin ruta"); }) });
  render(<AdhocView core={core} pollMs={1} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  expect(await screen.findByText(/No se pudo obtener la huella/)).toBeInTheDocument();
  expect(screen.queryByText(/compara la huella aquí abajo/)).not.toBeInTheDocument();
});

test("si cambian los comandos tras el rechazo, ya no se arma el trabajo viejo: se crea uno nuevo", async () => {
  const adhocStart = vi.fn().mockResolvedValueOnce({ jobId: "j9", armed: false, detail: "x" }).mockResolvedValueOnce({ jobId: "j10", armed: true, detail: "" });
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocStart, loginTest: vi.fn(async () => [login()]) });
  render(<AdhocView core={core} pollMs={1} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  await screen.findByText("SHA256:abc");
  await userEvent.type(screen.getByLabelText("Comandos (uno por línea)"), "x");
  expect(screen.queryByRole("button", { name: "Confiar y reintentar" })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  expect(adhocStart).toHaveBeenCalledTimes(2);
  expect(core.armJob).not.toHaveBeenCalled();
});

test("el rechazo del núcleo (comando que no es de lectura) se muestra como alerta", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocStart: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = comando no permitido en una recolección (solo lectura)"); }) });
  render(<AdhocView core={core} pollMs={1} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("solo lectura");
});

async function runBatch(core: ReturnType<typeof fakeCore>, props: { pollMs: number; maxWaitMs?: number }) {
  render(<AdhocView core={core} {...props} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
}

test("si el núcleo termina con error, lo muestra y deja de preguntar", async () => {
  const adhocResult = vi.fn(async () => ({ state: "completed", done: true, report: null, text: "", csv: "", markdown: "", error: "patrol: disco lleno" }));
  await runBatch(fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocResult }), { pollMs: 1 });
  expect(await screen.findByRole("alert")).toHaveTextContent("patrol: disco lleno");
  expect(adhocResult).toHaveBeenCalledTimes(1);
});

test("el bucle de consulta tiene tope de tiempo y lo dice", async () => {
  const adhocResult = vi.fn(async () => ({ state: "completed", done: false, report: null, text: "", csv: "", markdown: "" }));
  await runBatch(fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocResult }), { pollMs: 1, maxWaitMs: 30 });
  expect(await screen.findByRole("alert")).toHaveTextContent(/sigue sin resultado/);
  const n = adhocResult.mock.calls.length;
  await new Promise((ok) => setTimeout(ok, 30));
  expect(adhocResult.mock.calls.length).toBe(n);
  expect(screen.getByRole("button", { name: "Ejecutar lote" })).toBeEnabled();
});

test("Ejecutar lote nombra lo que falta y deja de hacerlo al completarlo", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred, { ...cred, id: "c2", label: "otra" }]) }); // con una sola se preelige
  render(<AdhocView core={core} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  const run = () => screen.getByRole("button", { name: "Ejecutar lote" });
  expect(run()).toBeDisabled();
  expect(run()).toHaveAccessibleDescription("Falta: elegir una credencial, indicar los equipos.");
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c1");
  expect(run()).toHaveAccessibleDescription("Falta: indicar los equipos.");
  await userEvent.clear(screen.getByLabelText("Comandos (uno por línea)"));
  expect(run()).toHaveAccessibleDescription("Falta: indicar los equipos, escribir los comandos.");
  await userEvent.type(screen.getByLabelText("Comandos (uno por línea)"), "show clock");
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1");
  expect(run()).toBeEnabled();
  expect(run()).not.toHaveAccessibleDescription();
});
