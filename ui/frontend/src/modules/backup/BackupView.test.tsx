import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BackupView } from "./BackupView";
import { fakeCore } from "../../lib/fake";
import { CoreContext, ModuleIdContext, NavContext } from "../../app/activity";
import { sampleEntry } from "./fake";

const a = sampleEntry();
const b = sampleEntry({ id: "SW1_192.0.2.1/20261106T110000Z-running", at: "2026-11-06T11:00:00Z", masked: false });

const cred = { id: "c1", label: "lab", username: "admin", hasEnable: false, hasSshKey: false };
const withCreds = (over = {}) => fakeCore({ listCredentials: vi.fn(async () => [cred]), ...over });

test("respalda una vez, espera el resultado, avisa y recarga la lista", async () => {
  const core = withCreds({
    backupCollect: vi.fn().mockResolvedValueOnce({ state: "running", done: false, saved: [], skipped: 0, pruned: 0, warnings: [] })
      .mockResolvedValueOnce({ state: "completed", done: true, saved: [a.id], skipped: 0, pruned: 0, warnings: ["SW1: el equipo no devolvió startup-config"] }),
    backupList: vi.fn().mockResolvedValueOnce({ backups: [], masked: false }).mockResolvedValue({ backups: [a], masked: true }),
  });
  render(<BackupView core={core} pollMs={1} />);
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1:2222");
  await userEvent.click(screen.getByLabelText("Incluir también el startup-config"));
  await userEvent.click(await screen.findByRole("button", { name: "Respaldar ahora" }));
  expect(core.backupStart).toHaveBeenCalledWith(expect.objectContaining({ targets: [{ address: "192.0.2.1", port: 2222 }], credentialId: "c1", startup: true, keep: 30, intervalSeconds: 0, rounds: 0, secrets: false }));
  expect(await screen.findByText(/1 respaldo guardado\. Avisos: SW1/)).toBeInTheDocument();
  expect(core.backupCollect).toHaveBeenCalledTimes(2);
  expect(await screen.findByText(a.device)).toBeInTheDocument();
  expect(screen.getByText(/Aviso: Los respaldos marcados «enmascarado»/)).toBeInTheDocument();
});

test("sin armar explica por qué y no espera", async () => {
  const core = withCreds({ backupStart: vi.fn(async () => ({ jobId: "j9", armed: false, detail: "Login Test falló" })) });
  render(<BackupView core={core} />);
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  await userEvent.click(await screen.findByRole("button", { name: "Respaldar ahora" }));
  expect(await screen.findByRole("status")).toHaveTextContent("Trabajo j9 creado sin armar: Login Test falló");
  expect(core.backupCollect).not.toHaveBeenCalled();
});

test("sin armar por llave de host muestra la huella y solo con «Confiar y reintentar» respalda con ella", async () => {
  const backupStart = vi.fn().mockResolvedValueOnce({ jobId: "j9", armed: false, detail: "Login Test falló" }).mockResolvedValueOnce({ jobId: "j10", armed: true, detail: "" });
  const loginTest = vi.fn(async () => [{ target: "192.0.2.1:22", passed: false, failedStep: "LOGIN_TEST_STEP_HOST_KEY", detail: "x", platform: "", fingerprint: "SHA256:abc", reason: "transport.hostkey.changed", args: { key_type: "ssh-rsa" } }]);
  const core = withCreds({ backupStart, loginTest, backupCollect: vi.fn(async () => ({ state: "completed", done: true, saved: [a.id], skipped: 0, pruned: 0, warnings: [] })) });
  render(<BackupView core={core} pollMs={1} />);
  expect(screen.queryByLabelText(/Huellas aceptadas|Huellas SHA256 aceptadas/)).not.toBeInTheDocument();
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  await userEvent.click(await screen.findByRole("button", { name: "Respaldar ahora" }));
  expect(await screen.findByText("SHA256:abc")).toBeInTheDocument();
  expect(loginTest).toHaveBeenCalledWith("j9");
  expect(screen.getByText("ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub")).toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent("CAMBIÓ");
  expect(backupStart).toHaveBeenCalledTimes(1); // sin clic no se acepta nada
  await userEvent.click(screen.getByRole("checkbox", { name: /Entiendo que la llave de este equipo cambió/ })); // llave cambiada
  await userEvent.click(screen.getByRole("button", { name: "Confiar y reintentar" }));
  await waitFor(() => expect(backupStart).toHaveBeenCalledTimes(2));
  expect(backupStart).toHaveBeenLastCalledWith(expect.objectContaining({ accept: [], acceptedKeys: [{ host: "192.0.2.1:22", fingerprint: "SHA256:abc" }] }));
  expect(await screen.findByText(/1 respaldo guardado/)).toBeInTheDocument();
});

test("si el Login Test no se puede obtener, se avisa que no hay huella", async () => {
  const core = withCreds({ backupStart: vi.fn(async () => ({ jobId: "j9", armed: false, detail: "x" })), loginTest: vi.fn(async () => { throw new Error("sin ruta"); }) });
  render(<BackupView core={core} />);
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  await userEvent.click(await screen.findByRole("button", { name: "Respaldar ahora" }));
  expect(await screen.findByText(/No se pudo obtener la huella/)).toBeInTheDocument();
});

test("programar convierte minutos en segundos y no espera el resultado", async () => {
  const core = withCreds();
  render(<BackupView core={core} />);
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  await userEvent.clear(screen.getByLabelText(/Programar cada/));
  await userEvent.type(screen.getByLabelText(/Programar cada/), "60");
  await userEvent.clear(screen.getByLabelText(/Veces/));
  await userEvent.type(screen.getByLabelText(/Veces/), "4");
  await userEvent.click(await screen.findByRole("button", { name: "Programar" }));
  expect(core.backupStart).toHaveBeenCalledWith(expect.objectContaining({ intervalSeconds: 3600, rounds: 4 }));
  expect(await screen.findByRole("status")).toHaveTextContent("Programado (trabajo j1)");
  expect(core.backupCollect).not.toHaveBeenCalled();
});

test("avisa que sin enmascarar deja secretos en claro", async () => {
  render(<BackupView core={withCreds()} />);
  await userEvent.click(screen.getByLabelText("Guardar sin enmascarar secretos"));
  expect(screen.getByRole("status")).toHaveTextContent("contraseñas y llaves en claro");
});

test("la línea de tiempo agrupa por equipo y ordena del más nuevo al más viejo", async () => {
  const r1 = sampleEntry({ id: "R1_192.0.2.9/20261105T080000Z-running", device: "R1_192.0.2.9", at: "2026-11-05T08:00:00Z", bytes: 2048 });
  const core = withCreds({ backupList: vi.fn(async () => ({ backups: [a, r1, b], masked: false })) });
  render(<BackupView core={core} />);
  const sw1 = await screen.findByRole("region", { name: a.device });
  const boxes = within(sw1).getAllByRole("checkbox").map((c) => c.getAttribute("aria-label"));
  expect(boxes).toEqual([`Comparar ${b.id}`, `Comparar ${a.id}`]);
  expect(within(sw1).getAllByText("1.2 KiB")).toHaveLength(2);
  expect(within(screen.getByRole("region", { name: r1.device })).getByText("2 KiB")).toBeInTheDocument();
});

test("compara dos respaldos, el más viejo primero, en el visor de diferencias", async () => {
  // El núcleo manda los dos textos ya enmascarados: el visor nunca pide el respaldo entero (que puede traer hashes).
  const diff = {
    from: a, to: b, added: 1, removed: 1, ignored: ["ntp clock-period 1", "ntp clock-period 2"], masked: true, changes: [],
    before: "hostname SW1\nenable secret 5 <MASKED:enable-secret>\ninterface Gi1/0/1\n description PC-01\nntp clock-period 1\n",
    after: "hostname SW1\nenable secret 5 <MASKED:enable-secret>\ninterface Gi1/0/1\n description PC-02\nntp clock-period 2\n",
  };
  const texts: Record<string, string> = {
    [a.id]: "hostname SW1\nenable secret 5 $1$abcd$HashViejo\ninterface Gi1/0/1\n description PC-01\nntp clock-period 1\n",
    [b.id]: "hostname SW1\nenable secret 5 <MASKED:enable-secret>\ninterface Gi1/0/1\n description PC-02\nntp clock-period 2\n",
  };
  const core = withCreds({
    backupList: vi.fn(async () => ({ backups: [b, a], masked: true })), backupDiff: vi.fn(async () => diff),
    backupGet: vi.fn(async (id: string) => ({ meta: id === a.id ? a : b, text: texts[id] })),
  });
  render(<BackupView core={core} />);
  const cmp = screen.getByRole("button", { name: "Comparar" });
  await screen.findByLabelText(`Comparar ${b.id}`);
  expect(cmp).toBeDisabled();
  await userEvent.click(screen.getByLabelText(`Comparar ${b.id}`));
  await userEvent.click(screen.getByLabelText(`Comparar ${a.id}`));
  await userEvent.click(cmp);
  expect(core.backupDiff).toHaveBeenCalledWith(a.id, b.id);
  expect(core.backupGet).not.toHaveBeenCalled();
  const reg = await screen.findByRole("region", { name: "Diferencias" });
  expect(within(reg).getByText("1 cambio", { exact: false })).toBeInTheDocument();
  expect(within(reg).getByText((_, el) => el?.tagName === "CODE" && el.textContent === " description PC-02" && el.closest("[data-op]")?.getAttribute("data-op") === "+")).toBeInTheDocument();
  // Las líneas volátiles que el núcleo ignora no se muestran como cambio.
  expect(within(reg).queryByText(/clock-period 2/)).not.toBeInTheDocument();
  expect(screen.getByText(/no son visibles porque alguno de los dos respaldos se tomó enmascarado/)).toBeInTheDocument();
  expect(screen.getByText(/Ignoradas por volátiles: ntp clock-period 1/)).toBeInTheDocument();
  expect(document.body.textContent).not.toMatch(/HashViejo|\$1\$/);
});

test("ver ofrece descargar el .cfg con el nombre del equipo y la fecha, y copiar el contenido", async () => {
  const core = withCreds({ backupList: vi.fn(async () => ({ backups: [a], masked: true })), backupGet: vi.fn(async () => ({ meta: a, text: "hostname SW1\n" })) });
  render(<CoreContext.Provider value={core}><BackupView core={core} /></CoreContext.Provider>);
  await userEvent.click(await screen.findByRole("button", { name: `Ver ${a.id}` }));
  const reg = await screen.findByRole("region", { name: "Contenido" });
  await userEvent.click(within(reg).getByRole("button", { name: "Descargar .cfg" }));
  expect(core.saveFile).toHaveBeenCalledWith("SW1_192.0.2.1-20261106T100000Z.cfg", "hostname SW1\n", "utf8");
  await userEvent.click(within(reg).getByRole("button", { name: "Copiar contenido" }));
  expect(core.copyText).toHaveBeenCalledWith("hostname SW1\n");
});

test("ver muestra el contenido y el error del núcleo sale como alerta", async () => {
  const core = withCreds({
    backupList: vi.fn(async () => ({ backups: [a], masked: true })),
    backupGet: vi.fn().mockResolvedValueOnce({ meta: a, text: "hostname SW1\n" }).mockRejectedValueOnce(new Error("rpc error: code = NotFound desc = no existe")),
  });
  render(<BackupView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: `Ver ${a.id}` }));
  expect(within(await screen.findByRole("region", { name: "Contenido" })).getByText((_, el) => el?.tagName === "PRE" && /hostname SW1/.test(el.textContent ?? ""))).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: `Ver ${a.id}` }));
  expect(await screen.findByRole("alert")).toHaveTextContent("no existe");
  expect(screen.queryByRole("region", { name: "Contenido" })).not.toBeInTheDocument();
});

test("el menú de equipo precarga la dirección en Equipos", () => {
  render(<NavContext.Provider value={{ go: () => {}, inbox: { backup: { data: "10.20.3.11", n: 1 } } }}><BackupView core={withCreds()} /></NavContext.Provider>);
  expect(screen.getByLabelText(/Equipos/)).toHaveValue("10.20.3.11");
});

// Una restauración viva tras reabrir la app se retoma en Respaldos aunque no haya una entrada elegida.
test("una restauración viva de Respaldos se engancha sin elegir entrada", async () => {
  localStorage.setItem("macuahuitl.assist.r7", "backup");
  try {
    const core = withCreds({ assistListRuns: vi.fn(async () => [{ runId: "r7", state: "running", active: true }]) });
    render(<ModuleIdContext.Provider value="backup"><BackupView core={core} /></ModuleIdContext.Provider>);
    await waitFor(() => expect(core.assistWatch).toHaveBeenCalledWith("r7"));
  } finally { localStorage.removeItem("macuahuitl.assist.r7"); }
});

test("comparar dos respaldos con secretos donde solo cambió una clave lo dice, sin mostrarla", async () => {
  const diff = {
    from: a, to: b, added: 0, removed: 0, ignored: [], masked: false,
    changes: [{ op: "~", path: "", line: "enable secret 5 <MASKED:enable-secret>" }],
    before: "hostname SW1\nenable secret 5 <MASKED:enable-secret>\n", after: "hostname SW1\nenable secret 5 <MASKED:enable-secret>\n",
  };
  const core = withCreds({ backupList: vi.fn(async () => ({ backups: [b, a], masked: false })), backupDiff: vi.fn(async () => diff) });
  render(<BackupView core={core} />);
  await userEvent.click(await screen.findByLabelText(`Comparar ${b.id}`));
  await userEvent.click(screen.getByLabelText(`Comparar ${a.id}`));
  await userEvent.click(screen.getByRole("button", { name: "Comparar" }));
  expect(await screen.findByText(/enable secret 5 <MASKED:enable-secret> \(cambió un valor enmascarado; no se muestra\)/)).toBeInTheDocument();
});

test("comparar y ver avisan si el respaldo se tomó sin enmascarar, y no si sí", async () => {
  const diff = (unmasked: boolean) => ({ from: a, to: b, added: 0, removed: 0, ignored: [], masked: !unmasked, ...(unmasked ? { unmasked } : {}), changes: [], before: "x\n", after: "x\n" });
  const core = withCreds({
    backupList: vi.fn(async () => ({ backups: [b, a], masked: false })),
    backupDiff: vi.fn().mockResolvedValueOnce(diff(true)).mockResolvedValueOnce(diff(false)),
    backupGet: vi.fn(async (id: string) => ({ meta: id === a.id ? a : b, text: "hostname SW1\n" })),
  });
  render(<BackupView core={core} />);
  await userEvent.click(await screen.findByLabelText(`Comparar ${b.id}`));
  await userEvent.click(screen.getByLabelText(`Comparar ${a.id}`));
  await userEvent.click(screen.getByRole("button", { name: "Comparar" }));
  expect(await screen.findByText(/esta evidencia se recogió sin enmascarar: puede traer secretos/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Comparar" }));
  await waitFor(() => expect(screen.queryByText(/esta evidencia se recogió/)).not.toBeInTheDocument());
  await userEvent.click(screen.getByRole("button", { name: `Ver ${a.id}` })); // a está enmascarado: sin aviso
  await screen.findByRole("region", { name: "Contenido" });
  expect(screen.queryByText(/esta evidencia se recogió/)).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: `Ver ${b.id}` })); // b se tomó sin enmascarar
  expect(await screen.findByText(/esta evidencia se recogió sin enmascarar/)).toBeInTheDocument();
});

// ---- Fase 24a ----
test("una restauración viva retomada muestra el aviso rojo del modo asistido", async () => {
  localStorage.setItem("macuahuitl.assist.r7", "backup");
  try {
    const core = withCreds({ assistListRuns: vi.fn(async () => [{ runId: "r7", state: "running", active: true }]) });
    render(<ModuleIdContext.Provider value="backup"><BackupView core={core} /></ModuleIdContext.Provider>);
    expect(await screen.findByRole("alert")).toHaveTextContent("MODO ASISTIDO ACTIVO");
  } finally { localStorage.removeItem("macuahuitl.assist.r7"); }
});

// Seguridad: con varios equipos cada huella viaja atada a su equipo (nunca una lista suelta) y solo la de los marcados.
test("con varios equipos el reintento manda pares (equipo, huella) de los marcados y accept vacío", async () => {
  const row = (target: string, fingerprint: string) => ({ target, passed: false, failedStep: "LOGIN_TEST_STEP_HOST_KEY", detail: "x", platform: "", fingerprint, reason: "transport.hostkey.unknown" });
  const backupStart = vi.fn().mockResolvedValueOnce({ jobId: "j9", armed: false, detail: "x" }).mockResolvedValue({ jobId: "j10", armed: false, detail: "x" });
  const core = withCreds({ backupStart, loginTest: vi.fn(async () => [row("192.0.2.1:22", "SHA256:abc"), row("sw2:2222", "SHA256:def")]) });
  render(<BackupView core={core} pollMs={1} />);
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1 sw2:2222");
  await userEvent.click(await screen.findByRole("button", { name: "Respaldar ahora" }));
  await userEvent.click(await screen.findByRole("checkbox", { name: /sw2:2222/ }));
  await userEvent.click(screen.getByRole("button", { name: "Confiar y reintentar" }));
  await waitFor(() => expect(backupStart).toHaveBeenCalledTimes(2));
  expect(backupStart).toHaveBeenLastCalledWith(expect.objectContaining({ accept: [], acceptedKeys: [{ host: "sw2:2222", fingerprint: "SHA256:def" }] }));
});

test("si cambian los equipos tras el rechazo, el panel de confianza desaparece", async () => {
  const loginTest = vi.fn(async () => [{ target: "192.0.2.1:22", passed: false, failedStep: "LOGIN_TEST_STEP_HOST_KEY", detail: "x", platform: "", fingerprint: "SHA256:abc", reason: "transport.hostkey.unknown" }]);
  const core = withCreds({ backupStart: vi.fn(async () => ({ jobId: "j9", armed: false, detail: "x" })), loginTest });
  render(<BackupView core={core} pollMs={1} />);
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  await userEvent.click(await screen.findByRole("button", { name: "Respaldar ahora" }));
  await screen.findByRole("button", { name: "Confiar y reintentar" });
  await userEvent.type(screen.getByLabelText(/Equipos/), " 192.0.2.9");
  expect(screen.queryByRole("button", { name: "Confiar y reintentar" })).not.toBeInTheDocument();
});

test("las opciones avanzadas del respaldo van plegadas, cuentan los cambios y el aviso de secretos queda fuera", async () => {
  render(<BackupView core={withCreds()} />);
  const det = screen.getByText("Opciones avanzadas").closest("details")!;
  expect(det.open).toBe(false);
  expect(det).toContainElement(screen.getByLabelText("Incluir también el startup-config"));
  expect(det).toContainElement(screen.getByLabelText("Guardar sin enmascarar secretos"));
  expect(det).toContainElement(screen.getByLabelText(/Respaldos a conservar/));
  expect(det).not.toContainElement(screen.getByLabelText(/Programar cada/));
  await userEvent.click(screen.getByLabelText("Incluir también el startup-config"));
  await userEvent.click(screen.getByLabelText("Guardar sin enmascarar secretos"));
  await userEvent.clear(screen.getByLabelText(/Respaldos a conservar/));
  await userEvent.type(screen.getByLabelText(/Respaldos a conservar/), "5");
  expect(screen.getByText("Opciones avanzadas · cambiadas: 3")).toBeInTheDocument();
  expect(det.open).toBe(false);
  expect(det).not.toContainElement(screen.getByRole("status"));
});

test("Respaldar ahora nombra lo que falta y deja de hacerlo al completarlo", async () => {
  render(<BackupView core={fakeCore({ listCredentials: vi.fn(async () => [cred, { ...cred, id: "c2", label: "otra" }]) })} />);
  await screen.findAllByRole("option", { name: /otra/ });
  const go = () => screen.getByRole("button", { name: "Respaldar ahora" });
  expect(go()).toBeDisabled();
  expect(go()).toHaveAccessibleDescription("Falta: elegir una credencial, indicar los equipos.");
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c1");
  expect(go()).toHaveAccessibleDescription("Falta: indicar los equipos.");
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  expect(go()).toBeEnabled();
  expect(go()).not.toHaveAccessibleDescription();
});
