import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ChangeView } from "./ChangeView";
import { fakeCore } from "../../lib/fake";
import { CoreContext, ModuleIdContext } from "../../app/activity";
import { BOOK_CRED, LABEL_MANY, bookCreds, pickHost } from "../inventory/testkit";

const creds = [{ id: "c1", label: "lab", username: "admin", hasEnable: true, hasSshKey: false }];

test("tras recargar, una reversa viva iniciada en Cambios se reengancha y se avisa como modo activo", async () => {
  localStorage.setItem("macuahuitl.assist.rbv", "change");
  const core = fakeCore({ assistListRuns: vi.fn(async () => [{ runId: "rbv", active: true, state: "running" }]) });
  render(<ModuleIdContext.Provider value="change"><CoreContext.Provider value={core}><ChangeView core={core} /></CoreContext.Provider></ModuleIdContext.Provider>);
  await waitFor(() => expect(core.assistWatch).toHaveBeenCalledWith("rbv"));
  expect(await screen.findByText(/MODO ASISTIDO ACTIVO/)).toBeInTheDocument();
  localStorage.removeItem("macuahuitl.assist.rbv");
});

test("la sección Reversas pendientes lista las guardadas", async () => {
  const core = fakeCore({ assistListPendingRollbacks: vi.fn(async () => [{ runId: "a", kind: "ports", devices: [{ device: "SW1", rollbackLines: ["no shutdown"] }], endedUnix: 1, ageSeconds: 60, writeMemory: false, unreadable: false, generatedSecret: false }]) });
  render(<CoreContext.Provider value={core}><ChangeView core={core} /></CoreContext.Provider>);
  expect(await screen.findByRole("heading", { name: "Reversas pendientes" })).toBeInTheDocument();
  expect(await screen.findByRole("region", { name: "Reversa de la ejecución a" })).toBeInTheDocument();
});

test("crea el cambio, muestra la huella y con «Confiar y reintentar» repite la captura PRE con ella", async () => {
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    changeCapture: vi.fn()
      .mockResolvedValueOnce({ jobId: "j1", armed: false, detail: "Login Test falló; excluye o corrige: 192.0.2.1:22: host_key" })
      .mockResolvedValueOnce({ jobId: "j2", armed: true, detail: "" }),
    loginTest: vi.fn(async () => [{ target: "192.0.2.1:22", passed: false, failedStep: "LOGIN_TEST_STEP_HOST_KEY", detail: "nueva", platform: "", fingerprint: "SHA256:abc", reason: "transport.hostkey.unknown" }]), // llave nueva: sin la casilla de «cambió»
  });
  render(<ChangeView core={core} />);
  await userEvent.type(screen.getByLabelText("Nombre del cambio"), "CRQ-1");
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1, 192.0.2.2");
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c1");
  await userEvent.click(screen.getByRole("button", { name: "Crear cambio" }));
  await waitFor(() => expect(core.changeCreate).toHaveBeenCalledWith({ name: "CRQ-1", targets: [{ address: "192.0.2.1" }, { address: "192.0.2.2" }], defaultCredentialId: "c1", outputDir: "" }));
  await userEvent.click(await screen.findByRole("button", { name: "Capturar PRE" }));
  expect(core.loginTest).toHaveBeenCalledWith("j1");
  expect(await screen.findByText("SHA256:abc")).toBeInTheDocument();
  expect(core.changeCapture).toHaveBeenCalledTimes(1); // sin clic no se acepta nada
  await userEvent.click(screen.getByRole("button", { name: "Confiar y reintentar" }));
  await waitFor(() => expect(core.changeCapture).toHaveBeenCalledTimes(2));
  expect(core.changeCapture).toHaveBeenLastCalledWith("ch1", "pre", [], [{ host: "192.0.2.1:22", fingerprint: "SHA256:abc" }], []);
  expect(await screen.findByText(/trabajo j2/)).toBeInTheDocument();
  // Lo aceptado vale solo para ese reintento: la siguiente captura sale sin huellas.
  await userEvent.click(screen.getByRole("button", { name: "Capturar POST" }));
  expect(core.changeCapture).toHaveBeenLastCalledWith("ch1", "post", [], [], []);
});

test("«Confiar y reintentar» repite la fase que quedó sin armar (POST), no otra", async () => {
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    changeCapture: vi.fn().mockResolvedValueOnce({ jobId: "j1", armed: false, detail: "x" }).mockResolvedValueOnce({ jobId: "j2", armed: true, detail: "" }),
    loginTest: vi.fn(async () => [{ target: "192.0.2.1:22", passed: false, failedStep: "LOGIN_TEST_STEP_HOST_KEY", detail: "", platform: "", fingerprint: "SHA256:abc", reason: "transport.hostkey.unknown" }]),
  });
  render(<ChangeView core={core} />);
  await userEvent.type(screen.getByLabelText("Nombre del cambio"), "CRQ-1");
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c1");
  await userEvent.click(screen.getByRole("button", { name: "Crear cambio" }));
  await userEvent.click(await screen.findByRole("button", { name: "Capturar POST" }));
  await userEvent.click(await screen.findByRole("button", { name: "Confiar y reintentar" }));
  await waitFor(() => expect(core.changeCapture).toHaveBeenLastCalledWith("ch1", "post", [], [{ host: "192.0.2.1:22", fingerprint: "SHA256:abc" }], []));
});

const hkRow = { target: "192.0.2.1:22", passed: false, failedStep: "LOGIN_TEST_STEP_HOST_KEY", detail: "", platform: "", fingerprint: "SHA256:abc", reason: "transport.hostkey.unknown" };
async function createChange(core: ReturnType<typeof fakeCore>) {
  render(<ChangeView core={core} />);
  await userEvent.type(screen.getByLabelText("Nombre del cambio"), "CRQ-1");
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c1");
  await userEvent.click(screen.getByRole("button", { name: "Crear cambio" }));
}

test("una captura que falla al armar sin huella no deja el reintento apuntando a la huella de la captura anterior", async () => {
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    changeCapture: vi.fn().mockResolvedValueOnce({ jobId: "j1", armed: false, detail: "x" }).mockRejectedValueOnce(new Error("rpc error: code = Unavailable desc = sin ruta")),
    loginTest: vi.fn(async () => [hkRow]),
  });
  await createChange(core);
  await userEvent.click(await screen.findByRole("button", { name: "Capturar PRE" }));
  expect(await screen.findByText("SHA256:abc")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Capturar POST" }));
  await screen.findByText(/sin ruta/);
  expect(screen.queryByRole("button", { name: "Confiar y reintentar" })).not.toBeInTheDocument();
});

test("la selección de huellas sobrevive a un cambio de render y un doble clic en «Confiar y reintentar» no lanza dos capturas", async () => {
  let release: (v: unknown) => void = () => {};
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    changeCapture: vi.fn().mockResolvedValueOnce({ jobId: "j1", armed: false, detail: "x" }).mockImplementationOnce(() => new Promise((ok) => { release = ok; })),
    loginTest: vi.fn(async () => [hkRow, { ...hkRow, target: "192.0.2.2:22", fingerprint: "SHA256:def" }]),
  });
  await createChange(core);
  await userEvent.click(await screen.findByRole("button", { name: "Capturar PRE" }));
  const box = await screen.findByRole("checkbox", { name: /192\.0\.2\.1:22/ });
  await userEvent.click(box);
  await userEvent.type(screen.getByLabelText("Nombre del cambio"), "x"); // otro render: no vacía la selección
  expect(box).toBeChecked();
  const btn = screen.getByRole("button", { name: "Confiar y reintentar" });
  await userEvent.dblClick(btn);
  expect(core.changeCapture).toHaveBeenCalledTimes(2);
  release({ jobId: "j2", armed: true, detail: "" });
});

test("confiar en la huella A de un equipo no acepta otra huella B del mismo equipo en la captura siguiente", async () => {
  const row = (fp: string) => ({ target: "192.0.2.1:22", passed: false, failedStep: "LOGIN_TEST_STEP_HOST_KEY", detail: "", platform: "", fingerprint: fp });
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    changeCapture: vi.fn()
      .mockResolvedValueOnce({ jobId: "j1", armed: false, detail: "host_key" })
      .mockResolvedValueOnce({ jobId: "j2", armed: true, detail: "" })
      .mockResolvedValueOnce({ jobId: "j3", armed: false, detail: "host_key" }),
    loginTest: vi.fn().mockResolvedValueOnce([row("SHA256:aaa")]).mockResolvedValueOnce([row("SHA256:bbb")]),
  });
  render(<ChangeView core={core} />);
  await userEvent.type(screen.getByLabelText("Nombre del cambio"), "CRQ-1");
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c1");
  await userEvent.click(screen.getByRole("button", { name: "Crear cambio" }));
  await userEvent.click(await screen.findByRole("button", { name: "Capturar PRE" }));
  await screen.findByText("SHA256:aaa");
  await userEvent.click(screen.getByRole("checkbox", { name: /Entiendo que la llave/ })); // sin reason cuenta como cambiada
  await userEvent.click(screen.getByRole("button", { name: "Confiar y reintentar" }));
  await screen.findByText(/trabajo j2/);
  await userEvent.click(screen.getByRole("button", { name: "Capturar POST" }));
  expect(await screen.findByText("SHA256:bbb")).toBeInTheDocument(); // otra llave del mismo equipo: el usuario decide de nuevo
  expect(core.changeCapture).toHaveBeenLastCalledWith("ch1", "post", [], [], []); // la anterior no se arrastra
});

test("el reporte muestra el semáforo por equipo", async () => {
  const json = JSON.stringify({ devices: [
    { address: "192.0.2.1", hostname: "DIST-01", verdict: "regression", findings: [{ facet: "ospf", level: "regression", detail: "192.0.2.3 @ Gi1/0/24: FULL → INIT" }], config_diff: ["+ line vty 0 15 > exec-timeout 10 0"] },
    { address: "192.0.2.2", hostname: "DIST-02", verdict: "ok", findings: [], config_diff: [] },
  ], note: "sin validar en laboratorio" });
  const core = fakeCore({
    listChanges: vi.fn(async () => [{ id: "ch1", name: "CRQ-1", preJobId: "j1", preState: "completed", postJobId: "j2", postState: "completed" }]),
    changeReport: vi.fn(async () => ({ json, text: "texto" })),
  });
  render(<ChangeView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: /Reporte de CRQ-1/ }));
  expect(core.changeReport).toHaveBeenCalledWith("ch1", "", "");
  expect(await screen.findByRole("region", { name: /DIST-01/ })).toHaveTextContent("Regresión");
  expect(screen.getByRole("region", { name: /DIST-02/ })).toHaveTextContent("Sin cambios inesperados");
  expect(screen.getByText(/FULL → INIT/)).toBeInTheDocument();
  // El nivel del hallazgo lleva la misma mayúscula inicial que el veredicto.
  expect(within(screen.getByRole("region", { name: /DIST-01/ })).getAllByText("Regresión")).toHaveLength(2);
  // La terminal resalta por palabras clave: el texto de la línea queda repartido en spans.
  expect(screen.getByLabelText("Diferencias de configuración")).toHaveTextContent(/exec-timeout 10 0/);
});

const reportJson = JSON.stringify({ devices: [
  { address: "192.0.2.1", hostname: "DIST-01", verdict: "regression", findings: [{ facet: "ospf", level: "regression", detail: "192.0.2.3 @ Gi1/0/24: FULL → INIT" }], config_diff: ["+ line vty 0 15 > exec-timeout 10 0", "- line vty 0 15 > exec-timeout 0 0"] },
  { address: "192.0.2.2", hostname: "DIST-02", verdict: "ok", findings: [], config_diff: [] },
], note: "sin validar en laboratorio" });
const withReport = () => fakeCore({
  listChanges: vi.fn(async () => [{ id: "ch1", name: "CRQ-1", preJobId: "j1", preState: "completed", postJobId: "j2", postState: "completed" }]),
  changeReport: vi.fn(async () => ({ json: reportJson, text: "texto" })),
});

test("la diferencia de configuración se lista por línea con su operación y el conteo por equipo", async () => {
  render(<ChangeView core={withReport()} />);
  await userEvent.click(await screen.findByRole("button", { name: /Reporte de CRQ-1/ }));
  const reg = await screen.findByRole("region", { name: /DIST-01/ });
  expect(within(reg).getByText("Agregadas: 1 · Quitadas: 1")).toBeInTheDocument();
  const rows = within(within(reg).getByLabelText("Diferencias de configuración")).getAllByRole("listitem");
  expect(rows.map((r) => r.getAttribute("data-op"))).toEqual(["+", "-"]);
  expect(rows[0]).toHaveTextContent("+ line vty 0 15 > exec-timeout 10 0");
});

test("el resumen cuenta equipos por veredicto y exporta el reporte en Markdown y JSON", async () => {
  const core = withReport();
  render(<CoreContext.Provider value={core}><ChangeView core={core} /></CoreContext.Provider>);
  await userEvent.click(await screen.findByRole("button", { name: /Reporte de CRQ-1/ }));
  const sum = await screen.findByRole("region", { name: "Resumen del cambio" });
  expect(sum).toHaveTextContent("Regresión");
  expect(within(sum).getByText("1 regresión · 0 por revisar · 1 sin cambios inesperados")).toBeInTheDocument();
  await userEvent.click(within(sum).getByRole("button", { name: "Exportar" }));
  await userEvent.click(screen.getByRole("menuitem", { name: "Markdown (.md)" }));
  const md = (core.saveFile as ReturnType<typeof vi.fn>).mock.calls[0];
  expect(md[0]).toBe("CRQ-1.md");
  expect(md[1]).toContain("# CRQ-1");
  expect(md[1]).toContain("## DIST-01 (192.0.2.1) · Regresión");
  expect(md[1]).toContain("- `+ line vty 0 15 > exec-timeout 10 0`");
  expect(md[1]).toContain("ospf");
  await userEvent.click(within(sum).getByRole("button", { name: "Exportar" }));
  await userEvent.click(screen.getByRole("menuitem", { name: "JSON (.json)" }));
  const js = (core.saveFile as ReturnType<typeof vi.fn>).mock.calls[1];
  expect(js[0]).toBe("CRQ-1.json");
  expect(JSON.parse(js[1]).devices[0].hostname).toBe("DIST-01");
});

test("upgrade y cumplimiento mandan lo escrito y muestran el texto", async () => {
  const core = fakeCore({
    upgradeCheck: vi.fn(async () => ({ json: "{}", text: "FALLA espacio" })),
    complianceCheck: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = compliance: la configuración está vacía"); }),
  });
  render(<ChangeView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Upgrade" }));
  await userEvent.type(screen.getByLabelText(/Salidas recolectadas/), "SW1#show version");
  await userEvent.type(screen.getByLabelText("Imagen destino"), "x.bin");
  await userEvent.type(screen.getByLabelText("Tamaño (bytes)"), "100");
  await userEvent.click(screen.getByRole("button", { name: "Verificar" }));
  expect(await screen.findByText("FALLA espacio")).toBeInTheDocument();
  expect(core.upgradeCheck).toHaveBeenCalledWith({ outputs: "SW1#show version", image: "x.bin", size: 100, md5: "", verify: "" });
  await userEvent.click(screen.getByRole("tab", { name: "Cumplimiento" }));
  await userEvent.type(screen.getByLabelText("Running-config"), "x");
  await userEvent.click(screen.getByRole("button", { name: "Evaluar" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/^compliance: la configuración está vacía$/);
});

test("el reporte avisa si la evidencia se recogió sin enmascarar, y no si no", async () => {
  const mk = (unmasked: boolean) => JSON.stringify({ devices: [{ address: "192.0.2.2", hostname: "DIST-02", verdict: "ok", findings: [], config_diff: [] }], note: "n", ...(unmasked ? { unmasked } : {}) });
  const core = fakeCore({
    listChanges: vi.fn(async () => [{ id: "ch1", name: "CRQ-1", preJobId: "j1", preState: "completed", postJobId: "j2", postState: "completed" }]),
    changeReport: vi.fn().mockResolvedValueOnce({ json: mk(true), text: "t" }).mockResolvedValueOnce({ json: mk(false), text: "t" }),
  });
  render(<ChangeView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: /Reporte de CRQ-1/ }));
  expect(await screen.findByText(/esta evidencia se recogió sin enmascarar: puede traer secretos/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /Reporte de CRQ-1/ }));
  await waitFor(() => expect(screen.queryByText(/sin enmascarar/)).not.toBeInTheDocument());
});

// Seguridad: dos equipos con la misma huella: marcar uno marca los dos a la vista y cada par viaja con su equipo.
test("capturar manda un par por cada equipo marcado aunque compartan huella", async () => {
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    changeCapture: vi.fn(async () => ({ jobId: "j1", armed: false, detail: "Login Test falló" })),
    loginTest: vi.fn(async () => [
      { target: "192.0.2.1:22", passed: false, failedStep: "LOGIN_TEST_STEP_HOST_KEY", detail: "", platform: "", fingerprint: "SHA256:same", reason: "transport.hostkey.unknown" },
      { target: "192.0.2.2:22", passed: false, failedStep: "LOGIN_TEST_STEP_HOST_KEY", detail: "", platform: "", fingerprint: "SHA256:same", reason: "transport.hostkey.unknown" },
    ]),
  });
  render(<ChangeView core={core} />);
  await userEvent.type(screen.getByLabelText("Nombre del cambio"), "CRQ-1");
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1, 192.0.2.2");
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c1");
  await userEvent.click(screen.getByRole("button", { name: "Crear cambio" }));
  await userEvent.click(await screen.findByRole("button", { name: "Capturar PRE" }));
  const boxes = await screen.findAllByRole("checkbox", { name: /Confiar en la llave de/ });
  expect(boxes).toHaveLength(2);
  await userEvent.click(boxes[1]);
  boxes.forEach((b) => expect(b).toBeChecked()); // la huella es la misma: ambos a la vista
  await userEvent.click(screen.getByRole("button", { name: "Confiar y reintentar" }));
  await waitFor(() => expect(core.changeCapture).toHaveBeenCalledTimes(2));
  expect(core.changeCapture).toHaveBeenLastCalledWith("ch1", "pre", [], [{ host: "192.0.2.1:22", fingerprint: "SHA256:same" }, { host: "192.0.2.2:22", fingerprint: "SHA256:same" }], []);
});

test("las subpestañas conservan lo escrito y Pre/Post refresca la lista sin remontarse", async () => {
  const row = { id: "ch1", name: "CRQ-1", preJobId: "", preState: "", postJobId: "", postState: "" };
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), listChanges: vi.fn().mockResolvedValueOnce([]).mockResolvedValue([row]) });
  render(<ChangeView core={core} />);
  await userEvent.type(screen.getByLabelText("Nombre del cambio"), "CRQ-1");
  await userEvent.click(screen.getByRole("tab", { name: "Upgrade" }));
  await userEvent.click(screen.getByRole("tab", { name: "Pre/Post" }));
  expect(screen.getByLabelText("Nombre del cambio")).toHaveValue("CRQ-1");
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c1");
  await userEvent.click(screen.getByRole("button", { name: "Crear cambio" }));
  await waitFor(() => expect(core.listChanges).toHaveBeenCalledTimes(3)); // montaje, volver a Pre/Post y crear
  expect(screen.getByLabelText("Nombre del cambio")).toHaveValue("CRQ-1");
});

test("al volver a Pre/Post la lista se relee: una captura que terminó habilita «Reporte»", async () => {
  const run = { id: "ch1", name: "CRQ-1", preJobId: "j1", preState: "completed", postJobId: "j2", postState: "running" };
  const listChanges = vi.fn().mockResolvedValueOnce([run]).mockResolvedValue([{ ...run, postState: "completed" }]);
  render(<ChangeView core={fakeCore({ listChanges })} />);
  await waitFor(() => expect(listChanges).toHaveBeenCalledTimes(1));
  await userEvent.click(screen.getByRole("tab", { name: "Upgrade" }));
  await userEvent.click(screen.getByRole("tab", { name: "Pre/Post" }));
  await waitFor(() => expect(listChanges).toHaveBeenCalledTimes(2));
});

test("Crear cambio nombra lo que falta y deja de hacerlo al completarlo", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [...creds, { ...creds[0], id: "c2", label: "otra" }]) });
  render(<ChangeView core={core} />);
  await screen.findAllByRole("option", { name: /otra/ });
  const go = () => screen.getByRole("button", { name: "Crear cambio" });
  expect(go()).toBeDisabled();
  expect(go()).toHaveAccessibleDescription("Falta: indicar el nombre, indicar los equipos, elegir una credencial.");
  await userEvent.type(screen.getByLabelText("Nombre del cambio"), "CRQ-1");
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  expect(go()).toHaveAccessibleDescription("Falta: elegir una credencial.");
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c1");
  expect(go()).toBeEnabled();
  expect(go()).not.toHaveAccessibleDescription();
});

test("Reporte nombra qué fase falta y lo calla cuando PRE y POST terminan", async () => {
  const mk = (post: string) => ({ id: "ch1", name: "CRQ-1", preJobId: "j1", preState: "completed", postJobId: "", postState: post });
  const show = async (post: string) => {
    const core = fakeCore({ listCredentials: vi.fn(async () => creds), listChanges: vi.fn(async () => [mk(post)]) });
    return render(<ChangeView core={core} />);
  };
  const a = await show("");
  const rep = await screen.findByRole("button", { name: /Reporte/ });
  expect(rep).toBeDisabled();
  expect(rep).toHaveAccessibleDescription("Falta: que termine POST.");
  a.unmount();
  await show("completed");
  expect(await screen.findByRole("button", { name: /Reporte/ })).toBeEnabled();
  expect(screen.getByRole("button", { name: /Reporte/ })).not.toHaveAccessibleDescription();
});

test("equipos de la libreta: etiqueta común, rellena campo y credencial, y se envía igual que a mano", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => bookCreds) });
  render(<ChangeView core={core} />);
  await screen.findByRole("option", { name: "admin lab (root)" });
  await userEvent.type(screen.getByLabelText("Nombre del cambio"), "CRQ-2");
  await pickHost("LAB-CORE");
  await pickHost("LAB-AP");
  expect(screen.getByLabelText(LABEL_MANY)).toHaveValue("10.9.0.1\nap1.lab:2222");
  expect(screen.getByLabelText("Credencial")).toHaveValue(BOOK_CRED);
  await userEvent.click(screen.getByRole("button", { name: "Crear cambio" }));
  await waitFor(() => expect(core.changeCreate).toHaveBeenCalledWith({ name: "CRQ-2", targets: [{ address: "10.9.0.1" }, { address: "ap1.lab", port: 2222 }], defaultCredentialId: BOOK_CRED, outputDir: "" }));
});
