import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ChangeView } from "./ChangeView";
import { fakeCore } from "../../lib/fake";
import { CoreContext } from "../../app/activity";

const creds = [{ id: "c1", label: "lab", username: "admin", hasEnable: true, hasSshKey: false }];

test("crea el cambio, confirma la huella y captura PRE", async () => {
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    changeCapture: vi.fn()
      .mockResolvedValueOnce({ jobId: "j1", armed: false, detail: "Login Test falló; excluye o corrige: 192.0.2.1:22: host_key" })
      .mockResolvedValueOnce({ jobId: "j2", armed: true, detail: "" }),
    loginTest: vi.fn(async () => [{ target: "192.0.2.1:22", passed: false, failedStep: "LOGIN_TEST_STEP_HOST_KEY", detail: "nueva", platform: "", fingerprint: "SHA256:abc" }]),
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
  await userEvent.click(await screen.findByLabelText(/SHA256:abc/));
  await userEvent.click(screen.getByRole("button", { name: "Capturar PRE" }));
  expect(core.changeCapture).toHaveBeenLastCalledWith("ch1", "pre", ["SHA256:abc"], []);
  expect(await screen.findByText(/trabajo j2/)).toBeInTheDocument();
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
