import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StorageSection } from "../modules/settings/StorageSection";
import { sampleOutputsDefault } from "../modules/settings/fake";
import { PatrolView } from "../modules/patrol/PatrolView";
import { ClientPanel } from "../modules/transfer/ClientPanel";
import { CoreContext } from "../app/activity";
import { I18nProvider } from "./i18n";
import { fakeCore } from "./fake";
import { setOSForTests } from "./platform";
import type { CorePrefsState } from "../modules/settings/api";

// Una ruta de Windows rechazada no solo se pinta: bloquea el envío al núcleo.
beforeEach(() => { localStorage.clear(); setOSForTests("windows"); });
afterEach(() => setOSForTests(undefined));
const BAD = "\\\\srv\\share\\x";

test("Ajustes → Almacenamiento: con una ruta rechazada, Guardar queda apagado y no se llama al núcleo", async () => {
  const prefs: CorePrefsState = { outputsDir: "", rotateMb: 0, rotateMin: 0, maxFiles: 0, format: "", outputsDirEffective: sampleOutputsDefault, outputsDirDefault: sampleOutputsDefault, note: "" };
  const core = fakeCore({ getCorePrefs: vi.fn(async () => prefs) });
  render(<I18nProvider><CoreContext.Provider value={core}><StorageSection core={core} /></CoreContext.Provider></I18nProvider>);
  const input = await screen.findByRole("textbox", { name: "Carpeta de salidas" });
  await userEvent.type(input, "C:\\ok\\nul");
  expect(input).toHaveAccessibleDescription(/reservado por Windows/);
  expect(screen.getByRole("button", { name: "Guardar" })).toBeDisabled();
  await userEvent.clear(input);
  await userEvent.type(input, "C:\\salidas");
  await userEvent.click(screen.getByRole("button", { name: "Guardar" }));
  expect(core.setCorePrefs).toHaveBeenCalledTimes(1);
  expect(core.setCorePrefs).toHaveBeenCalledWith(expect.objectContaining({ outputsDir: "C:\\salidas" }));
});

test("Patrol: con la carpeta de salida rechazada no se crea el trabajo y se avisa", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [{ id: "c1", label: "lab", username: "admin", hasEnable: true, hasSshKey: false }]) });
  render(<PatrolView core={core} />);
  await userEvent.type(await screen.findByLabelText("Nombre del trabajo"), "caso");
  await userEvent.type(screen.getByLabelText("Equipos"), "10.0.0.1");
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c1");
  await userEvent.type(screen.getByLabelText("Comandos"), "show version");
  await userEvent.type(screen.getByLabelText("Carpeta de salida"), "\\\\?\\C:\\out".replaceAll("\\", "\\"));
  await userEvent.click(screen.getByRole("button", { name: "Crear trabajo" }));
  expect(core.createJob).not.toHaveBeenCalled();
  expect(screen.getAllByText(/rutas de red/).length).toBeGreaterThan(0);
});

test("Transferencias: con la carpeta de destino rechazada no se descarga", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => []) });
  render(<CoreContext.Provider value={core}><ClientPanel core={core} /></CoreContext.Provider>);
  await userEvent.type(screen.getByLabelText("Equipo remoto"), "192.0.2.1");
  await userEvent.type(screen.getByLabelText("Ruta remota"), "/c4.bin");
  await userEvent.type(screen.getByLabelText(/Carpeta de destino/, { selector: "input" }), BAD);
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  expect(core.transferGet).not.toHaveBeenCalled();
  expect(screen.getByLabelText(/Carpeta de destino/, { selector: "input" })).toBeInvalid();
});
