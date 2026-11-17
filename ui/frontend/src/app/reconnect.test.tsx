import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { fakeCore } from "../lib/fake";
import type { CoreAPI } from "../lib/core";
import { I18nProvider } from "../lib/i18n";
import { vaultChanged } from "../lib/vaultSignal";
import { VaultView } from "../modules/vault/VaultView";
import { TransferView } from "../modules/transfer/TransferView";
import { ConsoleView } from "../modules/console/ConsoleView";
import { ExportDialog } from "../modules/packs/PackPersonal";
import { HostsDataCard } from "../modules/settings/HostsDataCard";
import { fakeInventory } from "../modules/inventory/fake";

// Vistas que cargan al abrir: si se abrieron sin núcleo (la app arrancó antes, o el núcleo se reinició), al reconectar
// (App avisa con vaultChanged) vuelven a cargar y el error del primer intento no se queda.
const down = "connection error: open \\\\.\\pipe\\macuahuitl: The system cannot find the file specified.";
const cases: [string, keyof CoreAPI, (core: CoreAPI) => ReactElement][] = [
  ["Bóveda", "vaultStatus", (core) => <VaultView core={core} />],
  ["Transferencias", "listInterfaces", (core) => <TransferView core={core} />],
  ["Consola serie", "fieldPorts", (core) => <ConsoleView core={core} />],
  ["Exportar paquete personal", "listScripts", (core) => <ExportDialog core={core} onClose={() => {}} />],
  ["Hosts (Ajustes)", "hostsImportFormat", (core) => <HostsDataCard core={core} />],
];

test.each(cases)("%s: abierta sin núcleo, al conectar no queda el error", async (_name, method, view) => {
  const core = fakeCore(fakeInventory());
  const real = core[method] as (...a: unknown[]) => Promise<unknown>;
  let up = false;
  (core as unknown as Record<string, unknown>)[method] = vi.fn((...a: unknown[]) => (up ? real(...a) : Promise.reject(new Error(down))));
  render(<I18nProvider>{view(core)}</I18nProvider>);
  expect(await screen.findByText(/cannot find the file/)).toBeVisible();
  up = true;
  act(() => vaultChanged());
  await waitFor(() => expect(screen.queryByText(/cannot find the file/)).toBeNull());
});

test("Consola serie: «Buscar puertos» sin núcleo tampoco deja el error al conectar", async () => {
  const core = fakeCore();
  let up = true;
  const real = core.fieldPorts;
  core.fieldPorts = vi.fn(() => (up ? real() : Promise.reject(new Error(down))));
  render(<I18nProvider><ConsoleView core={core} /></I18nProvider>);
  await screen.findByRole("button", { name: "Buscar puertos" });
  up = false;
  await userEvent.click(screen.getByRole("button", { name: "Buscar puertos" }));
  expect(await screen.findByText(/cannot find the file/)).toBeVisible();
  up = true;
  act(() => vaultChanged());
  await waitFor(() => expect(screen.queryByText(/cannot find the file/)).toBeNull());
});

test("Hosts: tras un fallo de lectura que ya se resolvió no reaparece el error viejo de una acción", async () => {
  const inv = fakeInventory();
  const core = fakeCore({ ...inv, hostsImportTemplate: vi.fn(async () => { throw new Error("fallo de la plantilla"); }) });
  render(<I18nProvider><HostsDataCard core={core} /></I18nProvider>);
  await userEvent.selectOptions(screen.getByLabelText("Qué exportar"), "some");
  await userEvent.click(screen.getByRole("button", { name: "Descargar plantilla CSV" }));
  expect(await screen.findByText("fallo de la plantilla")).toBeVisible();
  inv.listHosts.mockRejectedValueOnce(new Error(down));
  act(() => vaultChanged());
  expect(await screen.findByText(/cannot find the file/)).toBeVisible();
  act(() => vaultChanged()); // ahora la lectura sale bien
  await waitFor(() => expect(screen.queryByText(/cannot find the file/)).toBeNull());
  expect(screen.queryByText("fallo de la plantilla")).toBeNull();
});

test("Bóveda: el error de la recarga tras una acción se va cuando la carga vuelve a salir bien", async () => {
  const core = fakeCore();
  render(<I18nProvider><VaultView core={core} /></I18nProvider>);
  const lock = await screen.findByRole("button", { name: "Cerrar bóveda" });
  vi.mocked(core.vaultStatus).mockRejectedValueOnce(new Error(down)).mockRejectedValueOnce(new Error(down)); // la recarga de la acción y la del aviso
  await userEvent.click(lock);
  expect(await screen.findByText(/cannot find the file/)).toBeVisible();
  act(() => vaultChanged()); // núcleo reconectado
  await waitFor(() => expect(screen.queryByText(/cannot find the file/)).toBeNull());
});
