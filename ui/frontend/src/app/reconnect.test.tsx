import { act, render, screen, waitFor } from "@testing-library/react";
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
