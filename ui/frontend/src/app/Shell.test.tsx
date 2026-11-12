import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./App";
import { fakeCore } from "../lib/fake";
import { resetTheme } from "../lib/theme";
import { vaultChanged } from "../lib/vaultSignal";

beforeEach(() => {
  localStorage.clear(); // otra prueba pudo dejar idioma, tema o recientes
  delete document.documentElement.dataset.theme;
  resetTheme();
});

const palette = async () => {
  await userEvent.keyboard("{Control>}k{/Control}");
  return screen.findByRole("dialog", { name: "Paleta de comandos" });
};
const statusbar = () => screen.getByRole("contentinfo", { name: "Barra de estado" });

test("Ctrl+K abre la paleta con el foco en la búsqueda; Enter va al módulo y la cierra", async () => {
  render(<App core={fakeCore()} />);
  const dlg = await palette();
  const input = within(dlg).getByRole("combobox");
  expect(input).toHaveFocus();
  await userEvent.type(input, "rot");
  expect(within(dlg).getByRole("option", { name: /Rotar credenciales/ })).toHaveAttribute("aria-selected", "true");
  await userEvent.keyboard("{Enter}");
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(await screen.findByRole("heading", { name: "Rotar credenciales" })).toBeVisible();
});

test("la búsqueda ignora acentos y encuentra por el nombre en el otro idioma", async () => {
  render(<App core={fakeCore()} />);
  const dlg = await palette();
  const input = within(dlg).getByRole("combobox");
  await userEvent.type(input, "credentials");
  expect(within(dlg).getByRole("option", { name: /Rotar credenciales/ })).toBeInTheDocument();
  await userEvent.clear(input);
  await userEvent.type(input, "boveda");
  expect(within(dlg).getByRole("option", { name: /Bóveda/ })).toBeInTheDocument();
  await userEvent.clear(input);
  await userEvent.type(input, "zzzz");
  expect(within(dlg).getByText(/Sin resultados/)).toBeInTheDocument();
});

test("las flechas mueven la selección y Escape cierra la paleta", async () => {
  render(<App core={fakeCore()} />);
  const dlg = await palette();
  const opts = within(dlg).getAllByRole("option");
  expect(opts[0]).toHaveAttribute("aria-selected", "true");
  await userEvent.keyboard("{ArrowDown}");
  expect(opts[1]).toHaveAttribute("aria-selected", "true");
  expect(opts[0]).toHaveAttribute("aria-selected", "false");
  await userEvent.keyboard("{Escape}");
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

test("una acción de la paleta cambia el tema", async () => {
  render(<App core={fakeCore()} />);
  const dlg = await palette();
  await userEvent.type(within(dlg).getByRole("combobox"), "tema oscuro");
  await userEvent.keyboard("{Enter}");
  expect(document.documentElement.dataset.theme).toBe("dark");
});

test("el disparador de la barra de título abre la misma paleta", async () => {
  render(<App core={fakeCore()} />);
  await userEvent.click(screen.getByRole("button", { name: /Buscar o ir a/ }));
  expect(await screen.findByRole("dialog", { name: "Paleta de comandos" })).toBeInTheDocument();
});

test("Ctrl+B contrae y expande la barra lateral", async () => {
  render(<App core={fakeCore()} />);
  const toggle = screen.getByRole("button", { name: "Contraer la barra lateral" });
  expect(toggle).toHaveAttribute("aria-expanded", "true");
  await userEvent.keyboard("{Control>}b{/Control}");
  expect(toggle).toHaveAttribute("aria-expanded", "false");
  await userEvent.click(toggle);
  expect(toggle).toHaveAttribute("aria-expanded", "true");
});

test("la barra de estado muestra núcleo, bóveda y Patrol, y lleva a cada módulo", async () => {
  const core = fakeCore({
    vaultStatus: vi.fn(async () => ({ state: "locked" as const, armedJobs: [] })),
    listJobs: vi.fn(async () => [{ id: "j1", name: "nocturno", state: "armed" }]),
  });
  render(<App core={core} />);
  const bar = statusbar();
  expect(within(bar).getByRole("button", { name: /Núcleo conectado/ })).toBeInTheDocument();
  expect(await within(bar).findByRole("button", { name: /Patrol: 1 armado/ })).toBeInTheDocument();
  await userEvent.click(await within(bar).findByRole("button", { name: /Bóveda cerrada/ }));
  expect(await screen.findByRole("heading", { name: "Bóveda" })).toBeVisible();
});

test("una ejecución asistida viva muestra la franja roja y el segmento, y la franja lleva al módulo", async () => {
  localStorage.setItem("macuahuitl.assist.r1", "ports");
  const core = fakeCore({ assistListRuns: vi.fn(async () => [{ runId: "r1", active: true, state: "waiting-confirm", devices: ["SW1", "SW2"] }]) });
  render(<App core={core} />);
  const strip = await screen.findByRole("alert");
  expect(strip).toHaveTextContent("Modo de cambio asistido activo");
  expect(strip).toHaveTextContent("2 equipos");
  expect(within(statusbar()).getByRole("button", { name: /Cambio asistido en curso/ })).toBeInTheDocument();
  await userEvent.click(within(strip).getByRole("button", { name: "Ir a la ejecución" }));
  expect(await screen.findByRole("heading", { name: "Puertos de acceso" })).toBeVisible();
});

test("sin ejecución asistida viva no hay franja", async () => {
  render(<App core={fakeCore()} />);
  await act(async () => {});
  expect(screen.queryByText(/Modo de cambio asistido activo/)).not.toBeInTheDocument();
});

test("Ctrl+Enter ejecuta la acción principal de la vista", async () => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r1") });
  render(<App core={core} initial="ping" />);
  await userEvent.type(await screen.findByLabelText("Destino"), "10.0.0.1");
  await userEvent.keyboard("{Control>}{Enter}{/Control}");
  await waitFor(() => expect(core.diagRun).toHaveBeenCalled());
  expect(within(statusbar()).getByRole("button", { name: /1 en curso/ })).toBeInTheDocument();
});

test("Ctrl+Enter en la paleta solo abre el módulo: no pulsa el primario de ninguna vista", async () => {
  // En la app, el foco está en la paleta: ni la vista que se deja ni la que se abre deben ejecutar nada.
  const auditVerify = vi.fn(async () => ({ intact: true, firstBroken: 0, head: "" }));
  render(<App core={fakeCore({ auditVerify })} initial="audit" />);
  expect(await screen.findByRole("heading", { name: "Auditoría" })).toBeVisible();
  await userEvent.type(within(await palette()).getByRole("combobox"), "ping");
  await userEvent.keyboard("{Control>}{Enter}{/Control}");
  expect(await screen.findByRole("heading", { name: "Ping" })).toBeVisible();
  await act(async () => {});
  expect(auditVerify).not.toHaveBeenCalled();
});

test("Ctrl+Enter pulsa el primario de la sección donde está el foco", async () => {
  const acl = { name: "EDGE", rules: [], remarks: [] };
  const core = fakeCore({ aclImport: vi.fn(async () => acl), aclAnalyze: vi.fn(async () => []), aclGenerate: vi.fn(async () => "ip access-list NEW") });
  render(<App core={core} initial="acl" />);
  await userEvent.type(await screen.findByLabelText("ACL a importar"), "access-list EDGE extended permit tcp any any");
  await userEvent.keyboard("{Control>}{Enter}{/Control}");
  const dest = await screen.findByLabelText("Plataforma de destino");
  await userEvent.selectOptions(dest, "nx-os");
  dest.focus();
  await userEvent.keyboard("{Control>}{Enter}{/Control}");
  await waitFor(() => expect(core.aclGenerate).toHaveBeenCalled());
  expect(core.aclImport).toHaveBeenCalledTimes(1);
});

test("Alt+← vuelve al módulo anterior", async () => {
  render(<App core={fakeCore()} />);
  await userEvent.click(await within(statusbar()).findByRole("button", { name: /Bóveda/ }));
  expect(await screen.findByRole("heading", { name: "Bóveda" })).toBeVisible();
  await userEvent.keyboard("{Alt>}{ArrowLeft}{/Alt}");
  expect(await screen.findByRole("heading", { name: "Nuevo trabajo" })).toBeVisible();
});

test("la barra de título muestra dónde se está", async () => {
  render(<App core={fakeCore()} initial="ping" />);
  expect(screen.getByRole("navigation", { name: "Ubicación" })).toHaveTextContent("Diagnóstico›Ping");
});

test("la barra de estado se actualiza en cuanto cambia la bóveda, sin esperar el sondeo", async () => {
  let state: "absent" | "unlocked" = "absent";
  const vaultStatus = vi.fn(async () => ({ state, armedJobs: [] }));
  render(<App core={fakeCore({ vaultStatus })} />);
  expect(await within(statusbar()).findByRole("button", { name: /Sin bóveda/ })).toBeInTheDocument();
  state = "unlocked";
  act(() => vaultChanged());
  expect(await within(statusbar()).findByRole("button", { name: /Bóveda abierta/ })).toBeInTheDocument();
});

test("con el foco dentro de una terminal xterm los atajos globales no actúan: las teclas son del equipo", async () => {
  render(<App core={fakeCore()} />);
  const host = document.body.appendChild(document.createElement("div"));
  host.className = "xterm";
  host.appendChild(document.createElement("textarea")).focus();
  await userEvent.keyboard("{Control>}k{/Control}");
  await userEvent.keyboard("{Control>}/{/Control}");
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  host.remove();
  await userEvent.keyboard("{Control>}k{/Control}"); // fuera de la terminal sí
  expect(await screen.findByRole("dialog", { name: "Paleta de comandos" })).toBeInTheDocument();
});

test("Ctrl+Enter no pulsa el primario de un panel oculto (la pestaña Cliente de Transferencias mientras se ve Servidor)", async () => {
  const core = fakeCore();
  render(<App core={core} initial="transfer" />);
  // El caso peligroso: un formulario de cliente ya lleno en la pestaña que queda oculta.
  await userEvent.click(await screen.findByRole("tab", { name: /Cliente/ }));
  await userEvent.type(await screen.findByLabelText(/Equipo remoto/), "10.0.0.1");
  await userEvent.type(screen.getByLabelText(/Ruta remota/), "c9300.bin");
  await userEvent.click(screen.getByRole("tab", { name: /Servidor/ }));
  await userEvent.keyboard("{Control>}{Enter}{/Control}");
  await act(async () => {});
  expect(core.transferGet).not.toHaveBeenCalled();
  expect(core.transferGetAsync).not.toHaveBeenCalled();
  expect(core.transferPut).not.toHaveBeenCalled();
});
