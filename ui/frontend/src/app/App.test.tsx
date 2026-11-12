import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./App";
import { fakeCore } from "../lib/fake";
import { groups, modules } from "../modules";
import { es } from "../lib/i18n/es";
import { lazyView } from "../modules/lazy";
import { useNav } from "./activity";

const nav = () => screen.getByRole("navigation", { name: "Secciones" });
const item = (name: RegExp) => within(nav()).getByRole("button", { name });

// El núcleo pudo no estar al arrancar (o reiniciarse): al volver se le manda otra vez el idioma, si no contesta en español.
test("al reconectar el núcleo se le manda otra vez el idioma de la interfaz", async () => {
  const core = fakeCore();
  render(<App core={core} />);
  await act(async () => {});
  expect(core.setPreference).toHaveBeenCalledTimes(1);
  act(() => core.emitStatus("disconnected"));
  act(() => core.emitStatus("connected"));
  await act(async () => {}); // la llamada sale en fila, tras la anterior
  expect(core.setPreference).toHaveBeenCalledTimes(2);
  expect(core.setPreference).toHaveBeenLastCalledWith("ui.language", "es");
});

test("muestra el aviso de núcleo desconectado y lo quita al reconectar", async () => {
  const core = fakeCore();
  render(<App core={core} />);
  // Espera la respuesta inicial de coreStatus para que no pise el evento.
  await act(async () => {});
  act(() => core.emitStatus("disconnected"));
  expect(await screen.findByRole("alert")).toHaveTextContent("Núcleo desconectado");
  expect(screen.getByText("Núcleo desconectado")).toBeInTheDocument();
  act(() => core.emitStatus("connected"));
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(screen.getByText("Núcleo conectado")).toBeInTheDocument();
});

test("pide el estado al montar: el núcleo caído al abrir muestra el aviso", async () => {
  const core = fakeCore({ coreStatus: vi.fn(async () => "disconnected" as const) });
  render(<App core={core} />);
  expect(await screen.findByRole("alert")).toHaveTextContent("Núcleo desconectado");
});

test("abre en Patrol y un módulo directo cambia la vista", async () => {
  render(<App core={fakeCore()} />);
  expect(await screen.findByRole("heading", { name: "Nuevo trabajo" })).toBeVisible();
  expect(item(/^Patrol/)).toHaveAttribute("aria-current", "page");
  await userEvent.click(item(/^Bóveda/));
  expect(await screen.findByRole("heading", { name: "Bóveda" })).toBeVisible();
  expect(item(/^Bóveda/)).toHaveAttribute("aria-current", "page");
  expect(screen.queryByRole("heading", { name: "Nuevo trabajo" })).not.toBeInTheDocument();
});

test("un grupo abre su panel al dar click y elegir una opción lo cierra", async () => {
  render(<App core={fakeCore()} />);
  const g = item(/^Diagnóstico/);
  expect(g).toHaveAttribute("aria-expanded", "false");
  expect(screen.queryByRole("button", { name: "Traceroute" })).not.toBeInTheDocument();
  await userEvent.click(g);
  expect(g).toHaveAttribute("aria-expanded", "true");
  await userEvent.click(screen.getByRole("button", { name: "Traceroute" }));
  expect(g).toHaveAttribute("aria-expanded", "false");
  expect(await screen.findByRole("heading", { name: "Traceroute" })).toBeVisible();
  expect(g).toHaveAttribute("aria-current", "page");
  expect(g).toHaveTextContent("Traceroute");
});

test("pasar el mouse por un grupo abre su panel", async () => {
  render(<App core={fakeCore()} />);
  await userEvent.hover(item(/^Análisis/));
  expect(screen.getByRole("button", { name: "ACL" })).toBeInTheDocument();
});

test("teclado: flecha derecha abre el grupo, las flechas recorren y Escape regresa", async () => {
  render(<App core={fakeCore()} />);
  const g = item(/^Diagnóstico/);
  act(() => g.focus());
  await userEvent.keyboard("{ArrowRight}");
  expect(screen.getByRole("button", { name: "Ping" })).toHaveFocus();
  await userEvent.keyboard("{ArrowDown}");
  expect(screen.getByRole("button", { name: "Traceroute" })).toHaveFocus();
  await userEvent.keyboard("{ArrowUp}{ArrowUp}");
  expect(screen.getByRole("button", { name: "Captura" })).toHaveFocus();
  await userEvent.keyboard("{Escape}");
  expect(g).toHaveFocus();
  expect(g).toHaveAttribute("aria-expanded", "false");
});

test("al volver a un módulo conserva lo que tenía", async () => {
  render(<App core={fakeCore()} />);
  await userEvent.click(item(/^Análisis/));
  await userEvent.click(screen.getByRole("button", { name: "ACL" }));
  await userEvent.type(await screen.findByLabelText("ACL a importar"), "permit ip any any");
  await userEvent.click(item(/^Patrol/));
  await userEvent.click(item(/^Análisis/));
  await userEvent.click(screen.getByRole("button", { name: "ACL" }));
  expect(screen.getByLabelText("ACL a importar")).toHaveValue("permit ip any any");
});

test("un diagnóstico en curso se marca en la barra aunque cambies de módulo", async () => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r1") });
  render(<App core={core} />);
  await userEvent.click(item(/^Diagnóstico/));
  await userEvent.click(screen.getByRole("button", { name: "Ping" }));
  await userEvent.type(await screen.findByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await userEvent.click(item(/^Patrol/));
  expect(item(/^Diagnóstico/)).toHaveAccessibleDescription("En curso");
  act(() => core.emitDiag({ runId: "r1", done: true, exitCode: 0, outputPath: "/tmp/x" }));
  expect(item(/^Diagnóstico/)).not.toHaveAccessibleDescription("En curso");
});

test("al terminar una captura, Analizar captura abre PCAP con el archivo puesto", async () => {
  const core = fakeCore({ diagRun: vi.fn(async () => "c1") });
  render(<App core={core} />);
  await userEvent.click(item(/^Diagnóstico/));
  await userEvent.click(screen.getByRole("button", { name: "Captura" }));
  await userEvent.click(await screen.findByRole("button", { name: "Ejecutar" }));
  act(() => core.emitDiag({ runId: "c1", done: true, exitCode: 0, outputPath: "/home/u/out/cap.pcapng" }));
  await userEvent.click(await screen.findByRole("button", { name: "Analizar captura" }));
  expect(await screen.findByRole("heading", { name: "Análisis de captura" })).toBeVisible();
  // La vista se carga bajo demanda: la ruta llega con el efecto de su primer montaje.
  await waitFor(() => expect(screen.getByLabelText("Archivo de captura")).toHaveValue("/home/u/out/cap.pcapng"));
  expect(item(/^Análisis/)).toHaveAttribute("aria-current", "page");
});

test("el manifiesto: ids únicos y cada módulo se alcanza desde la barra", async () => {
  const ids = modules.map((m) => m.id);
  expect(new Set(ids).size).toBe(ids.length);
  render(<App core={fakeCore()} />);
  for (const m of modules) {
    const label = es[m.label];
    if (m.group) {
      await userEvent.click(item(new RegExp(`^${es[groups[m.group].label]}`)));
      await userEvent.click(screen.getByRole("button", { name: label }));
    } else {
      await userEvent.click(item(new RegExp(`^${label}`)));
    }
    expect(document.querySelectorAll(".view:not([hidden])")).toHaveLength(1);
  }
  expect(document.querySelectorAll(".view")).toHaveLength(modules.length);
}, 60_000);

test("Operación agrupa los módulos de operación y Análisis suma Deriva, Limpiador y Flota", async () => {
  render(<App core={fakeCore()} />);
  await userEvent.click(item(/^Operación/));
  for (const n of ["Puertos", "Lotes", "Snippets", "Rotar credenciales", "Respaldos"]) {
    expect(screen.getByRole("button", { name: n })).toBeInTheDocument();
  }
  await userEvent.click(item(/^Análisis/));
  for (const n of ["Deriva", "Limpiador", "Flota"]) expect(screen.getByRole("button", { name: n })).toBeInTheDocument();
});

test("Acceso es el primer grupo de la barra: SSH y Consola serie", async () => {
  expect(Object.keys(groups)[0]).toBe("access");
  render(<App core={fakeCore()} />);
  const buttons = within(nav()).getAllByRole("button");
  expect(buttons.findIndex((b) => /^Acceso/.test(b.textContent ?? ""))).toBeLessThan(buttons.findIndex((b) => /^Diagnóstico/.test(b.textContent ?? "")));
  await userEvent.click(item(/^Acceso/));
  expect(screen.getByRole("button", { name: "SSH" })).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Consola serie" }));
  expect(await screen.findByRole("heading", { name: "Consola serie" })).toBeVisible();
  await userEvent.click(item(/^Acceso/));
  await userEvent.click(screen.getByRole("button", { name: "SSH" }));
  expect(await screen.findByRole("region", { name: "Terminal SSH" })).toBeVisible();
});

test("en inglés la barra y los módulos de Acceso salen en inglés", async () => {
  render(<App core={fakeCore()} />);
  // El botón de la barra de estado abre Ajustes, donde viven idioma y tema.
  await userEvent.click(screen.getByRole("button", { name: /^Idioma, tema y terminal/ }));
  await userEvent.click(screen.getByRole("radio", { name: "English" }));
  await userEvent.click(within(screen.getByRole("navigation", { name: "Sections" })).getByRole("button", { name: /^Access/ }));
  await userEvent.click(screen.getByRole("button", { name: "Serial console" }));
  expect(await screen.findByRole("heading", { name: "Serial console" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Scan ports" })).toBeInTheDocument();
});

test("initial abre ese módulo al arrancar; uno desconocido cae al primero", async () => {
  localStorage.clear(); // otra prueba pudo dejar el idioma en inglés
  const { unmount } = render(<App core={fakeCore()} initial="vault" />);
  expect(await screen.findByRole("heading", { name: "Bóveda" })).toBeVisible();
  unmount();
  render(<App core={fakeCore()} initial="no-existe" />);
  expect(await screen.findByRole("heading", { name: "Nuevo trabajo" })).toBeVisible();
});

test("el botón de preferencias de la barra de estado abre Ajustes", async () => {
  localStorage.clear();
  render(<App core={fakeCore()} />);
  await userEvent.click(screen.getByRole("button", { name: /^Idioma, tema y terminal/ }));
  expect(await screen.findByRole("heading", { name: "Ajustes" })).toBeVisible();
  expect(item(/^Ajustes/)).toHaveAttribute("aria-current", "page");
});

test("cambiar de módulo no vuelve a renderizar las vistas que quedaron montadas y ocultas", async () => {
  let renders = 0;
  const Contador = () => { useNav(); renders++; return <p>contador</p>; };
  const original = modules[0].view;
  modules[0].view = lazyView(async () => ({ Contador }), "Contador");
  try {
    render(<App core={fakeCore()} />);
    expect(await screen.findByText("contador")).toBeInTheDocument();
    const base = renders;
    await userEvent.click(item(/^Bóveda/));
    expect(await screen.findByRole("heading", { name: "Bóveda" })).toBeVisible();
    await userEvent.click(item(/^Auditoría/));
    expect(await screen.findByRole("heading", { name: "Auditoría" })).toBeVisible();
    expect(renders).toBe(base);
  } finally {
    modules[0].view = original;
  }
});

test("abrir la app no precarga vistas; pasar el puntero o enfocar una entrada sí precarga la suya", async () => {
  const bottom = modules.find((m) => m.bottom)!;
  const spies = modules.map((m) => vi.spyOn(m.view, "preload").mockResolvedValue());
  render(<App core={fakeCore()} />);
  await act(async () => {});
  expect(spies.every((s) => s.mock.calls.length === 0)).toBe(true);
  const entry = screen.getAllByRole("button", { name: new RegExp(`^${es[bottom.label as keyof typeof es]}`) }).find((b) => b.classList.contains("nav-item"))!;
  await userEvent.hover(entry);
  expect(vi.mocked(bottom.view.preload)).toHaveBeenCalled();
  spies.forEach((s) => s.mockRestore());
});
