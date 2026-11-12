import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SettingsView } from "./SettingsView";
import { I18nProvider } from "../../lib/i18n";
import { resetTheme } from "../../lib/theme";
import { resetTermPrefs, setTermPrefs } from "../../lib/termPrefs";
import { fakeCore } from "../../lib/fake";


const view = (core = fakeCore()) => render(<I18nProvider><SettingsView core={core} /></I18nProvider>);

beforeEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.theme;
  resetTheme();
  resetTermPrefs();
});

test("muestra las secciones Apariencia, Idioma, Terminal y Datos", () => {
  view();
  expect(screen.getByRole("heading", { name: "Ajustes" })).toBeVisible();
  for (const n of ["Apariencia", "Idioma", "Terminal", "Datos"]) expect(screen.getByRole("heading", { name: n })).toBeVisible();
  expect(screen.getByRole("heading", { name: "Hosts" })).toBeVisible(); // tarjeta de datos de la libreta
  expect(screen.getByRole("heading", { name: "Almacenamiento" })).toBeVisible();
  expect(screen.queryByText(/Todavía no está disponible/)).toBeNull(); // la bóveda ya tiene su tarjeta
});

test("el tema se aplica al momento", async () => {
  view();
  await userEvent.click(screen.getByRole("radio", { name: "Oscuro" }));
  expect(document.documentElement.dataset.theme).toBe("dark");
});

test("el idioma cambia los textos y <html lang>", async () => {
  view();
  await userEvent.click(screen.getByRole("radio", { name: "English" }));
  expect(await screen.findByRole("heading", { name: "Settings" })).toBeVisible();
  expect(document.documentElement.lang).toBe("en");
});

test("la paleta se elige con su muestra y se guarda en las preferencias de terminal", async () => {
  view();
  await userEvent.click(screen.getByRole("radio", { name: "Ámbar (P3)" }));
  expect(JSON.parse(localStorage.getItem("macuahuitl.terminal")!).palette).toBe("p3");
  expect(screen.getByRole("radio", { name: "Ámbar (P3)" })).toBeChecked();
});

test("resaltado y lector de pantalla usan las preferencias de terminal", async () => {
  view();
  await userEvent.click(screen.getByRole("checkbox", { name: "Resaltar palabras clave" }));
  await userEvent.click(screen.getByRole("checkbox", { name: "Modo lector de pantalla" }));
  expect(JSON.parse(localStorage.getItem("macuahuitl.terminal")!)).toMatchObject({ hl: false, srm: true });
});

test("refleja lo que cambie otra pantalla (misma tienda)", () => {
  view();
  expect(screen.getByRole("checkbox", { name: "Resaltar palabras clave" })).toBeChecked();
  act(() => setTermPrefs({ hl: false }));
  expect(screen.getByRole("checkbox", { name: "Resaltar palabras clave" })).not.toBeChecked();
});

describe("Datos", () => {
  const card = (name: string) => screen.getByRole("article", { name });
  const TPL = '{"formato":"macuahuitl-scripts","version":1,"scripts":[{"id":"x"}]}';

  test("la tarjeta solo resume (título, qué contiene, formato y botones); la tabla de campos no está en ella", async () => {
    const core = fakeCore();
    view(core);
    const c = card("Scripts");
    await waitFor(() => expect(core.importFormat).toHaveBeenCalledWith("scripts"));
    expect(within(c).getByText("Formato aceptado: JSON.")).toBeVisible();
    expect(within(c).queryByText(/suma sha256/)).toBeNull();
    expect(within(c).queryByRole("table")).toBeNull();
    for (const n of ["Descargar plantilla de ejemplo", "Exportar todo", "Importar…"]) expect(within(c).getByRole("button", { name: n })).toBeVisible();
    expect(within(c).getByRole("button", { name: /^Ver detalles · / })).toBeVisible(); // el nombre accesible nombra la tarjeta
    expect(within(card("Bóveda")).getByRole("button", { name: "Abrir la bóveda" })).toBeVisible();
  });

  test.each([["Scripts", "scripts"], ["Colecciones de scripts", "colecciones"]])("«Ver detalles» de %s abre un diálogo con la tabla de campos que da el núcleo", async (name, kind) => {
    const core = fakeCore();
    view(core);
    await userEvent.click(within(card(name)).getByRole("button", { name: /^Ver detalles/ }));
    const d = await screen.findByRole("dialog", { name: `Detalles · ${name}` });
    expect(core.importFormat).toHaveBeenCalledWith(kind);
    const rows = within(await within(d).findByRole("table", { name: /Campos del archivo/ })).getAllByRole("row");
    expect(within(rows[0]).getByText("Obligatorio")).toBeVisible();
    expect(within(rows[1]).getByText("Texto")).toBeVisible(); // «texto» del núcleo, en el idioma elegido
    expect(within(rows[1]).getByText("Sí")).toBeVisible();
    expect(within(d).getByText(/La suma sha256 es opcional/)).toBeVisible();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(within(card(name)).getByRole("button", { name: /^Ver detalles/ })).toHaveFocus();
  });

  test("descargar la plantilla pide dónde guardar y escribe el contenido que da el núcleo", async () => {
    const core = fakeCore({ importTemplate: vi.fn(async () => TPL) });
    view(core);
    await userEvent.click(within(card("Scripts")).getByRole("button", { name: "Descargar plantilla de ejemplo" }));
    await waitFor(() => expect(core.writeFile).toHaveBeenCalledWith("/home/u/Descargas/plantilla-scripts.json", TPL, "utf8", true));
    expect(core.importTemplate).toHaveBeenCalledWith("scripts");
    expect(await screen.findByText("Plantilla guardada en /home/u/Descargas/plantilla-scripts.json.")).toBeVisible();
    await userEvent.click(within(card("Colecciones de scripts")).getByRole("button", { name: "Descargar plantilla de ejemplo" }));
    await waitFor(() => expect(core.importTemplate).toHaveBeenCalledWith("colecciones"));
    expect(core.writeFile).toHaveBeenLastCalledWith("/home/u/Descargas/plantilla-colecciones.json", expect.any(String), "utf8", true);
  });

  test("si la persona cancela el diálogo de guardar no se escribe nada", async () => {
    const core = fakeCore({ pickSavePath: vi.fn(async () => "") });
    view(core);
    await userEvent.click(within(card("Scripts")).getByRole("button", { name: "Descargar plantilla de ejemplo" }));
    await waitFor(() => expect(core.pickSavePath).toHaveBeenCalled());
    expect(core.writeFile).not.toHaveBeenCalled();
  });

  test("exportar todo: scripts propios y todas las colecciones", async () => {
    const core = fakeCore();
    await core.setScriptFavorite("a".repeat(32), true); // favoritos con algo: si no, no hay nada que exportar
    view(core);
    await userEvent.click(within(card("Scripts")).getByRole("button", { name: "Exportar todo" }));
    await waitFor(() => expect(core.exportScripts).toHaveBeenCalledWith(["a".repeat(32)], "/home/u/Descargas/scripts.json", true)); // solo el propio, no la biblioteca
    await userEvent.click(within(card("Colecciones de scripts")).getByRole("button", { name: "Exportar todo" }));
    await waitFor(() => expect(core.exportCollections).toHaveBeenCalledWith(["favoritos"], "/home/u/Descargas/colecciones.json", true));
  });

  test("si exportar falla se borra el archivo vacío que dejó el diálogo", async () => {
    const core = fakeCore({ exportScripts: vi.fn(async () => { throw new Error("disco lleno"); }) });
    await core.setScriptFavorite("a".repeat(32), true);
    view(core);
    await userEvent.click(within(card("Scripts")).getByRole("button", { name: "Exportar todo" }));
    await waitFor(() => expect(core.removeEmptyFile).toHaveBeenCalledWith("/home/u/Descargas/scripts.json"));
    expect(await within(card("Scripts")).findByText(/disco lleno/)).toBeVisible();
  });

  test("con solo la colección favoritos vacía, exportar colecciones avisa y no llama al núcleo", async () => {
    const core = fakeCore();
    view(core);
    await userEvent.click(within(card("Colecciones de scripts")).getByRole("button", { name: "Exportar todo" }));
    expect(await within(card("Colecciones de scripts")).findByText("No hay nada que exportar todavía.")).toBeVisible();
    expect(core.exportCollections).not.toHaveBeenCalled();
  });

  test("sin scripts propios, exportar avisa y no llama al núcleo", async () => {
    const core = fakeCore({ listScripts: vi.fn(async () => []) });
    view(core);
    await userEvent.click(within(card("Scripts")).getByRole("button", { name: "Exportar todo" }));
    expect(await screen.findByText("No hay nada que exportar todavía.")).toBeVisible();
    expect(core.exportScripts).not.toHaveBeenCalled();
  });

  test("importar colecciones desde Ajustes muestra la vista previa con sus avisos", async () => {
    const core = fakeCore({ pickPath: vi.fn(async () => "/x.json") });
    view(core);
    await userEvent.click(within(card("Colecciones de scripts")).getByRole("button", { name: "Importar…" }));
    const preview = await screen.findByRole("region", { name: "Vista previa de la importación de colecciones" });
    expect(within(preview).getByText(/Colección «Nueva»: el script lib-de-otra-version no está en la biblioteca local y se omitirá\./)).toBeVisible();
  });

  test("importar scripts desde Ajustes avisa de que el archivo no trae suma", async () => {
    const core = fakeCore({ pickPath: vi.fn(async () => "/x.json") });
    view(core);
    await userEvent.click(within(card("Scripts")).getByRole("button", { name: "Importar…" }));
    expect(await screen.findByText(/El archivo no trae suma de verificación/)).toBeVisible();
  });

  test("en inglés: títulos, tipos y plantilla salen en inglés", async () => {
    localStorage.setItem("macuahuitl.idioma", "en");
    const core = fakeCore();
    view(core);
    const c = card("Scripts");
    await userEvent.click(within(c).getByRole("button", { name: /^Show details/ }));
    const d = await screen.findByRole("dialog", { name: "Details · Scripts" });
    expect(await within(d).findByRole("table", { name: /File fields/ })).toBeVisible();
    expect(within(d).getAllByText("Text").length).toBeGreaterThan(0);
    expect(within(d).getByText(/Accepted format: JSON\. The sha256 checksum is optional/)).toBeVisible();
    expect(d.textContent).not.toMatch(/[áéíóúñ¿¡«»]|Campo|Obligatorio|Detalles/);
    await userEvent.keyboard("{Escape}");
    expect(screen.getByRole("article", { name: "Script collections" })).toBeVisible();
    await userEvent.click(within(c).getByRole("button", { name: "Download example template" }));
    await waitFor(() => expect(core.pickSavePath).toHaveBeenCalledWith("scripts-template.json"));
  });
});
