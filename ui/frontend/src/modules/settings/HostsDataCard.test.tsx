import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HostsDataCard } from "./HostsDataCard";
import { fakeInventory } from "../inventory/fake";
import { fakeCore } from "../../lib/fake";
import { I18nProvider } from "../../lib/i18n";
import { hostsChanged } from "../inventory/signal";

const setup = (over = {}) => {
  const core = fakeCore({ ...fakeInventory(), pickPath: vi.fn(async () => "/home/u/hosts.csv"), ...over });
  render(<I18nProvider><HostsDataCard core={core} /></I18nProvider>);
  return core;
};
beforeEach(() => localStorage.clear());

test("la tarjeta solo resume: qué contiene, formatos aceptados y botones; sin tabla ni notas", async () => {
  const core = setup();
  await waitFor(() => expect(core.hostsImportFormat).toHaveBeenCalled());
  expect(screen.getByText(/La libreta de hosts/)).toBeVisible();
  expect(screen.getByText("Formatos aceptados: CSV y JSON.")).toBeVisible();
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.queryByText(/CSV sirve para Excel/)).toBeNull();
  expect(screen.queryByText(/Hasta 1000 hosts/)).toBeNull();
  expect(screen.queryByText(/valores de ejemplo de la plantilla/)).toBeNull();
  for (const n of ["Descargar plantilla CSV", "Descargar plantilla JSON", "Exportar hosts", "Importar…"]) expect(screen.getByRole("button", { name: n })).toBeVisible();
  expect(screen.getByRole("button", { name: /^Ver detalles · / })).toBeVisible(); // el nombre accesible nombra la tarjeta
});

test("«Ver detalles» abre el diálogo con la tabla de campos del núcleo, las notas y los límites; Cerrar devuelve el foco", async () => {
  setup();
  const open = screen.getByRole("button", { name: /^Ver detalles/ });
  await userEvent.click(open);
  const d = await screen.findByRole("dialog", { name: "Detalles · Hosts" });
  const fields = await within(d).findByRole("table", { name: "Campos del archivo" });
  expect(within(fields).getAllByRole("row")).toHaveLength(9); // encabezado + 8 campos
  expect(within(fields).getByText("credential_label")).toBeVisible();
  expect(within(d).getByText(/CSV sirve para Excel/)).toBeVisible();
  expect(within(d).getByText("Hasta 1000 hosts y 5 MB por archivo.")).toBeVisible();
  expect(within(d).getByText(/valores de ejemplo de la plantilla/)).toBeVisible();
  await userEvent.click(within(d).getByRole("button", { name: "Cerrar" }));
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(open).toHaveFocus();
});

test.each([["csv", "Descargar plantilla CSV"], ["json", "Descargar plantilla JSON"]] as const)("plantilla %s: pide la ruta y escribe el contenido", async (format, name) => {
  const core = setup();
  await userEvent.click(screen.getByRole("button", { name }));
  expect(core.hostsImportTemplate).toHaveBeenCalledWith(format);
  expect(core.pickSavePath).toHaveBeenCalledWith(`hosts-plantilla.${format}`);
  const [path, data, enc, overwrite] = (core.writeFile as ReturnType<typeof vi.fn>).mock.calls[0];
  expect([path, enc, overwrite]).toEqual([`/home/u/Descargas/hosts-plantilla.${format}`, "utf8", true]);
  if (format === "csv") expect(data.startsWith("﻿name,address,port,platform,folder,tags,credential_label,notes")).toBe(true);
  else expect(JSON.parse(data).hosts).toHaveLength(3);
  expect(await screen.findByText(`Plantilla guardada en /home/u/Descargas/hosts-plantilla.${format}.`)).toBeVisible();
});

test("cancelar el diálogo de guardar no escribe nada", async () => {
  const core = setup({ pickSavePath: vi.fn(async () => "") });
  await userEvent.click(screen.getByRole("button", { name: "Descargar plantilla CSV" }));
  expect(core.writeFile).not.toHaveBeenCalled();
});

test("exportar todos manda ids vacíos y el formato elegido; elegir hosts manda solo los marcados", async () => {
  const core = setup();
  await userEvent.selectOptions(screen.getByLabelText("Formato"), "json");
  await userEvent.click(screen.getByRole("button", { name: "Exportar hosts" }));
  expect(core.exportHosts).toHaveBeenCalledWith([], "/home/u/Descargas/hosts.json", true, "json");
  expect(await screen.findByText("Se exportaron 3 hosts a /home/u/Descargas/hosts.json.")).toBeVisible();
  await userEvent.selectOptions(screen.getByLabelText("Formato"), "csv");
  await userEvent.selectOptions(screen.getByLabelText("Qué exportar"), "some");
  await userEvent.click(await screen.findByRole("checkbox", { name: /LAB-AP/ }));
  await userEvent.click(screen.getByRole("button", { name: "Exportar hosts" }));
  expect(core.exportHosts).toHaveBeenLastCalledWith(["b".repeat(32)], "/home/u/Descargas/hosts.csv", true, "csv");
});

test("la vista previa muestra el error de cada línea y los estados; solo se aplican las filas válidas con sus decisiones", async () => {
  const core = setup();
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  expect(core.previewHostsImport).toHaveBeenCalledWith("/home/u/hosts.csv");
  const errors = await screen.findByRole("table", { name: "Filas inválidas del archivo" });
  const rows = within(errors).getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell").map((c) => c.textContent));
  expect(rows).toEqual([["14", "address", expect.stringContaining("admin@10.0.0.9")], ["15", "Fila completa", "tiene 3 columnas; se esperaban 8"]]);
  const states = screen.getByRole("table", { name: "Filas válidas del archivo" });
  expect(within(states).getByText("Nuevo")).toBeVisible();
  expect(within(states).getByText("Igual")).toBeVisible();
  expect(within(states).getByText("No está en la bóveda: quedaría sin credencial")).toBeVisible();
  expect(screen.getByText("Solo se aplican las filas válidas; las 2 inválidas se omiten.")).toBeVisible();
  // El conflicto por nombre admite renombrar; el de dirección, no.
  expect(within(screen.getByLabelText("Qué hacer con LAB-AP")).getByRole("option", { name: "Renombrar" })).toBeInTheDocument();
  expect(within(screen.getByLabelText("Qué hacer con OTRO-NOMBRE")).queryByRole("option", { name: "Renombrar" })).toBeNull();
  await userEvent.selectOptions(screen.getByLabelText("Qué hacer con OTRO-NOMBRE"), "reemplazar");
  await userEvent.selectOptions(screen.getByLabelText("Qué hacer con LAB-AP"), "renombrar");
  await userEvent.click(screen.getByRole("button", { name: "Aplicar importación" }));
  expect(core.applyHostsImport).toHaveBeenCalledWith("token-1", [{ key: "10.9.0.1:22", action: "reemplazar" }, { key: "ap2.lab:22", action: "renombrar" }]);
  expect(await screen.findByText("Importación aplicada: 1 creados, 1 reemplazados, 1 renombrados, 3 omitidos (2 inválidos).")).toBeVisible();
  expect(screen.queryByRole("table", { name: "Filas inválidas del archivo" })).toBeNull();
});

test("un archivo sin filas válidas no se puede aplicar", async () => {
  setup({ previewHostsImport: vi.fn(async () => ({ token: "t", expiresMs: 0, format: "json", items: [], errors: [{ line: 1, field: "name", reason: "vacío" }], warnings: ["archivo sin suma de verificación"] })) });
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  expect(await screen.findByText("El archivo no trae ninguna fila válida.")).toBeVisible();
  expect(screen.getByRole("button", { name: "Aplicar importación" })).toBeDisabled();
  expect(screen.getByText("El archivo no trae suma de verificación: no se pudo comprobar que esté íntegro.")).toBeVisible(); // aviso conocido, traducido
});

test("en inglés no aparece ningún texto del núcleo en español: errores por línea, avisos y ejemplos", async () => {
  localStorage.setItem("macuahuitl.idioma", "en");
  setup();
  await userEvent.click(screen.getByRole("button", { name: /^Show details/ }));
  const dialog = await screen.findByRole("dialog", { name: "Details · Hosts" });
  const fields = await within(dialog).findByRole("table", { name: "File fields" });
  // Ejemplos: solo los neutros (dirección, puerto, plataforma); «SW-CORE», «Lab», «admin lab» y «Piso 2» vienen del núcleo.
  expect(within(fields).getByText("10.0.0.1")).toBeVisible();
  for (const x of ["SW-CORE", "Piso 2", "admin lab"]) expect(within(fields).queryByText(x)).toBeNull();
  expect(within(dialog).getByText(/example values are written by the core and may be in Spanish/)).toBeVisible();
  const detailsText = dialog.textContent ?? "";
  await userEvent.keyboard("{Escape}");
  await userEvent.click(screen.getByRole("button", { name: "Import…" }));
  const errors = await screen.findByRole("table", { name: "Invalid rows in the file" });
  const rows = within(errors).getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell").map((c) => c.textContent));
  expect(rows).toEqual([["14", "address", "Invalid value"], ["15", "Whole row", "The row could not be read"]]);
  expect(screen.getByText("1 hosts reference a credential that is not in the vault (or is ambiguous) and would end up without a credential.")).toBeVisible();
  const text = (document.body.textContent ?? "") + detailsText;
  // Textos reales del doble: avisos, errores de línea, descripciones de campo y estados del núcleo.
  for (const w of ["tiene 3 columnas", "use una IP", "etiqueta de credencial", "quedarían sin credencial", "Nombre del host", "vacío", "Detalle del núcleo", "en español)"]) expect(text, w).not.toContain(w);
  expect(text).not.toMatch(/[áéíóúñ¿¡«»]/);
  for (const w of ["Download CSV template", "Problem", "Whole row", "Conflict: same address and port", "Apply import"]) expect(text).toContain(w);
  expect(text).not.toMatch(/\b(Nuevo|Igual|Omitir|Reemplazar|Filas|Línea)\b/);
});

test("un aviso desconocido del núcleo sale tal cual en español y como aviso genérico en inglés", async () => {
  const prev = { token: "t", expiresMs: 0, format: "json" as const, items: [], errors: [], warnings: ["algo raro pasó con el archivo"] };
  const { unmount } = render(<I18nProvider><HostsDataCard core={fakeCore({ ...fakeInventory(), pickPath: vi.fn(async () => "/x.json"), previewHostsImport: vi.fn(async () => prev) })} /></I18nProvider>);
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  expect(await screen.findByText("algo raro pasó con el archivo")).toBeVisible();
  unmount();
  localStorage.setItem("macuahuitl.idioma", "en");
  render(<I18nProvider><HostsDataCard core={fakeCore({ ...fakeInventory(), pickPath: vi.fn(async () => "/x.json"), previewHostsImport: vi.fn(async () => prev) })} /></I18nProvider>);
  await userEvent.click(screen.getByRole("button", { name: "Import…" }));
  expect(await screen.findByText("The core reported a warning for this file.")).toBeVisible();
  expect(document.body.textContent).not.toContain("algo raro");
});

test("si la exportación falla se borra el archivo vacío y se muestra el error sin decir que quedó vacío", async () => {
  const core = setup({ exportHosts: vi.fn(async () => { throw new Error("no se pudo escribir"); }) });
  await userEvent.click(screen.getByRole("button", { name: "Exportar hosts" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("no se pudo escribir");
  expect(core.removeEmptyFile).toHaveBeenCalledWith("/home/u/Descargas/hosts.csv");
  expect(screen.getByRole("alert")).not.toHaveTextContent("quedó vacío");
});

test("si no se borra (archivo previo con contenido que el usuario eligió reemplazar), se muestra el error real sin decir que quedó vacío", async () => {
  setup({ exportHosts: vi.fn(async () => { throw new Error("no se pudo escribir"); }), removeEmptyFile: vi.fn(async () => { throw new Error("no está vacío"); }) });
  await userEvent.click(screen.getByRole("button", { name: "Exportar hosts" }));
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("no se pudo escribir");
  expect(alert).not.toHaveTextContent("quedó vacío");
});

test("una exportación correcta no borra nada", async () => {
  const core = setup();
  await userEvent.click(screen.getByRole("button", { name: "Exportar hosts" }));
  await screen.findByText(/Se exportaron/);
  expect(core.removeEmptyFile).not.toHaveBeenCalled();
});

test("los avisos de la exportación salen como aviso, no como error", async () => {
  setup({ exportHosts: vi.fn(async () => ({ count: 2, warnings: ["1 host salió sin credencial"] })) });
  await userEvent.click(screen.getByRole("button", { name: "Exportar hosts" }));
  expect(await screen.findByText("Se exportaron 2 hosts a /home/u/Descargas/hosts.csv.")).toBeVisible();
  expect(screen.getByText("1 host salió sin credencial").closest(".notice")).toHaveClass("warn");
  expect(screen.queryByRole("alert")).toBeNull();
});

test("la lista de hosts a exportar se pone al día cuando cambia la libreta y descarta los marcados que ya no existen", async () => {
  const inv = fakeInventory();
  const core = setup({ ...inv });
  await userEvent.selectOptions(screen.getByLabelText("Qué exportar"), "some");
  await userEvent.click(await screen.findByRole("checkbox", { name: /LAB-AP/ }));
  inv.listHosts.mockResolvedValueOnce([]);
  act(() => hostsChanged());
  expect(await screen.findByRole("group", { name: "Hosts a exportar" })).toBeEmptyDOMElement();
  await userEvent.click(screen.getByRole("button", { name: "Exportar hosts" }));
  expect(await screen.findByText("No hay hosts que exportar.")).toBeVisible();
  expect(core.exportHosts).not.toHaveBeenCalled();
});

test("si el token de la vista previa venció o ya se usó, se cierra la vista previa y se pide abrir el archivo otra vez", async () => {
  const core = setup({ applyHostsImport: vi.fn(async () => { throw new Error("rpc error: code = NotFound desc = el token no existe o venció"); }) });
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  await screen.findByRole("table", { name: "Filas válidas del archivo" });
  await userEvent.selectOptions(screen.getByLabelText("Qué hacer con OTRO-NOMBRE"), "reemplazar");
  await userEvent.selectOptions(screen.getByLabelText("Qué hacer con LAB-AP"), "omitir");
  await userEvent.click(screen.getByRole("button", { name: "Aplicar importación" }));
  expect(await screen.findByText("La vista previa venció o ya se usó: vuelve a abrir el archivo.")).toBeVisible();
  expect(screen.queryByRole("table", { name: "Filas válidas del archivo" })).toBeNull();
  expect(core.applyHostsImport).toHaveBeenCalledTimes(1);
});

test("otro error al aplicar deja la vista previa abierta", async () => {
  setup({ applyHostsImport: vi.fn(async () => { throw new Error("falta la decisión de un conflicto"); }) });
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  await screen.findByRole("table", { name: "Filas válidas del archivo" });
  await userEvent.click(screen.getByRole("button", { name: "Aplicar importación" }));
  expect(await screen.findByText("falta la decisión de un conflicto")).toBeVisible();
  expect(screen.getByRole("table", { name: "Filas válidas del archivo" })).toBeVisible();
});
