import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HostsView } from "./HostsView";
import { fakeInventory } from "./fake";
import { fakeCore } from "../../lib/fake";
import { I18nProvider } from "../../lib/i18n";

const cred = { id: "c".repeat(32), label: "admin lab", username: "admin", hasEnable: false, hasSshKey: false };
const setup = (over = {}) => {
  const inv = fakeInventory();
  const core = fakeCore({ ...inv, listCredentials: vi.fn(async () => [cred]), ...over });
  const { unmount } = render(<I18nProvider><HostsView core={core} /></I18nProvider>);
  return { core, inv, unmount };
};
beforeEach(() => localStorage.clear());

test("lista los hosts de la libreta agrupados por carpeta, con plataforma y credencial", async () => {
  const { inv } = setup();
  const table = await screen.findByRole("table", { name: "Hosts de la libreta" });
  expect(inv.listHosts).toHaveBeenCalled();
  const groups = within(table).getAllByRole("rowgroup").slice(1); // el primero es el encabezado
  expect(groups.map((g) => within(g).getAllByRole("row")[0].textContent)).toEqual(["Lab (2)", "Oficina (1)"]);
  expect(within(table).getByText("10.9.0.1:22")).toBeVisible();
  expect(within(table).getByText("admin lab")).toBeVisible();
  expect(within(table).getByText("WLC")).toBeVisible();
});

test("busca por nombre, dirección o etiqueta y filtra por carpeta", async () => {
  setup();
  const table = await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.type(screen.getByLabelText("Buscar por nombre, dirección o etiqueta"), "dc-1");
  expect(within(table).queryByText("LAB-CORE")).toBeNull();
  expect(within(table).getByText("OFI-SW")).toBeVisible();
  await userEvent.clear(screen.getByLabelText("Buscar por nombre, dirección o etiqueta"));
  await userEvent.selectOptions(screen.getByLabelText("Carpeta"), "Lab");
  expect(within(table).queryByText("OFI-SW")).toBeNull();
  expect(within(table).getByText("LAB-AP")).toBeVisible();
});

test("crear: valida en línea sin llamar al núcleo y luego guarda con puerto 22 y etiquetas partidas", async () => {
  const { inv } = setup();
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: /Nuevo host/ }));
  expect(screen.getByLabelText("Puerto")).toHaveValue("22");
  await userEvent.type(screen.getByLabelText("Dirección (IP o nombre DNS)"), "admin@10.0.0.9");
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  expect(inv.saveHost).not.toHaveBeenCalled();
  expect(screen.getByText(/El nombre es obligatorio/)).toBeVisible();
  expect(screen.getByLabelText("Dirección (IP o nombre DNS)")).toBeInvalid();
  await userEvent.type(screen.getByLabelText("Nombre"), "NUEVO");
  await userEvent.clear(screen.getByLabelText("Dirección (IP o nombre DNS)"));
  await userEvent.type(screen.getByLabelText("Dirección (IP o nombre DNS)"), "10.0.0.9");
  await userEvent.type(screen.getByLabelText("Etiquetas"), "core, dc-1");
  await userEvent.selectOptions(screen.getByLabelText("Credencial de la bóveda"), cred.id);
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  expect(inv.saveHost).toHaveBeenCalledWith({ name: "NUEVO", address: "10.0.0.9", port: 22, platform: "", folder: "", tags: ["core", "dc-1"], credentialId: cred.id, notes: "" });
  expect(await screen.findByText("Host «NUEVO» guardado.")).toBeVisible();
  expect(await screen.findByText("10.0.0.9:22")).toBeVisible(); // la lista se pone al día
});

test("editar manda el id del host y conserva lo que no se tocó", async () => {
  const { inv } = setup();
  await userEvent.click(await screen.findByRole("button", { name: "Editar LAB-AP" }));
  expect(screen.getByLabelText("Puerto")).toHaveValue("2222");
  await userEvent.clear(screen.getByRole("textbox", { name: "Carpeta" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Carpeta" }), "Campus");
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  expect(inv.saveHost).toHaveBeenCalledWith({ id: "b".repeat(32), name: "LAB-AP", address: "ap1.lab", port: 2222, platform: "wlc", folder: "Campus", tags: [], credentialId: "", notes: "" });
  expect(await within(screen.getByRole("table", { name: "Hosts de la libreta" })).findByText("Campus")).toBeVisible();
});

test("el error del núcleo se marca en el campo y su texto va aparte, como detalle del núcleo", async () => {
  setup();
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: /Nuevo host/ }));
  await userEvent.type(screen.getByLabelText("Nombre"), "lab-core"); // repite LAB-CORE sin importar mayúsculas
  await userEvent.type(screen.getByLabelText("Dirección (IP o nombre DNS)"), "10.0.0.50");
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  expect(await screen.findByText("Ya hay un host con este nombre.")).toBeVisible();
  expect(screen.getByLabelText("Nombre")).toBeInvalid();
  expect(screen.getByText(/ya hay un host llamado "lab-core"/)).toBeVisible(); // en español se muestra el detalle del núcleo
});

test("eliminar pide confirmación y borra por id", async () => {
  const { inv } = setup();
  await userEvent.click(await screen.findByRole("button", { name: "Eliminar OFI-SW" }));
  expect(inv.deleteHost).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Confirmar eliminación" }));
  expect(inv.deleteHost).toHaveBeenCalledWith("d".repeat(32));
  await waitFor(() => expect(screen.queryByText("OFI-SW")).toBeNull());
});

test("un equipo descubierto es de solo lectura y «Guardar en la libreta» rellena el formulario", async () => {
  setup();
  const found = await screen.findByRole("table", { name: "Equipos descubiertos" });
  expect(within(found).queryByRole("button", { name: /Editar|Eliminar/ })).toBeNull();
  expect(within(found).getByText("SW-ACC1")).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "Guardar SW-ACC1 en la libreta" }));
  expect(screen.getByLabelText("Nombre")).toHaveValue("SW-ACC1");
  expect(screen.getByLabelText("Dirección (IP o nombre DNS)")).toHaveValue("10.0.0.2");
  expect(screen.getByLabelText("Plataforma")).toHaveValue("ios-xe");
  expect(screen.getByLabelText("Puerto")).toHaveValue("22");
});

test("con la bóveda cerrada se conserva la credencial guardada al editar", async () => {
  const { inv } = setup({ listCredentials: vi.fn(async () => { throw new Error("bóveda cerrada"); }) });
  await userEvent.click(await screen.findByRole("button", { name: "Editar LAB-CORE" }));
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  expect(inv.saveHost).toHaveBeenCalledWith(expect.objectContaining({ id: "a".repeat(32), credentialId: "c".repeat(32) }));
});

test("en inglés no queda ningún texto en español ni clave sin traducir", async () => {
  localStorage.setItem("macuahuitl.lang", "en");
  setup();
  await screen.findByRole("table", { name: "Hosts in the book" });
  await userEvent.click(screen.getByRole("button", { name: /New host/ }));
  await userEvent.click(screen.getByRole("button", { name: "Save host" })); // errores de validación
  const text = document.body.textContent ?? "";
  expect(screen.getByRole("heading", { name: "Host book" })).toBeVisible();
  expect(screen.getByRole("table", { name: "Discovered devices" })).toBeVisible();
  expect(text).not.toMatch(/[áéíóúñ¿¡«»]/);
  expect(text).not.toMatch(/\b(hosts|nav|common)\.[a-z]+/);
  expect(text).toMatch(/The name is required/);
});

test("en inglés el error del núcleo en el formulario es genérico y no muestra su texto en español", async () => {
  localStorage.setItem("macuahuitl.lang", "en");
  setup();
  await screen.findByRole("table", { name: "Hosts in the book" });
  await userEvent.click(screen.getByRole("button", { name: /New host/ }));
  await userEvent.type(screen.getByLabelText("Name"), "lab-core");
  await userEvent.type(screen.getByLabelText("Address (IP or DNS name)"), "10.0.0.50");
  await userEvent.click(screen.getByRole("button", { name: "Save host" }));
  expect(await screen.findByText("A host with this name already exists.")).toBeVisible();
  expect(screen.getByLabelText("Name")).toBeInvalid();
  expect(document.body.textContent).not.toMatch(/ya hay un host|Detalle del núcleo|Core detail/);
});

test("en inglés un error sin campo y los avisos de guardado salen como textos genéricos", async () => {
  localStorage.setItem("macuahuitl.lang", "en");
  const { core } = setup();
  core.saveHost = vi.fn().mockRejectedValueOnce(new Error("el núcleo no responde")).mockResolvedValueOnce({ id: "x", warnings: ["la bóveda está cerrada: la credencial se guardó sin validar"] });
  await screen.findByRole("table", { name: "Hosts in the book" });
  await userEvent.click(screen.getByRole("button", { name: /New host/ }));
  await userEvent.type(screen.getByLabelText("Name"), "N1");
  await userEvent.type(screen.getByLabelText("Address (IP or DNS name)"), "10.0.0.51");
  await userEvent.click(screen.getByRole("button", { name: "Save host" }));
  expect(await screen.findByText("The core could not complete the operation.")).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "Save host" }));
  expect(await screen.findByText("The core reported a warning for this operation.")).toBeVisible();
  expect(document.body.textContent).not.toMatch(/núcleo no responde|bóveda está cerrada/);
});

test("la dirección repetida se marca en su campo, en español y en inglés", async () => {
  for (const [lang, name, addr, save, msg] of [["es", "Nombre", "Dirección (IP o nombre DNS)", "Guardar host", "Esta dirección y puerto ya están en la libreta."], ["en", "Name", "Address (IP or DNS name)", "Save host", "This address is already in the book."]]) {
    localStorage.setItem("macuahuitl.lang", lang);
    const { unmount } = setup();
    await userEvent.click(await screen.findByRole("button", { name: lang === "es" ? /Nuevo host/ : /New host/ }));
    await userEvent.type(screen.getByLabelText(name), "OTRO");
    await userEvent.type(screen.getByLabelText(addr), "10.9.0.1"); // ya es de LAB-CORE en el puerto 22
    await userEvent.click(screen.getByRole("button", { name: save }));
    expect(await screen.findByText(msg)).toBeVisible();
    expect(screen.getByLabelText(addr)).toBeInvalid();
    unmount();
  }
});

const gone = { id: "e".repeat(32), name: "HUERFANO", address: "10.1.1.1", port: 22, platform: "" as const, folder: "", tags: [], credentialId: "f".repeat(32), credentialLabel: "", notes: "" };

test("una credencial borrada con la bóveda abierta se distingue de la bóveda cerrada", async () => {
  setup({ listHosts: vi.fn(async () => [gone]) });
  expect(await screen.findByText("La credencial ya no existe en la bóveda")).toBeVisible();
  expect(screen.queryByText("Credencial guardada (bóveda cerrada)")).toBeNull();
});

test("con la bóveda cerrada se dice que la credencial está guardada", async () => {
  setup({ listHosts: vi.fn(async () => [gone]), listCredentials: vi.fn(async () => { throw new Error("bóveda cerrada"); }) });
  expect(await screen.findByText("Credencial guardada (bóveda cerrada)")).toBeVisible();
  expect(screen.queryByText("La credencial ya no existe en la bóveda")).toBeNull();
});

test("Editar enfoca el primer campo y al cancelar o guardar el foco vuelve al botón de origen", async () => {
  setup();
  const edit = await screen.findByRole("button", { name: "Editar LAB-AP" });
  await userEvent.click(edit);
  expect(screen.getByLabelText("Nombre")).toHaveFocus();
  await userEvent.click(screen.getByRole("button", { name: "Cancelar" }));
  expect(screen.getByRole("button", { name: "Editar LAB-AP" })).toHaveFocus();
  await userEvent.click(screen.getByRole("button", { name: "Editar LAB-AP" }));
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Editar LAB-AP" })).toHaveFocus());
});

test("Guardar en la libreta enfoca el formulario y, al guardar, el foco vuelve a la página", async () => {
  setup();
  await userEvent.click(await screen.findByRole("button", { name: "Guardar SW-ACC1 en la libreta" }));
  expect(screen.getByLabelText("Nombre")).toHaveFocus();
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  await screen.findByText("Host «SW-ACC1» guardado.");
  expect(document.activeElement).not.toBe(document.body);
});

test("con reason el campo sale de metadata.field y el texto del núcleo se muestra tal cual, en inglés también", async () => {
  localStorage.setItem("macuahuitl.lang", "en");
  const err = Object.assign(new Error("rpc error: code = InvalidArgument desc = the credential is not in the vault"), { cause: { code: "InvalidArgument", reason: "hosts.unknown_credential", metadata: { field: "credentialId" } } });
  setup({ saveHost: vi.fn(async () => { throw err; }) });
  await screen.findByRole("table", { name: "Hosts in the book" });
  await userEvent.click(screen.getByRole("button", { name: /New host/ }));
  await userEvent.type(screen.getByLabelText("Name"), "x1");
  await userEvent.type(screen.getByLabelText("Address (IP or DNS name)"), "10.0.0.51");
  await userEvent.click(screen.getByRole("button", { name: "Save host" }));
  expect(await screen.findByText("the credential is not in the vault")).toBeVisible();
  expect(screen.getByLabelText("Name")).not.toBeInvalid();
  expect(screen.getByLabelText("Vault credential")).toBeInvalid(); // el error va al campo que dice metadata.field
});
