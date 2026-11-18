import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HostsView } from "./HostsView";
import { fakeInventory, sampleHosts } from "./fake";
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
  expect(groups.map((g) => g.querySelector("th")?.textContent)).toEqual(["Lab (2)", "Oficina (1)", "Sin carpeta (0)"]);
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
  expect(inv.saveHost).toHaveBeenCalledWith({ name: "NUEVO", address: "10.0.0.9", port: 22, platform: "", folder: "", tags: ["core", "dc-1"], credentialId: cred.id, notes: "", startCommand: "" });
  expect(await screen.findByText("Host «NUEVO» guardado.")).toBeVisible();
  expect(await screen.findByText("10.0.0.9:22")).toBeVisible(); // la lista se pone al día
});

test("editar manda el id del host y conserva lo que no se tocó", async () => {
  const { inv } = setup();
  await userEvent.click(await screen.findByRole("button", { name: "Editar LAB-AP" }));
  expect(screen.getByLabelText("Puerto")).toHaveValue("2222");
  await userEvent.selectOptions(screen.getAllByRole("combobox", { name: "Carpeta" })[0], "Oficina"); // el primero es el del formulario
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  expect(inv.saveHost).toHaveBeenCalledWith({ id: "b".repeat(32), name: "LAB-AP", address: "ap1.lab", port: 2222, platform: "wlc", folder: "Oficina", tags: [], credentialId: "", notes: "", startCommand: "" });
  expect(await screen.findByText("Oficina (2)")).toBeVisible();
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
  await screen.findByRole("table", { name: "Host list" });
  await userEvent.click(screen.getByRole("button", { name: /New host/ }));
  await userEvent.click(screen.getByRole("button", { name: "Save host" })); // errores de validación
  const text = document.body.textContent ?? "";
  expect(screen.getByRole("heading", { name: "Saved hosts" })).toBeVisible();
  expect(screen.getByRole("table", { name: "Discovered devices" })).toBeVisible();
  expect(text).not.toMatch(/[áéíóúñ¿¡«»]/);
  expect(text).not.toMatch(/\b(hosts|nav|common)\.[a-z]+/);
  expect(text).toMatch(/The name is required/);
});

test("en inglés el error del núcleo en el formulario se muestra tal cual (ya llega traducido)", async () => {
  localStorage.setItem("macuahuitl.lang", "en");
  const { core } = setup();
  core.saveHost = vi.fn().mockRejectedValue(Object.assign(new Error("there is already a host named \"lab-core\""), { cause: { code: "AlreadyExists", reason: "hosts.duplicate_name", metadata: { field: "name" } } }));
  await screen.findByRole("table", { name: "Host list" });
  await userEvent.click(screen.getByRole("button", { name: /New host/ }));
  await userEvent.type(screen.getByLabelText("Name"), "lab-core");
  await userEvent.type(screen.getByLabelText("Address (IP or DNS name)"), "10.0.0.50");
  await userEvent.click(screen.getByRole("button", { name: "Save host" }));
  expect(await screen.findByText("A host with this name already exists.")).toBeVisible();
  expect(screen.getByLabelText("Name")).toBeInvalid();
  expect(screen.getByText("there is already a host named \"lab-core\"")).toBeVisible();
});

test("en inglés un error sin campo y los avisos de guardado salen con el texto del núcleo, sin repetidos", async () => {
  localStorage.setItem("macuahuitl.lang", "en");
  const { core } = setup();
  const w = "the vault is closed: the credential was saved without validation";
  core.saveHost = vi.fn().mockRejectedValueOnce(new Error("the core is not responding")).mockResolvedValueOnce({ id: "x", warnings: [w, w, "file without a checksum: nothing verifies that it is not damaged or modified; review its contents"] });
  await screen.findByRole("table", { name: "Host list" });
  await userEvent.click(screen.getByRole("button", { name: /New host/ }));
  await userEvent.type(screen.getByLabelText("Name"), "N1");
  await userEvent.type(screen.getByLabelText("Address (IP or DNS name)"), "10.0.0.51");
  await userEvent.click(screen.getByRole("button", { name: "Save host" }));
  expect(await screen.findByText("the core is not responding")).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "Save host" }));
  const notice = (await screen.findByText(/the vault is closed/)).closest(".notice");
  expect(notice?.textContent).toBe(`${w} file without a checksum: nothing verifies that it is not damaged or modified; review its contents`);
});

test("la dirección repetida se marca en su campo, en español y en inglés", async () => {
  for (const [lang, name, addr, save, msg] of [["es", "Nombre", "Dirección (IP o nombre DNS)", "Guardar host", "Esta dirección y puerto ya están en la libreta."], ["en", "Name", "Address (IP or DNS name)", "Save host", "A saved host already uses this address and port."]]) {
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
  await screen.findByRole("table", { name: "Host list" });
  await userEvent.click(screen.getByRole("button", { name: /New host/ }));
  await userEvent.type(screen.getByLabelText("Name"), "x1");
  await userEvent.type(screen.getByLabelText("Address (IP or DNS name)"), "10.0.0.51");
  await userEvent.click(screen.getByRole("button", { name: "Save host" }));
  expect(await screen.findByText("the credential is not in the vault")).toBeVisible();
  expect(screen.getByLabelText("Name")).not.toBeInvalid();
  expect(screen.getByLabelText("Vault credential")).toBeInvalid(); // el error va al campo que dice metadata.field
});

// ---- Fase 44: carpetas, mover y orden de inicio ----
const dt = () => { const d: Record<string, string> = {}; return { setData: (k: string, v: string) => { d[k] = v; }, getData: (k: string) => d[k] ?? "", effectAllowed: "", dropEffect: "" }; };
const rowOf = (name: string) => screen.getByText(name).closest("tr") as HTMLElement;
const groupOf = (name: string) => screen.getByRole("rowgroup", { name: new RegExp(`^${name}\\b`) });

test("orden de inicio: solo con linux o windows, con aviso, y viaja en el borrador", async () => {
  const { inv } = setup();
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: /Nuevo host/ }));
  expect(screen.queryByLabelText("Orden de inicio")).toBeNull();
  await userEvent.selectOptions(screen.getByLabelText("Plataforma"), "linux");
  expect(screen.getByLabelText("Orden de inicio")).toBeVisible();
  expect(screen.getByText(/se ejecuta en el equipo al conectar/)).toBeVisible();
  await userEvent.type(screen.getByLabelText("Nombre"), "SRV");
  await userEvent.type(screen.getByLabelText("Dirección (IP o nombre DNS)"), "10.5.5.5");
  await userEvent.type(screen.getByLabelText("Orden de inicio"), "x".repeat(257));
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  expect(inv.saveHost).not.toHaveBeenCalled();
  expect(screen.getByLabelText("Orden de inicio")).toBeInvalid();
  await userEvent.clear(screen.getByLabelText("Orden de inicio"));
  await userEvent.type(screen.getByLabelText("Orden de inicio"), "tmux attach");
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  expect(inv.saveHost).toHaveBeenCalledWith(expect.objectContaining({ platform: "linux", startCommand: "tmux attach" }));
});

test("crear una carpeta sin registrar un host; las vacías se ven y valida el nombre", async () => {
  const { inv } = setup();
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: "Nueva carpeta" }));
  await userEvent.type(screen.getByLabelText("Nombre de la carpeta"), "a/b");
  await userEvent.click(screen.getByRole("button", { name: "Crear carpeta" }));
  expect(inv.createFolder).not.toHaveBeenCalled();
  expect(screen.getByLabelText("Nombre de la carpeta")).toBeInvalid();
  await userEvent.clear(screen.getByLabelText("Nombre de la carpeta"));
  await userEvent.type(screen.getByLabelText("Nombre de la carpeta"), "Nueva");
  await userEvent.click(screen.getByRole("button", { name: "Crear carpeta" }));
  expect(inv.createFolder).toHaveBeenCalledWith("Nueva");
  expect(await screen.findByText("Nueva (0)")).toBeVisible();
  expect(inv.saveHost).not.toHaveBeenCalled();
});

test("renombrar una carpeta mueve a sus hosts", async () => {
  const { inv } = setup();
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: "Renombrar carpeta Oficina" }));
  const f = screen.getByLabelText("Nombre de la carpeta");
  expect(f).toHaveValue("Oficina");
  await userEvent.clear(f);
  await userEvent.type(f, "Matriz");
  await userEvent.click(screen.getByRole("button", { name: "Renombrar" }));
  expect(inv.renameFolder).toHaveBeenCalledWith("Oficina", "Matriz");
  expect(await screen.findByText("Matriz (1)")).toBeVisible();
  expect(screen.queryByText("Oficina (1)")).toBeNull();
});

test("borrar una carpeta con hosts pide confirmar diciendo cuántos pasan a «Sin carpeta» y no borra hosts", async () => {
  const { inv } = setup();
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: "Eliminar carpeta Lab" }));
  expect(inv.deleteFolder).not.toHaveBeenCalled();
  const ok = screen.getByRole("button", { name: "Confirmar: 2 hosts pasan a «Sin carpeta»" });
  await userEvent.click(ok);
  expect(inv.deleteFolder).toHaveBeenCalledWith("Lab", true); // confirmó con la cuenta conocida: confirm=true
  expect(await screen.findByText("Sin carpeta (2)")).toBeVisible();
  expect(inv.deleteHost).not.toHaveBeenCalled();
  expect(screen.getByText("LAB-CORE")).toBeVisible();
});

test("borrar con la cuenta desactualizada: FailedPrecondition muestra la cuenta del núcleo y reintenta con confirm=true solo tras confirmar de nuevo", async () => {
  const inv0 = fakeInventory();
  setup({ ...inv0, listFolders: vi.fn(async () => [{ name: "Lab", count: 0 }, { name: "Oficina", count: 1 }]) }); // la lista de carpetas dice 0 hosts en Lab
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: "Eliminar carpeta Lab" }));
  await userEvent.click(screen.getByRole("button", { name: /^Confirmar/ }));
  expect(inv0.deleteFolder).toHaveBeenNthCalledWith(1, "Lab", false); // no sabía de hosts: sin confirm
  expect(await screen.findByText(/ya tiene 2 hosts/)).toBeVisible();
  expect(inv0.deleteFolder).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByRole("button", { name: "Borrar la carpeta y dejar sus hosts sin carpeta" }));
  expect(inv0.deleteFolder).toHaveBeenNthCalledWith(2, "Lab", true);
  expect(await screen.findByText("Sin carpeta (2)")).toBeVisible();
});

const grip = (name: string) => screen.getByRole("button", { name: new RegExp(`^Arrastrar ${name} `) });

test("«Mover a…» por teclado: Enter lo abre, las flechas no mueven nada, Tab + Enter elige; el foco vuelve a su botón", async () => {
  const { inv } = setup();
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  screen.getByRole("button", { name: "Mover LAB-CORE a…" }).focus();
  await userEvent.keyboard("{Enter}");
  const panel = screen.getByRole("group", { name: "Mover LAB-CORE a" });
  expect(within(panel).getAllByRole("button")[0]).toHaveFocus();
  await userEvent.keyboard("{ArrowDown}{ArrowUp}{ArrowDown}");
  expect(inv.moveHosts).not.toHaveBeenCalled(); // una flecha jamás mueve (en un select cerrado dispararía change)
  expect(panel).toBeVisible();
  expect(within(panel).queryByRole("button", { name: "Lab" })).toBeNull(); // su carpeta actual no es destino
  await userEvent.keyboard("{Tab}{Enter}"); // «Sin carpeta» → Oficina
  expect(inv.moveHosts).toHaveBeenCalledWith(["a".repeat(32)], "Oficina");
  expect(await screen.findByText("Oficina (2)")).toBeVisible();
  expect(await screen.findByText(/LAB-CORE.*Oficina/)).toBeVisible(); // anuncio en la región aria-live
  await waitFor(() => expect(screen.getByRole("button", { name: "Mover LAB-CORE a…" })).toHaveFocus()); // el nodo cambió de grupo: se ubica por id
});

test("«Mover a…»: «Sin carpeta» como destino; Esc y Cancelar no mueven y devuelven el foco", async () => {
  const { inv } = setup();
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: "Mover LAB-CORE a…" }));
  await userEvent.keyboard("{Escape}");
  expect(screen.queryByRole("group", { name: "Mover LAB-CORE a" })).toBeNull();
  expect(screen.getByRole("button", { name: "Mover LAB-CORE a…" })).toHaveFocus();
  await userEvent.click(screen.getByRole("button", { name: "Mover LAB-CORE a…" }));
  await userEvent.click(within(screen.getByRole("group", { name: "Mover LAB-CORE a" })).getByRole("button", { name: "Cancelar" }));
  expect(screen.getByRole("button", { name: "Mover LAB-CORE a…" })).toHaveFocus();
  expect(inv.moveHosts).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Mover LAB-CORE a…" }));
  await userEvent.click(within(screen.getByRole("group", { name: "Mover LAB-CORE a" })).getByRole("button", { name: "Sin carpeta" }));
  expect(inv.moveHosts).toHaveBeenCalledWith(["a".repeat(32)], "");
});

test("arrastrar el asa de un host sobre una carpeta (y sobre «Sin carpeta») lo mueve; solo el asa es arrastrable", async () => {
  const { inv } = setup();
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  expect(rowOf("LAB-AP")).not.toHaveAttribute("draggable"); // el nombre y la IP se pueden seleccionar y copiar
  expect(grip("LAB-AP")).toHaveAttribute("draggable", "true");
  const data = dt();
  fireEvent.dragStart(grip("LAB-AP"), { dataTransfer: data });
  const target = groupOf("Oficina").querySelector("tr.hosts-folder") as HTMLElement;
  expect(fireEvent.dragOver(target, { dataTransfer: data })).toBe(false); // preventDefault: acepta el soltar
  fireEvent.drop(target, { dataTransfer: data });
  await waitFor(() => expect(inv.moveHosts).toHaveBeenCalledWith(["b".repeat(32)], "Oficina"));
  expect(await screen.findByText("Oficina (2)")).toBeVisible();
  const d2 = dt();
  fireEvent.dragStart(grip("LAB-CORE"), { dataTransfer: d2 });
  fireEvent.drop(screen.getByText(/^Sin carpeta/).closest("tr")!, { dataTransfer: d2 }); // aún no hay hosts sin carpeta: el destino existe igual
  await waitFor(() => expect(inv.moveHosts).toHaveBeenLastCalledWith(["a".repeat(32)], ""));
});

test("un drop con un id real en text/plain pero sin dragstart propio no mueve nada", async () => {
  const { inv } = setup();
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  const d = dt();
  d.setData("text/plain", "a".repeat(32));
  fireEvent.drop(groupOf("Oficina").querySelector("tr.hosts-folder")!, { dataTransfer: d });
  expect(inv.moveHosts).not.toHaveBeenCalled();
});

test("un dragOver de archivos del sistema no se acepta (sin preventDefault)", async () => {
  setup();
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  expect(fireEvent.dragOver(groupOf("Oficina").querySelector("tr.hosts-folder")!, { dataTransfer: { ...dt(), types: ["Files"] } })).toBe(true);
});

test("«Nueva carpeta» y «Renombrar» llevan el foco a su campo y lo devuelven al cerrar o guardar", async () => {
  const { inv } = setup();
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  const nueva = screen.getByRole("button", { name: "Nueva carpeta" });
  await userEvent.click(nueva);
  expect(screen.getByLabelText("Nombre de la carpeta")).toHaveFocus();
  await userEvent.click(screen.getByRole("button", { name: "Cancelar" }));
  expect(nueva).toHaveFocus();
  await userEvent.click(screen.getByRole("button", { name: "Renombrar carpeta Oficina" }));
  expect(screen.getByLabelText("Nombre de la carpeta")).toHaveFocus();
  await userEvent.click(screen.getByRole("button", { name: "Renombrar" })); // mismo nombre: no llama al núcleo
  expect(inv.renameFolder).not.toHaveBeenCalled();
  await waitFor(() => expect(screen.getByRole("button", { name: "Renombrar carpeta Oficina" })).toHaveFocus());
  await userEvent.click(screen.getByRole("button", { name: "Renombrar carpeta Oficina" }));
  await userEvent.type(screen.getByLabelText("Nombre de la carpeta"), "2");
  await userEvent.click(screen.getByRole("button", { name: "Renombrar" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Renombrar carpeta Oficina2" })).toHaveFocus()); // el grupo renombrado es otro nodo
});

test("un error al renombrar no pisa lo que se tecleó mientras esperaba", async () => {
  let rej: (e: Error) => void = () => {};
  const { inv } = setup();
  inv.renameFolder.mockImplementationOnce(() => new Promise<void>((_, r) => { rej = r; }));
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: "Renombrar carpeta Oficina" }));
  await userEvent.type(screen.getByLabelText("Nombre de la carpeta"), "X");
  await userEvent.click(screen.getByRole("button", { name: "Renombrar" }));
  await userEvent.type(screen.getByLabelText("Nombre de la carpeta"), "Y");
  await act(async () => rej(new Error("carpeta repetida")));
  expect(screen.getByLabelText("Nombre de la carpeta")).toHaveValue("OficinaXY");
  expect(screen.getByText("carpeta repetida")).toBeVisible();
});

test("con una carpeta vacía en el filtro se ve su grupo vacío, no «Ningún host coincide»", async () => {
  const { inv } = setup();
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await inv.createFolder("Vacia");
  await userEvent.click(screen.getByRole("button", { name: "Nueva carpeta" })); // fuerza recarga con otra carpeta nueva
  await userEvent.type(screen.getByLabelText("Nombre de la carpeta"), "Otra");
  await userEvent.click(screen.getByRole("button", { name: "Crear carpeta" }));
  await screen.findByText("Otra (0)");
  await userEvent.selectOptions(screen.getAllByLabelText("Carpeta")[0], "Otra");
  expect(screen.getByText("Otra (0)")).toBeVisible();
  expect(screen.queryByText("Ningún host coincide con la búsqueda.")).toBeNull();
});

test("el host con orden de inicio lo muestra con una marca y su orden en el title", async () => {
  const hosts = [{ ...sampleHosts[0], platform: "linux" as const, startCommand: "tmux attach" }, sampleHosts[1]];
  const inv = fakeInventory(hosts);
  render(<I18nProvider><HostsView core={fakeCore({ ...inv, listCredentials: vi.fn(async () => [cred]) })} /></I18nProvider>);
  const mark = await screen.findByTitle("tmux attach");
  expect(mark).toHaveAccessibleName("Orden de inicio: tmux attach");
  expect(screen.getAllByText("Orden de inicio")).toHaveLength(1);
});

test("la credencial de solo llave se ofrece solo con linux o windows, y la orden de inicio avisa que queda en la auditoría", async () => {
  const key = { ...cred, id: "k".repeat(32), label: "llave pi", kind: "key" as const, hasSshKey: true };
  setup({ listCredentials: vi.fn(async () => [cred, key]) });
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: /Nuevo host/ }));
  const sel = screen.getByLabelText("Credencial de la bóveda");
  const names = () => within(sel).getAllByRole("option").map((o) => o.textContent);
  expect(names().some((n) => /llave pi/.test(n ?? ""))).toBe(false); // sin plataforma
  await userEvent.selectOptions(screen.getByLabelText("Plataforma"), "ios-xe");
  expect(names().some((n) => /llave pi/.test(n ?? ""))).toBe(false);
  expect(screen.queryByText(/queda en la auditoría y en la grabación/)).toBeNull();
  await userEvent.selectOptions(screen.getByLabelText("Plataforma"), "linux");
  expect(names().some((n) => /llave pi/.test(n ?? ""))).toBe(true);
  expect(screen.getByText(/queda en la auditoría y en la grabación/)).toBeVisible();
});

test("la credencial de solo llave también se ofrece con windows", async () => {
  const key = { ...cred, id: "k".repeat(32), label: "llave pi", kind: "key" as const, hasSshKey: true };
  setup({ listCredentials: vi.fn(async () => [cred, key]) });
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: /Nuevo host/ }));
  await userEvent.selectOptions(screen.getByLabelText("Plataforma"), "windows");
  expect(within(screen.getByLabelText("Credencial de la bóveda")).getAllByRole("option").some((o) => /llave pi/.test(o.textContent ?? ""))).toBe(true);
});

test("un error del núcleo con metadata.field startup_command marca el campo de la orden", async () => {
  const err = Object.assign(new Error("orden inválida"), { cause: { code: "InvalidArgument", reason: "hosts.invalid_startup_command", metadata: { field: "startup_command" } } });
  setup({ saveHost: vi.fn(async () => { throw err; }) });
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: /Nuevo host/ }));
  await userEvent.type(screen.getByLabelText("Nombre"), "PI");
  await userEvent.type(screen.getByLabelText("Dirección (IP o nombre DNS)"), "10.0.0.5");
  await userEvent.selectOptions(screen.getByLabelText("Plataforma"), "linux");
  await userEvent.type(screen.getByLabelText(/Orden de inicio/), "ls");
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  await waitFor(() => expect(screen.getByLabelText(/Orden de inicio/)).toBeInvalid());
});

test("una credencial de llave importada se ofrece al registrar un host linux", async () => {
  const imp = { ...cred, id: "i".repeat(32), label: "llave importada", kind: "key" as const, origin: "imported" as const, hasSshKey: true };
  setup({ listCredentials: vi.fn(async () => [imp]) });
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: /Nuevo host/ }));
  await userEvent.selectOptions(screen.getByLabelText("Plataforma"), "linux");
  expect(within(screen.getByLabelText("Credencial de la bóveda")).getAllByRole("option").some((o) => /llave importada/.test(o.textContent ?? ""))).toBe(true);
});
