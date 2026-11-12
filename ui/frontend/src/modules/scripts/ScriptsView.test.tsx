import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ScriptsView } from "./ScriptsView";
import { fakeCore } from "../../lib/fake";
import { NavContext } from "../../app/activity";
import { sampleImport, sampleScripts } from "./fake";
import { encodeInsert } from "./text";

const OSPF = sampleScripts[2];

function setup(over = {}) {
  const core = fakeCore(over);
  const go = vi.fn();
  render(<NavContext.Provider value={{ go, inbox: {} }}><ScriptsView core={core} /></NavContext.Provider>);
  return { core, go };
}
const rows = () => within(screen.getByRole("list", { name: "Scripts" })).getAllByRole("listitem");
const mine = () => userEvent.click(screen.getByRole("tab", { name: "Mis scripts" }));
const open = (name: string) => userEvent.click(screen.getByRole("button", { name }));

test("la biblioteca y los scripts propios van en pestañas; la fila muestra plataforma y solo lectura", async () => {
  setup();
  expect(await screen.findByText("L2 · STP")).toBeInTheDocument();
  expect(rows()).toHaveLength(2);
  expect(screen.queryByText("Mi OSPF")).not.toBeInTheDocument();
  expect(within(rows()[1]).getByText("Solo lectura")).toBeInTheDocument(); // STP: readOnly
  expect(within(rows()[0]).queryByText("Solo lectura")).not.toBeInTheDocument(); // VLAN: configura
  await mine();
  expect(await screen.findByText("Mi OSPF")).toBeInTheDocument();
  expect(rows()).toHaveLength(1);
});

test("filtra por tecnología, plataforma, favoritos y busca también en los comandos", async () => {
  const { core } = setup();
  await screen.findByText("L2 · STP");
  await userEvent.type(screen.getByLabelText("Buscar"), "vlan 10");
  await waitFor(() => expect(rows()).toHaveLength(1));
  expect(core.listScripts).toHaveBeenLastCalledWith(expect.objectContaining({ text: "vlan 10" }));
  expect(screen.getByText("Config · VLAN y puerto de acceso")).toBeInTheDocument();
  await userEvent.clear(screen.getByLabelText("Buscar"));
  await userEvent.selectOptions(screen.getByLabelText("Tecnología"), "l3");
  expect(await screen.findByText(/Ningún script coincide/)).toBeInTheDocument(); // la biblioteca de ejemplo no tiene l3
  await userEvent.selectOptions(screen.getByLabelText("Tecnología"), "");
  await userEvent.selectOptions(screen.getByLabelText("Plataforma"), "nx-os");
  expect(core.listScripts).toHaveBeenLastCalledWith(expect.objectContaining({ platform: "nx-os" }));
  await userEvent.selectOptions(screen.getByLabelText("Plataforma"), "");
  await userEvent.click(screen.getByRole("checkbox", { name: "Solo favoritos" }));
  expect(core.listScripts).toHaveBeenLastCalledWith(expect.objectContaining({ onlyFavorites: true }));
  expect(await screen.findByText(/Ningún script coincide/)).toBeInTheDocument();
});

test("la estrella marca y desmarca el favorito, con aria-pressed", async () => {
  const { core } = setup();
  await mine();
  const star = await screen.findByRole("button", { name: "Favorito: Mi OSPF" });
  expect(star).toHaveAttribute("aria-pressed", "false");
  await userEvent.click(star);
  expect(core.setScriptFavorite).toHaveBeenCalledWith(OSPF.id, true);
  await waitFor(() => expect(screen.getByRole("button", { name: "Favorito: Mi OSPF" })).toHaveAttribute("aria-pressed", "true"));
  await userEvent.click(screen.getByRole("button", { name: "Favorito: Mi OSPF" }));
  expect(core.setScriptFavorite).toHaveBeenLastCalledWith(OSPF.id, false);
});

test("un script de la biblioteca se ve con sus comandos, sin editar ni borrar, pero se duplica", async () => {
  const { core } = setup();
  await screen.findByText("L2 · STP");
  await open("L2 · STP");
  const detail = screen.getByRole("region", { name: "L2 · STP" });
  expect(within(detail).getByText("show spanning-tree summary")).toBeInTheDocument();
  expect(within(detail).getByRole("button", { name: "Copiar los comandos de L2 · STP" })).toBeInTheDocument();
  expect(within(detail).queryByRole("button", { name: "Editar" })).not.toBeInTheDocument();
  expect(within(detail).queryByRole("button", { name: /Borrar/ })).not.toBeInTheDocument();
  await userEvent.click(within(detail).getByRole("button", { name: "Duplicar" }));
  expect(core.duplicateScript).toHaveBeenCalledWith("lib-l2-stp");
  await mine();
  expect(await screen.findByRole("button", { name: "L2 · STP (copia)" })).toBeInTheDocument();
});

test("borrar un script propio pide confirmación", async () => {
  const { core } = setup();
  await mine();
  await open("Mi OSPF");
  await userEvent.click(screen.getByRole("button", { name: "Borrar el script Mi OSPF" }));
  expect(core.deleteScript).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Confirmar el borrado de Mi OSPF" }));
  expect(core.deleteScript).toHaveBeenCalledWith(OSPF.id);
  await waitFor(() => expect(screen.queryByText("Mi OSPF")).not.toBeInTheDocument());
});

test("crear con un nombre repetido muestra el error junto al campo del nombre", async () => {
  const { core } = setup();
  await mine();
  await userEvent.click(await screen.findByRole("button", { name: "Nuevo script" }));
  await userEvent.type(screen.getByLabelText("Nombre"), "mi ospf");
  await userEvent.type(screen.getByLabelText("Comandos"), "show clock");
  await userEvent.click(screen.getByRole("button", { name: "Guardar" }));
  expect(core.saveScript).toHaveBeenCalled();
  expect(await screen.findByLabelText("Nombre")).toHaveAccessibleDescription(/ya hay un script llamado "mi ospf"/);
  expect(screen.getByLabelText("Nombre")).toBeInvalid();
});

test("valida en línea: nombre vacío, comandos vacíos o con acentos y etiquetas malas no se envían", async () => {
  const { core } = setup();
  await mine();
  await userEvent.click(await screen.findByRole("button", { name: "Nuevo script" }));
  const save = screen.getByRole("button", { name: "Guardar" });
  await userEvent.click(save);
  expect(screen.getByLabelText("Nombre")).toHaveAccessibleDescription(/obligatorio/);
  expect(screen.getByLabelText("Comandos")).toHaveAccessibleDescription(/al menos un comando/);
  await userEvent.type(screen.getByLabelText("Nombre"), "X");
  await userEvent.type(screen.getByLabelText("Comandos"), "show clock{enter}descripción ñ");
  await userEvent.type(screen.getByLabelText("Etiquetas"), "OK mal_tag");
  await userEvent.click(save);
  expect(screen.getByLabelText("Comandos")).toHaveAccessibleDescription(/Línea 2/);
  expect(screen.getByLabelText("Etiquetas")).toBeInvalid();
  expect(core.saveScript).not.toHaveBeenCalled();
});

test("guarda un script nuevo con tecnología, plataforma, etiquetas y comandos por línea", async () => {
  const { core } = setup();
  await mine();
  await userEvent.click(await screen.findByRole("button", { name: "Nuevo script" }));
  await userEvent.type(screen.getByLabelText("Nombre"), "  Rutas  ");
  await userEvent.selectOptions(screen.getByLabelText("Tecnología"), "l3");
  await userEvent.selectOptions(screen.getByLabelText("Plataforma"), "nx-os");
  await userEvent.type(screen.getByLabelText("Etiquetas"), "rutas, bgp ospf");
  await userEvent.type(screen.getByLabelText("Comandos"), "show ip route{enter}show ip bgp summary");
  await userEvent.click(screen.getByRole("button", { name: "Guardar" }));
  expect(core.saveScript).toHaveBeenCalledWith({ name: "Rutas", tech: "l3", platform: "nx-os", description: "", tags: ["rutas", "bgp", "ospf"], commands: ["show ip route", "show ip bgp summary"] });
  expect(await screen.findByRole("region", { name: "Rutas" })).toBeInTheDocument();
});

test("editar un script propio manda su id", async () => {
  const { core } = setup();
  await mine();
  await open("Mi OSPF");
  await userEvent.click(screen.getByRole("button", { name: "Editar" }));
  expect(screen.getByLabelText("Comandos")).toHaveValue("show ip ospf neighbor");
  await userEvent.type(screen.getByLabelText("Comandos"), "{enter}show ip ospf database");
  await userEvent.click(screen.getByRole("button", { name: "Guardar" }));
  expect(core.saveScript).toHaveBeenCalledWith(expect.objectContaining({ id: OSPF.id, commands: ["show ip ospf neighbor", "show ip ospf database"] }));
});

test("exportar elige la ruta con pickSavePath y llama exportScripts con overwrite", async () => {
  const { core } = setup();
  await screen.findByText("L2 · STP");
  expect(screen.getByRole("button", { name: "Exportar seleccionados (0)" })).toBeDisabled();
  await userEvent.click(screen.getByRole("checkbox", { name: "Seleccionar L2 · STP" }));
  await userEvent.click(screen.getByRole("checkbox", { name: "Seleccionar Config · VLAN y puerto de acceso" }));
  await userEvent.click(screen.getByRole("button", { name: "Exportar seleccionados (2)" }));
  await waitFor(() => expect(core.exportScripts).toHaveBeenCalledWith(["lib-l2-stp", "lib-cfg-vlan-acceso"], "/home/u/Descargas/scripts.json", true));
  const order = (f: unknown) => (f as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
  expect(order(core.pickSavePath)).toBeLessThan(order(core.exportScripts));
  expect(await screen.findByText("Se exportaron 2 scripts a /home/u/Descargas/scripts.json.")).toBeInTheDocument();
});

test("si exportScripts falla se borra el archivo vacío y se muestra el error", async () => {
  const { core } = setup({ exportScripts: vi.fn(async () => { throw new Error("disco lleno"); }) });
  await screen.findByText("L2 · STP");
  await userEvent.click(screen.getByRole("checkbox", { name: "Seleccionar L2 · STP" }));
  await userEvent.click(screen.getByRole("button", { name: "Exportar seleccionados (1)" }));
  await waitFor(() => expect(core.removeEmptyFile).toHaveBeenCalledWith("/home/u/Descargas/scripts.json"));
  expect(await screen.findByText(/disco lleno/)).toBeInTheDocument();
});

test("cancelar el diálogo de guardar no exporta; un error del núcleo se muestra", async () => {
  const { core } = setup({ pickSavePath: vi.fn(async () => "") });
  await screen.findByText("L2 · STP");
  await userEvent.click(screen.getByRole("checkbox", { name: "Seleccionar L2 · STP" }));
  await userEvent.click(screen.getByRole("button", { name: "Exportar seleccionados (1)" }));
  await waitFor(() => expect(core.pickSavePath).toHaveBeenCalled());
  expect(core.exportScripts).not.toHaveBeenCalled();
});

test("importar: la vista previa muestra el estado de cada script y los conflictos piden decisión", async () => {
  const { core } = setup({ pickPath: vi.fn(async () => "/home/u/scripts.json") });
  await screen.findByText("L2 · STP");
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  const preview = await screen.findByRole("region", { name: "Vista previa de la importación" });
  expect(core.previewScriptsImport).toHaveBeenCalledWith("/home/u/scripts.json");
  const r = within(preview).getAllByRole("row");
  expect(r).toHaveLength(1 + sampleImport.items.length);
  expect(within(r[1]).getByText("Nuevo", { selector: ".badge" })).toBeInTheDocument();
  expect(within(r[2]).getByText("Igual (se omite)")).toBeInTheDocument();
  expect(within(r[3]).getByText("Mismo nombre, otro ID")).toBeInTheDocument();
  // «nuevo» e «igual» no piden decisión; el conflicto sí, y mientras falte no se puede aplicar.
  expect(within(preview).getAllByRole("combobox")).toHaveLength(1);
  expect(within(preview).getByRole("button", { name: "Aplicar importación" })).toBeDisabled();
  await userEvent.selectOptions(within(preview).getByRole("combobox", { name: "Qué hacer con Mi OSPF" }), "renombrar");
  await userEvent.click(within(preview).getByRole("button", { name: "Aplicar importación" }));
  expect(core.applyScriptsImport).toHaveBeenCalledWith("token-1", [{ scriptId: "c".repeat(32), action: "renombrar" }]);
  expect(await screen.findByText("Importación lista: 1 nuevos, 0 reemplazados, 1 renombrados, 1 omitidos.")).toBeInTheDocument();
  expect(screen.queryByRole("region", { name: "Vista previa de la importación" })).not.toBeInTheDocument();
});

test("importar: cancelar el selector de archivo no abre nada y un error del núcleo se muestra", async () => {
  const { core } = setup({ pickPath: vi.fn(async () => "/x.json"), previewScriptsImport: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = suma sha256 no coincide"); }) });
  await screen.findByText("L2 · STP");
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  expect(await screen.findByText("suma sha256 no coincide")).toBeInTheDocument();
  expect(core.applyScriptsImport).not.toHaveBeenCalled();
});

test("enviar una línea manda nombre, texto y readOnly por el canal terminal-insert", async () => {
  const { go } = setup();
  await mine();
  await open("Mi OSPF");
  await userEvent.click(screen.getByRole("button", { name: "Enviar a la terminal" }));
  expect(go).toHaveBeenCalledWith("terminal", encodeInsert({ name: "Mi OSPF", text: "show ip ospf neighbor", readOnly: true }), "terminal-insert");
});

test("enviar varias líneas de solo lectura las junta con salto de línea", async () => {
  const { go } = setup();
  await screen.findByText("L2 · STP");
  await open("L2 · STP");
  await userEvent.click(screen.getByRole("button", { name: "Enviar a la terminal" }));
  expect(go).toHaveBeenCalledWith("terminal", encodeInsert({ name: "L2 · STP", text: "show spanning-tree summary\nshow spanning-tree root", readOnly: true }), "terminal-insert");
});

test("las líneas «!» se mandan tal cual (dentro de un banner son texto)", async () => {
  const { go } = setup();
  await mine();
  await userEvent.click(await screen.findByRole("button", { name: "Nuevo script" }));
  await userEvent.type(screen.getByLabelText("Nombre"), "Con comentario");
  await userEvent.type(screen.getByLabelText("Comandos"), "show clock{enter}! nota{enter}show version");
  await userEvent.click(screen.getByRole("button", { name: "Guardar" }));
  await userEvent.click(await screen.findByRole("button", { name: "Enviar a la terminal" }));
  expect(go).toHaveBeenCalledWith("terminal", expect.stringContaining("show clock\\n! nota\\nshow version"), "terminal-insert");
});

test("un script de configuración de varias líneas no se envía: ofrece Copiar y avisa", async () => {
  const { core, go } = setup();
  await screen.findByText("L2 · STP");
  await open("Config · VLAN y puerto de acceso");
  expect(screen.queryByRole("button", { name: "Enviar a la terminal" })).not.toBeInTheDocument();
  expect(screen.getByText(/Los scripts de configuración no se envían a la terminal: cada salto de línea ejecutaría una línea\. Aplícalos con un snippet en modo asistido o pégalos tú\./)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Copiar" }));
  expect(core.copyText).toHaveBeenCalledWith("configure terminal\nvlan 10\nend");
  expect(go).not.toHaveBeenCalled();
});

test("un script de configuración de una sola línea sí se envía", async () => {
  const { go } = setup();
  await mine();
  await userEvent.click(await screen.findByRole("button", { name: "Nuevo script" }));
  await userEvent.type(screen.getByLabelText("Nombre"), "Limpiar");
  await userEvent.type(screen.getByLabelText("Comandos"), "clear counters");
  await userEvent.click(screen.getByRole("button", { name: "Guardar" }));
  await userEvent.click(await screen.findByRole("button", { name: "Enviar a la terminal" }));
  expect(go).toHaveBeenCalledWith("terminal", encodeInsert({ name: "Limpiar", text: "clear counters", readOnly: false }), "terminal-insert");
});

test.each(["NotFound", "FailedPrecondition"])("importar: con %s al aplicar se cierra la vista previa y se pide abrir el archivo otra vez", async (code) => {
  const { core } = setup({ pickPath: vi.fn(async () => "/x.json"), applyScriptsImport: vi.fn(async () => { throw new Error(`rpc error: code = ${code} desc = el token venció`); }) });
  await screen.findByText("L2 · STP");
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  const preview = await screen.findByRole("region", { name: "Vista previa de la importación" });
  await userEvent.selectOptions(within(preview).getByRole("combobox"), "omitir");
  await userEvent.click(within(preview).getByRole("button", { name: "Aplicar importación" }));
  expect(await screen.findByText("La vista previa venció o ya se usó: vuelve a abrir el archivo.")).toBeInTheDocument();
  expect(screen.queryByRole("region", { name: "Vista previa de la importación" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Aplicar importación" })).not.toBeInTheDocument();
  expect(core.applyScriptsImport).toHaveBeenCalledTimes(1);
});

test("importar: un error de decisión (InvalidArgument) deja la vista previa abierta para corregir", async () => {
  setup({ pickPath: vi.fn(async () => "/x.json"), applyScriptsImport: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = decisión repetida"); }) });
  await screen.findByText("L2 · STP");
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  const preview = await screen.findByRole("region", { name: "Vista previa de la importación" });
  await userEvent.selectOptions(within(preview).getByRole("combobox"), "omitir");
  await userEvent.click(within(preview).getByRole("button", { name: "Aplicar importación" }));
  expect(await screen.findByText("decisión repetida")).toBeInTheDocument();
  expect(screen.getByRole("region", { name: "Vista previa de la importación" })).toBeInTheDocument();
});

test("importar: «Choca con» resuelve el nombre contra todos los scripts, aunque los filtros lo oculten", async () => {
  setup({ pickPath: vi.fn(async () => "/x.json") });
  await screen.findByText("L2 · STP");
  await userEvent.type(screen.getByLabelText("Buscar"), "vlan"); // «Mi OSPF» queda fuera de la lista filtrada
  await waitFor(() => expect(rows()).toHaveLength(1));
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  const preview = await screen.findByRole("region", { name: "Vista previa de la importación" });
  const cell = within(within(preview).getAllByRole("row")[2]).getAllByRole("cell")[2];
  expect(cell).toHaveTextContent("Mi OSPF");
  expect(cell).not.toHaveTextContent(OSPF.id);
});

test("la selección para exportar solo cuenta lo que se ve: cambiar de pestaña o de filtro quita lo oculto", async () => {
  const { core } = setup();
  await screen.findByText("L2 · STP");
  await userEvent.click(screen.getByRole("checkbox", { name: "Seleccionar L2 · STP" }));
  await userEvent.click(screen.getByRole("checkbox", { name: "Seleccionar Config · VLAN y puerto de acceso" }));
  expect(screen.getByRole("button", { name: "Exportar seleccionados (2)" })).toBeEnabled();
  await userEvent.type(screen.getByLabelText("Buscar"), "spanning"); // solo queda STP a la vista
  expect(await screen.findByRole("button", { name: "Exportar seleccionados (1)" })).toBeEnabled();
  await mine(); // STP también se oculta
  expect(await screen.findByRole("button", { name: "Exportar seleccionados (0)" })).toBeDisabled();
  await userEvent.click(screen.getByRole("tab", { name: "Biblioteca" })); // lo quitado no vuelve marcado
  expect(await screen.findByRole("button", { name: "Exportar seleccionados (0)" })).toBeDisabled();
  expect(core.exportScripts).not.toHaveBeenCalled();
});

test("el formulario toma el foco en el nombre y al cerrar el foco vuelve al botón que lo abrió", async () => {
  setup();
  await mine();
  await userEvent.click(await screen.findByRole("button", { name: "Nuevo script" }));
  await waitFor(() => expect(screen.getByLabelText("Nombre")).toHaveFocus());
  await userEvent.click(screen.getByRole("button", { name: "Cancelar" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Nuevo script" })).toHaveFocus());
  await open("Mi OSPF");
  await userEvent.click(screen.getByRole("button", { name: "Editar" }));
  await waitFor(() => expect(screen.getByLabelText("Nombre")).toHaveFocus());
  await userEvent.click(screen.getByRole("button", { name: "Cancelar" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Editar" })).toHaveFocus());
});

test("importar: contra un script de la biblioteca no se ofrece «Reemplazar»", async () => {
  const lib = { script: { ...OSPF, id: "d".repeat(32), name: "L2 · STP" }, state: "conflicto_nombre" as const, conflictsWith: "lib-l2-stp" };
  setup({ pickPath: vi.fn(async () => "/x.json"), previewScriptsImport: vi.fn(async () => ({ ...sampleImport, items: [lib, sampleImport.items[2]] })) });
  await screen.findByText("L2 · STP");
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  const choices = (name: string) => within(screen.getByRole("combobox", { name })).getAllByRole("option").map((o) => (o as HTMLOptionElement).value);
  await screen.findByRole("combobox", { name: "Qué hacer con L2 · STP" });
  expect(choices("Qué hacer con L2 · STP")).toEqual(["", "renombrar", "omitir"]);
  expect(choices("Qué hacer con Mi OSPF")).toEqual(["", "renombrar", "reemplazar", "omitir"]);
});
