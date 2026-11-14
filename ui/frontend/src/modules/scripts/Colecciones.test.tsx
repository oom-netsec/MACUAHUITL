import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ScriptsView } from "./ScriptsView";
import { fakeCore } from "../../lib/fake";
import { NavContext } from "../../app/activity";
import { I18nProvider } from "../../lib/i18n";
import { FAVORITES_ID, MAX_PINNED } from "./api";
import { sampleScripts, sampleCollectionsImport } from "./fake";
import { DataSection } from "../settings/DataSection";

const OSPF = sampleScripts[2];
const STP = sampleScripts[0];

function setup(over = {}) {
  const core = fakeCore(over);
  const view = render(<I18nProvider><NavContext.Provider value={{ go: vi.fn(), inbox: {} }}><ScriptsView core={core} /></NavContext.Provider></I18nProvider>);
  return { core, ...view };
}
const cols = () => userEvent.click(screen.getByRole("tab", { name: "Colecciones" }));
const colRows = () => within(screen.getByRole("list", { name: "Colecciones" })).getAllByRole("listitem");
const crear = async (name: string) => {
  await userEvent.click(screen.getByRole("button", { name: "Nueva colección" }));
  await userEvent.type(screen.getByLabelText("Nombre de la colección"), name);
  await userEvent.click(screen.getByRole("button", { name: "Guardar colección" }));
  await waitFor(() => expect(screen.getByRole("button", { name: `Abrir ${name}` })).toBeInTheDocument());
};
beforeEach(() => localStorage.setItem("macuahuitl.idioma", "es"));

describe("colecciones: alta, edición, borrado y orden", () => {
  test("favoritos va primero y es fija; crear una colección la deja al final y llama a saveCollection sin id", async () => {
    const { core } = setup();
    await cols();
    await waitFor(() => expect(colRows()).toHaveLength(1));
    expect(within(colRows()[0]).getByText("Favoritos")).toBeInTheDocument();
    await crear("Redes");
    expect(core.saveCollection).toHaveBeenCalledWith({ id: undefined, name: "Redes", description: "" });
    expect(colRows().map((r) => within(r).getByRole("button", { name: /^Abrir/ }).textContent)).toEqual(["Favoritos", "Redes"]);
  });

  test("favoritos no ofrece borrar y no deja renombrar; una propia sí se renombra", async () => {
    const { core } = setup();
    await cols();
    await userEvent.click(await screen.findByRole("button", { name: "Abrir Favoritos" }));
    expect(screen.queryByRole("button", { name: /^Borrar la colección/ })).not.toBeInTheDocument();
    expect(screen.getByText(/es la colección fija/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Editar" }));
    expect(screen.getByLabelText("Nombre de la colección")).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Cancelar" }));
    await crear("Redes");
    await userEvent.click(screen.getByRole("button", { name: "Editar" }));
    await userEvent.clear(screen.getByLabelText("Nombre de la colección"));
    await userEvent.type(screen.getByLabelText("Nombre de la colección"), "WAN");
    await userEvent.click(screen.getByRole("button", { name: "Guardar colección" }));
    await waitFor(() => expect(core.saveCollection).toHaveBeenLastCalledWith(expect.objectContaining({ id: expect.stringMatching(/^c/), name: "WAN" })));
    expect(await screen.findByRole("button", { name: "Abrir WAN" })).toBeInTheDocument();
  });

  test("un error del núcleo (nombre repetido) queda junto al campo y el formulario sigue abierto", async () => {
    setup();
    await cols();
    await crear("Redes");
    await userEvent.click(screen.getByRole("button", { name: "Nueva colección" }));
    await userEvent.type(screen.getByLabelText("Nombre de la colección"), "redes");
    await userEvent.click(screen.getByRole("button", { name: "Guardar colección" }));
    expect(await screen.findByText(/ya hay una colección llamada "redes"/)).toBeInTheDocument();
  });

  test("borrar pide confirmación en dos pasos", async () => {
    const { core } = setup();
    await cols();
    await crear("Redes");
    const del = screen.getByRole("button", { name: "Borrar la colección Redes" });
    await userEvent.click(del);
    expect(core.deleteCollection).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Confirmar el borrado de Redes" }));
    await waitFor(() => expect(core.deleteCollection).toHaveBeenCalledWith(expect.stringMatching(/^c/)));
    await waitFor(() => expect(colRows()).toHaveLength(1));
  });

  test("subir y bajar reordenan con todas las colecciones (favoritos incluida) y el foco se queda en el botón", async () => {
    const { core } = setup();
    await cols();
    await crear("A");
    await crear("B");
    const ids = (await core.listCollections()).map((c) => c.id);
    expect(ids).toHaveLength(3);
    expect(screen.getByRole("button", { name: "Subir Favoritos" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Bajar B" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Subir B" }));
    await waitFor(() => expect(core.reorderCollections).toHaveBeenCalledWith([ids[0], ids[2], ids[1]]));
    await waitFor(() => expect(colRows().map((r) => within(r).getByRole("button", { name: /^Abrir/ }).textContent)).toEqual(["Favoritos", "B", "A"]));
    await waitFor(() => expect(screen.getByRole("button", { name: "Subir B" })).toHaveFocus());
    // Llegó al tope de lo permitido tras favoritos: sube otra vez y el foco pasa al botón contrario (el de subir quedó apagado)
    await userEvent.click(screen.getByRole("button", { name: "Subir B" }));
    await waitFor(() => expect(core.reorderCollections).toHaveBeenLastCalledWith([ids[2], ids[0], ids[1]]));
  });
});

describe("colecciones: sus scripts, por referencia", () => {
  test("agregar (de la biblioteca o propio) deja la lista completa y ordenada; quitar y reordenar también", async () => {
    const { core } = setup();
    await cols();
    await crear("Redes");
    const id = (await core.listCollections())[1].id;
    await userEvent.selectOptions(screen.getByLabelText("Agregar un script"), STP.id);
    await userEvent.click(screen.getByRole("button", { name: "Agregar" }));
    await waitFor(() => expect(core.setCollectionScripts).toHaveBeenLastCalledWith(id, [STP.id]));
    await userEvent.selectOptions(screen.getByLabelText("Agregar un script"), OSPF.id);
    await userEvent.click(screen.getByRole("button", { name: "Agregar" }));
    await waitFor(() => expect(core.setCollectionScripts).toHaveBeenLastCalledWith(id, [STP.id, OSPF.id]));
    expect(within(screen.getByRole("list", { name: "Scripts de Redes" })).getAllByRole("listitem")).toHaveLength(2);
    await userEvent.click(await screen.findByRole("button", { name: `Subir el script ${OSPF.name}` }));
    await waitFor(() => expect(core.setCollectionScripts).toHaveBeenLastCalledWith(id, [OSPF.id, STP.id]));
    await userEvent.click(await screen.findByRole("button", { name: `Quitar ${STP.name} de la colección` }));
    await waitFor(() => expect(core.setCollectionScripts).toHaveBeenLastCalledWith(id, [OSPF.id]));
    expect(await screen.findByRole("option", { name: /L2 · STP/ })).toBeInTheDocument(); // vuelve a poder agregarse
  });

  test("lo que ya está en la colección no se ofrece otra vez", async () => {
    setup();
    await cols();
    await crear("Redes");
    await userEvent.selectOptions(screen.getByLabelText("Agregar un script"), STP.id);
    await userEvent.click(screen.getByRole("button", { name: "Agregar" }));
    await screen.findByRole("list", { name: "Scripts de Redes" });
    expect(screen.queryByRole("option", { name: /L2 · STP/ })).not.toBeInTheDocument();
  });

  test("desde la fila: «Agregar a colección» es multiselección y usa la lista al día", async () => {
    const { core } = setup();
    await cols();
    await crear("Redes");
    await userEvent.click(screen.getByRole("tab", { name: "Biblioteca" }));
    await userEvent.click(await screen.findByRole("button", { name: `Agregar a colección: ${STP.name}` }));
    const menu = screen.getByRole("menu", { name: `Colecciones de ${STP.name}` });
    const [fav, redes] = within(menu).getAllByRole("menuitemcheckbox");
    expect(fav).toHaveTextContent("Favoritos");
    await userEvent.click(fav);
    await waitFor(() => expect(core.setCollectionScripts).toHaveBeenLastCalledWith(FAVORITES_ID, [STP.id]));
    await userEvent.click(redes);
    await waitFor(() => expect(core.setCollectionScripts).toHaveBeenLastCalledWith(expect.stringMatching(/^c/), [STP.id]));
    await waitFor(() => expect(within(screen.getByRole("menu")).getAllByRole("menuitemcheckbox").map((b) => b.getAttribute("aria-checked"))).toEqual(["true", "true"]));
    await userEvent.click(fav); // quitar
    await waitFor(() => expect(core.setCollectionScripts).toHaveBeenLastCalledWith(FAVORITES_ID, []));
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: `Agregar a colección: ${STP.name}` })).toHaveFocus();
  });
});

describe("fijados", () => {
  test("el botón fija y desfija con aria-pressed", async () => {
    const { core } = setup();
    await userEvent.click(await screen.findByRole("button", { name: `Fijar en la terminal: ${STP.name}` }));
    expect(core.setScriptPinned).toHaveBeenCalledWith(STP.id, true);
    await waitFor(() => expect(screen.getByRole("button", { name: `Fijar en la terminal: ${STP.name}` })).toHaveAttribute("aria-pressed", "true"));
    await userEvent.click(screen.getByRole("button", { name: `Fijar en la terminal: ${STP.name}` }));
    expect(core.setScriptPinned).toHaveBeenLastCalledWith(STP.id, false);
  });

  test("el sexto fijado muestra el motivo del núcleo y no queda fijado", async () => {
    const lib = (n: number) => ({ ...STP, id: `lib-x${n}`, name: `Lib ${n}`, pinned: n <= MAX_PINNED });
    const many = [1, 2, 3, 4, 5, 6].map(lib);
    const { fakeScripts } = await import("./fake");
    setup(fakeScripts(many));
    const sixth = await screen.findByRole("button", { name: "Fijar en la terminal: Lib 6" });
    await userEvent.click(sixth);
    expect(await screen.findByText("Ya hay 5 scripts fijados, el máximo. Desfija uno antes de fijar otro.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Fijar en la terminal: Lib 6" })).toHaveAttribute("aria-pressed", "false");
  });

  test("otro error al fijar se muestra tal cual", async () => {
    setup({ setScriptPinned: vi.fn(async () => { throw new Error("rpc error: code = NotFound desc = no hay un script"); }) });
    await userEvent.click(await screen.findByRole("button", { name: `Fijar en la terminal: ${STP.name}` }));
    expect(await screen.findByText("no hay un script")).toBeInTheDocument();
  });
});

describe("exportar e importar colecciones", () => {
  test("exportar las seleccionadas pide la ruta y avisa cuántas", async () => {
    const { core } = setup();
    await cols();
    await crear("Redes");
    expect(screen.getByRole("button", { name: "Exportar seleccionadas (0)" })).toBeDisabled();
    await userEvent.click(screen.getByRole("checkbox", { name: "Seleccionar la colección Redes" }));
    await userEvent.click(screen.getByRole("button", { name: "Exportar seleccionadas (1)" }));
    await waitFor(() => expect(core.exportCollections).toHaveBeenCalledWith([expect.stringMatching(/^c/)], "/home/u/Descargas/colecciones.json", true));
    expect(await screen.findByText("Se exportaron 1 colecciones y 0 scripts propios a /home/u/Descargas/colecciones.json.")).toBeInTheDocument();
  });

  test("la vista previa muestra estados, avisos traducidos y pide decisión por conflicto, con favoritos sin «Reemplazar»", async () => {
    const { core } = setup({ pickPath: vi.fn(async () => "/home/u/col.json") });
    await cols();
    await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
    const preview = await screen.findByRole("region", { name: "Vista previa de la importación de colecciones" });
    expect(core.previewCollectionsImport).toHaveBeenCalledWith("/home/u/col.json");
    expect(within(preview).getByText("Nueva", { selector: ".badge" })).toBeInTheDocument();
    expect(within(preview).getByText("Igual (se omite)")).toBeInTheDocument();
    expect(within(preview).getByText("Mismo nombre, otro ID")).toBeInTheDocument();
    expect(within(preview).getByText("Fusionar")).toBeInTheDocument();
    expect(within(preview).getByText(/Colección «Nueva»: el script lib-de-otra-version no está en la biblioteca local y se omitirá\./)).toBeInTheDocument();
    // Solo el conflicto de nombre pide decisión; fusionar no.
    expect(within(preview).getAllByRole("combobox")).toHaveLength(1);
    expect(within(preview).getByRole("button", { name: "Aplicar importación" })).toBeDisabled();
    await userEvent.selectOptions(within(preview).getByRole("combobox", { name: "Qué hacer con la colección Redes" }), "renombrar");
    await userEvent.click(within(preview).getByRole("button", { name: "Aplicar importación" }));
    expect(core.applyCollectionsImport).toHaveBeenCalledWith("token-c1", [], [{ scriptId: "f".repeat(32), action: "renombrar" }]);
    expect(await screen.findByText(/Importación lista\. Colecciones: 1 nuevas, 0 reemplazadas, 1 renombradas, 1 fusionadas, 1 omitidas\. Scripts: 1 nuevos/)).toBeInTheDocument();
  });

  test("los conflictos de scripts del archivo llevan su propia decisión, aparte de las colecciones", async () => {
    const withScriptConflict = {
      ...sampleCollectionsImport,
      scripts: [...sampleCollectionsImport.scripts, { script: { ...OSPF, id: "9".repeat(32), name: "Mi OSPF" }, state: "conflicto_nombre" as const, conflictsWith: OSPF.id }],
    };
    const { core } = setup({ pickPath: vi.fn(async () => "/x.json"), previewCollectionsImport: vi.fn(async () => withScriptConflict) });
    await cols();
    await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
    const preview = await screen.findByRole("region", { name: "Vista previa de la importación de colecciones" });
    await userEvent.selectOptions(within(preview).getByRole("combobox", { name: "Qué hacer con la colección Redes" }), "omitir");
    expect(within(preview).getByRole("button", { name: "Aplicar importación" })).toBeDisabled(); // falta la del script
    await userEvent.selectOptions(within(preview).getByRole("combobox", { name: "Qué hacer con Mi OSPF" }), "reemplazar");
    await userEvent.click(within(preview).getByRole("button", { name: "Aplicar importación" }));
    expect(core.applyCollectionsImport).toHaveBeenCalledWith("token-c1", [{ scriptId: "9".repeat(32), action: "reemplazar" }], [{ scriptId: "f".repeat(32), action: "omitir" }]);
  });

  test("contra la colección favoritos no se ofrece «Reemplazar»", async () => {
    const vsFav = { ...sampleCollectionsImport, collections: [{ collection: { ...sampleCollectionsImport.collections[2].collection, name: "Favoritos" }, state: "conflicto_nombre" as const, conflictsWith: FAVORITES_ID }] };
    setup({ pickPath: vi.fn(async () => "/x.json"), previewCollectionsImport: vi.fn(async () => vsFav) });
    await cols();
    await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
    const sel = await screen.findByRole("combobox", { name: "Qué hacer con la colección Favoritos" });
    expect(within(sel).queryByRole("option", { name: "Reemplazar" })).not.toBeInTheDocument();
  });

  test("en inglés los avisos y los estados salen en inglés, sin español", async () => {
    localStorage.setItem("macuahuitl.idioma", "en");
    setup({ pickPath: vi.fn(async () => "/x.json"), previewCollectionsImport: vi.fn(async () => ({ ...sampleCollectionsImport, warnings: ["archivo sin suma de verificación", ...sampleCollectionsImport.warnings] })) });
    await userEvent.click(screen.getByRole("tab", { name: "Collections" }));
    await userEvent.click(screen.getByRole("button", { name: "Import…" }));
    const preview = await screen.findByRole("region", { name: "Collections import preview" });
    expect(within(preview).getByText("The file has no checksum (sha256): it cannot be verified that it was not altered.")).toBeInTheDocument();
    expect(within(preview).getByText(/Collection "Nueva": the script lib-de-otra-version is not in the local library and will be skipped\./)).toBeInTheDocument();
    expect(within(preview).getByText("Same name, different ID")).toBeInTheDocument();
    expect(within(preview).getAllByText("Favorites").length).toBeGreaterThan(0); // el nombre fijo del núcleo, en el idioma elegido
    expect(preview.textContent).not.toMatch(/sin suma|Favoritos|se omitió/);
  });
});

test("el aviso de que el archivo no trae suma también sale al importar scripts", async () => {
  setup({ pickPath: vi.fn(async () => "/x.json") });
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  const preview = await screen.findByRole("region", { name: "Vista previa de la importación" });
  expect(within(preview).getByText(/El archivo no trae suma de verificación \(sha256\)/)).toBeInTheDocument();
});

describe("revisión: avisos, datos, límite, foco y favoritos", () => {
  const WARN_NEXT = 'colección "Nueva": el script lib-x no está en la biblioteca local; se omitirá';
  const WARN_DONE = 'colección "Nueva": el script lib-y no está en la biblioteca local; se omitió';
  const WARN_DROP = 'colección "Nueva": el script lib-z no se importó; se quitó de la colección';
  const result = (warnings: string[]) => ({ scriptsCreated: 0, scriptsReplaced: 0, scriptsRenamed: 0, scriptsSkipped: 0, collectionsCreated: 1, collectionsReplaced: 0, collectionsRenamed: 0, collectionsMerged: 0, collectionsSkipped: 0, warnings });
  const onlyNew = (warnings: string[]) => vi.fn(async () => ({ ...sampleCollectionsImport, collections: [sampleCollectionsImport.collections[0]], warnings }));

  test("en inglés, los tres avisos del núcleo (vista previa «se omitirá» y resultado «se omitió»/«no se importó») salen traducidos", async () => {
    localStorage.setItem("macuahuitl.idioma", "en");
    setup({ pickPath: vi.fn(async () => "/x.json"), previewCollectionsImport: onlyNew([WARN_NEXT]), applyCollectionsImport: vi.fn(async () => result([WARN_DONE, WARN_DROP])) });
    await userEvent.click(screen.getByRole("tab", { name: "Collections" }));
    await userEvent.click(screen.getByRole("button", { name: "Import…" }));
    const preview = await screen.findByRole("region", { name: "Collections import preview" });
    expect(within(preview).getByText('Collection "Nueva": the script lib-x is not in the local library and will be skipped.')).toBeInTheDocument();
    await userEvent.click(within(preview).getByRole("button", { name: "Apply import" }));
    expect(await screen.findByText('Collection "Nueva": the script lib-y is not in the local library and was skipped.')).toBeInTheDocument();
    expect(screen.getByText('Collection "Nueva": the script lib-z was not imported and was removed from the collection.')).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/se omit|no se import|biblioteca local;/);
  });

  test("tras aplicar en español también se ven los avisos del resultado", async () => {
    setup({ pickPath: vi.fn(async () => "/x.json"), previewCollectionsImport: onlyNew([]), applyCollectionsImport: vi.fn(async () => result([WARN_DROP])) });
    await cols();
    await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
    const preview = await screen.findByRole("region", { name: "Vista previa de la importación de colecciones" });
    await userEvent.click(within(preview).getByRole("button", { name: "Aplicar importación" }));
    expect(await screen.findByText("Colección «Nueva»: el script lib-z no se importó y se quitó de la colección.")).toBeInTheDocument();
  });

  const both = (core: ReturnType<typeof fakeCore>) => render(<I18nProvider><NavContext.Provider value={{ go: vi.fn(), inbox: {} }}><ScriptsView core={core} /><DataSection core={core} /></NavContext.Provider></I18nProvider>);

  test("importar desde Ajustes → Datos recarga la lista de Scripts que sigue montada", async () => {
    const core = fakeCore({ pickPath: vi.fn(async () => "/x.json") });
    both(core);
    await screen.findByText("L2 · STP");
    expect(screen.queryByText("Importado")).not.toBeInTheDocument();
    const lib = sampleScripts[0];
    (core.listScripts as ReturnType<typeof vi.fn>).mockImplementation(async () => [lib, { ...lib, id: "lib-nuevo", name: "Importado" }]);
    await userEvent.click(within(screen.getByRole("article", { name: "Scripts" })).getByRole("button", { name: "Importar…" }));
    const preview = await screen.findByRole("region", { name: "Vista previa de la importación" });
    await userEvent.selectOptions(within(preview).getByRole("combobox"), "omitir");
    await userEvent.click(within(preview).getByRole("button", { name: "Aplicar importación" }));
    expect(await screen.findByText("Importado")).toBeInTheDocument();
  });

  test("importar colecciones desde Ajustes recarga el área de colecciones montada", async () => {
    const core = fakeCore({ pickPath: vi.fn(async () => "/x.json") });
    both(core);
    await cols();
    await waitFor(() => expect(colRows()).toHaveLength(1));
    const base = { description: "", scriptIds: [], hiddenScriptIds: [], createdMs: 0, updatedMs: 0 };
    (core.listCollections as ReturnType<typeof vi.fn>).mockImplementation(async () => [{ ...base, id: FAVORITES_ID, name: "Favoritos", order: 0 }, { ...base, id: "9".repeat(32), name: "Traída", order: 1 }]);
    await userEvent.click(within(screen.getByRole("article", { name: "Colecciones de scripts" })).getByRole("button", { name: "Importar…" }));
    const preview = await screen.findByRole("region", { name: "Vista previa de la importación de colecciones" });
    await userEvent.selectOptions(within(preview).getByRole("combobox"), "omitir");
    await userEvent.click(within(preview).getByRole("button", { name: "Aplicar importación" }));
    await waitFor(() => expect(colRows()).toHaveLength(2));
  });

  test("el límite de fijados se reconoce por el código FailedPrecondition del mensaje crudo, sin depender de la palabra «fijados»", async () => {
    localStorage.setItem("macuahuitl.idioma", "en");
    setup({ setScriptPinned: vi.fn(async () => { throw new Error("rpc error: code = FailedPrecondition desc = limit reached"); }) });
    await userEvent.click(await screen.findByRole("button", { name: `Pin to the terminal: ${STP.name}` }));
    expect(await screen.findByText("There are already 5 pinned scripts, the maximum. Unpin one before pinning another.")).toBeInTheDocument();
  });

  test("otro código gRPC cuyo texto menciona «fijados» no se confunde con el límite", async () => {
    setup({ setScriptPinned: vi.fn(async () => { throw new Error("rpc error: code = NotFound desc = no hay un script fijados"); }) });
    await userEvent.click(await screen.findByRole("button", { name: `Fijar en la terminal: ${STP.name}` }));
    expect(await screen.findByText("no hay un script fijados")).toBeInTheDocument();
  });

  const conTres = async () => {
    const out = setup();
    await cols();
    await crear("Redes");
    for (const [i, id] of [STP.id, OSPF.id, sampleScripts[1].id].entries()) {
      await userEvent.selectOptions(screen.getByLabelText("Agregar un script"), id);
      await userEvent.click(screen.getByRole("button", { name: "Agregar" }));
      await waitFor(() => expect(screen.getAllByRole("button", { name: /^Quitar/ })).toHaveLength(i + 1));
    }
    return out;
  };
  const quitar = () => screen.queryAllByRole("button", { name: /^Quitar/ });

  test("al quitar un script el foco pasa al siguiente; si era el último, al anterior; si no queda ninguno, al selector de agregar", async () => {
    await conTres();
    await userEvent.click(quitar()[0]);
    await waitFor(() => expect(quitar()).toHaveLength(2));
    await waitFor(() => expect(quitar()[0]).toHaveFocus()); // el que ocupa el lugar del quitado
    await userEvent.click(quitar()[1]); // el último
    await waitFor(() => expect(quitar()).toHaveLength(1));
    await waitFor(() => expect(quitar()[0]).toHaveFocus());
    await userEvent.click(quitar()[0]);
    await waitFor(() => expect(quitar()).toHaveLength(0));
    await waitFor(() => expect(screen.getByLabelText("Agregar un script")).toHaveFocus());
  });

  test("si el reordenamiento falla no queda un foco pendiente que se dispare con un cambio posterior", async () => {
    setup({ reorderCollections: vi.fn(async () => { throw new Error("falló"); }) });
    await cols();
    await crear("A");
    await crear("B");
    await userEvent.click(screen.getByRole("button", { name: "Subir B" }));
    expect(await screen.findByText("falló")).toBeInTheDocument();
    await crear("C"); // cambia la lista: el foco viejo no debe robarse
    expect(screen.getByRole("button", { name: "Subir B" })).not.toHaveFocus();
  });

  test("en inglés, editar favoritos muestra «Favorites» y al guardar manda el nombre del núcleo sin renombrar", async () => {
    localStorage.setItem("macuahuitl.idioma", "en");
    const { core } = setup();
    await userEvent.click(screen.getByRole("tab", { name: "Collections" }));
    await userEvent.click(await screen.findByRole("button", { name: "Open Favorites" }));
    await userEvent.click(screen.getByRole("button", { name: "Edit" }));
    expect(screen.getByLabelText("Collection name")).toHaveValue("Favorites");
    await userEvent.type(screen.getByLabelText("Description"), "mis comandos");
    await userEvent.click(screen.getByRole("button", { name: "Save collection" }));
    await waitFor(() => expect(core.saveCollection).toHaveBeenCalledWith({ id: FAVORITES_ID, name: "Favoritos", description: "mis comandos" }));
  });
});

describe("colecciones: ocultos por un paquete y scripts no disponibles", () => {
  const withIds = async (scriptIds: string[], hiddenScriptIds: string[]) => {
    const { core, ...r } = setup();
    const base = await core.listCollections();
    const c = { ...base[0], scriptIds, hiddenScriptIds };
    (core.listCollections as ReturnType<typeof vi.fn>).mockResolvedValue([c]);
    await cols();
    await userEvent.click(await screen.findByRole("button", { name: "Abrir Favoritos" }));
    return { core, ...r };
  };

  test("un id oculto se marca «oculto» y uno lib-* sin script, «no disponible», sin romper la lista", async () => {
    await withIds([STP.id, "lib-l2-ghost", "lib-l2-hid"], ["lib-l2-hid"]);
    const items = within(screen.getByRole("list", { name: /^Scripts de/ })).getAllByRole("listitem");
    expect(items).toHaveLength(3);
    expect(items[0]).not.toHaveTextContent(/oculto|no disponible/);
    expect(items[1]).toHaveTextContent("lib-l2-ghost");
    expect(items[1]).toHaveTextContent("no disponible: instala el paquete");
    expect(items[2]).toHaveTextContent("oculto por un paquete");
    expect(items[2]).not.toHaveTextContent("no disponible");
  });

  test("el contador no cuenta los no disponibles", async () => {
    await withIds([STP.id, "lib-l2-ghost"], []);
    expect(within(colRows()[0]).getByText("1 scripts")).toBeInTheDocument();
  });

  test("un oculto que sí resuelve se marca «oculto» y tampoco cuenta", async () => {
    await withIds([STP.id, "lib-l2-ghost"], [STP.id]);
    const items = within(screen.getByRole("list", { name: /^Scripts de/ })).getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("oculto por un paquete");
    expect(within(colRows()[0]).getByText("0 scripts")).toBeInTheDocument();
  });
});
