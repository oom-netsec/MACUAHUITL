import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StorageSection, parseOutputsError } from "./StorageSection";
import { I18nProvider } from "../../lib/i18n";
import { CoreContext, NavContext } from "../../app/activity";
import { SettingsView } from "./SettingsView";
import { fakeCore } from "../../lib/fake";
import { sampleOutputsDefault } from "./fake";
import type { CorePrefsState } from "./api";

const base: CorePrefsState = { outputsDir: "", rotateMb: 0, rotateMin: 0, maxFiles: 0, format: "", outputsDirEffective: sampleOutputsDefault, outputsDirDefault: sampleOutputsDefault, note: "" };
const rpc = (m: string) => new Error(`rpc error: code = InvalidArgument desc = ${m}`);
const view = (core = fakeCore(), lang = "es") => {
  localStorage.setItem("macuahuitl.lang", lang);
  return render(<I18nProvider><CoreContext.Provider value={core}><StorageSection core={core} /></CoreContext.Provider></I18nProvider>);
};
const folder = () => screen.findByRole("textbox", { name: /Carpeta de salidas|Output folder/ });
const typeIn = async (el: HTMLElement, v: string) => { await userEvent.clear(el); if (v) await userEvent.type(el, v); };

beforeEach(() => localStorage.clear());

test("muestra la carpeta en uso y la de fábrica", async () => {
  view(fakeCore({ getCorePrefs: vi.fn(async () => ({ ...base, outputsDir: "/home/u/s", outputsDirEffective: "/home/u/s" })) }));
  await folder();
  expect(screen.getAllByText("/home/u/s").length).toBeGreaterThan(0);
  expect(screen.getAllByText(sampleOutputsDefault).length).toBeGreaterThan(0);
});

test("la nota del núcleo sale como aviso en español", async () => {
  view(fakeCore({ getCorePrefs: vi.fn(async () => ({ ...base, note: "Nota del núcleo X." })) }));
  expect(await screen.findByText("Nota del núcleo X.")).toBeVisible();
});

test("la nota del núcleo no sale en inglés: va el aviso traducido", async () => {
  view(fakeCore({ getCorePrefs: vi.fn(async () => ({ ...base, outputsDir: "/home/u/viejo", note: "El cambio aplica a lo que empiece después." })) }), "en");
  await folder();
  expect(screen.queryByText(/El cambio aplica/)).toBeNull();
  expect(screen.getByText(/no longer meets the rules/)).toBeVisible(); // carpeta guardada distinta de la efectiva
});

test("sin nota ni desvío no hay aviso", async () => {
  view();
  await folder();
  expect(screen.queryByText(/ya no cumple/)).toBeNull();
});

test("la vista dice que lo anterior no se mueve", async () => {
  view();
  await folder();
  expect(screen.getByText(/no se mueven/)).toBeVisible();
});

test("guardar manda la forma exacta; vacío es de fábrica (0 y cadena vacía)", async () => {
  const core = fakeCore();
  view(core);
  await userEvent.click(await screen.findByRole("button", { name: "Guardar" }));
  await waitFor(() => expect(core.setCorePrefs).toHaveBeenCalledWith({ outputsDir: "", rotateMb: 0, rotateMin: 0, maxFiles: 0, format: "" }));
});

test("guardar con valores manda números y formato", async () => {
  const core = fakeCore();
  view(core);
  await typeIn(await folder(), "/home/u/salidas");
  await typeIn(screen.getByRole("textbox", { name: "Rotar cada (MB)" }), "10");
  await typeIn(screen.getByRole("textbox", { name: "Rotar cada (minutos)" }), "60");
  await typeIn(screen.getByRole("textbox", { name: "Archivos que se conservan" }), "5");
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "Formato" }), "jsonl");
  await userEvent.click(screen.getByRole("button", { name: "Guardar" }));
  await waitFor(() => expect(core.setCorePrefs).toHaveBeenCalledWith({ outputsDir: "/home/u/salidas", rotateMb: 10, rotateMin: 60, maxFiles: 5, format: "jsonl" }));
  expect(await screen.findByText(/Guardado/)).toBeVisible();
});

test("«Usar la de fábrica» vacía el campo y al guardar manda outputsDir vacío", async () => {
  const core = fakeCore({ getCorePrefs: vi.fn(async () => ({ ...base, outputsDir: "/home/u/s", outputsDirEffective: "/home/u/s" })) });
  view(core);
  expect(await folder()).toHaveValue("/home/u/s");
  await userEvent.click(screen.getByRole("button", { name: "Usar la de fábrica" }));
  expect(await folder()).toHaveValue("");
  await userEvent.click(screen.getByRole("button", { name: "Guardar" }));
  await waitFor(() => expect(core.setCorePrefs).toHaveBeenCalledWith(expect.objectContaining({ outputsDir: "" })));
});

test("«Examinar…» elige una carpeta con el diálogo nativo", async () => {
  const core = fakeCore({ pickPath: vi.fn(async () => "/home/u/elegida") });
  view(core);
  await userEvent.click(await screen.findByRole("button", { name: /Examinar/ }));
  expect(core.pickPath).toHaveBeenCalledWith({ title: "Carpeta de salidas", directory: true });
  expect(await folder()).toHaveValue("/home/u/elegida");
});

test("valida los defaults con los rangos del núcleo y no llama a guardar", async () => {
  const core = fakeCore();
  view(core);
  await typeIn(await screen.findByRole("textbox", { name: "Rotar cada (MB)" }), "2000");
  await typeIn(screen.getByRole("textbox", { name: "Archivos que se conservan" }), "abc");
  expect(screen.getByText("Debe estar entre 1 y 1024.")).toBeVisible();
  expect(screen.getByText("Escribe un número entero positivo.")).toBeVisible();
  expect(screen.getByRole("button", { name: "Guardar" })).toBeDisabled();
  expect(core.setCorePrefs).not.toHaveBeenCalled();
});

test("muestra el valor de fábrica como marcador", async () => {
  view();
  expect(await screen.findByRole("textbox", { name: "Rotar cada (MB)" })).toHaveAttribute("placeholder", "50");
  expect(screen.getByRole("textbox", { name: "Archivos que se conservan" })).toHaveAttribute("placeholder", "20");
});

describe("motivos de rechazo", () => {
  const REASONS: Record<string, [RegExp, RegExp]> = {
    relativa: [/debe ser absoluta/, /must be absolute/],
    punto_punto: [/no puede llevar «\.\.»/, /cannot contain/],
    no_existe: [/no existe/, /does not exist/],
    ilegible: [/No se pudo leer/, /could not be read/],
    no_directorio: [/no es una carpeta/, /is not a folder/],
    otro_dueno: [/no es de tu usuario/, /not owned by your user/],
    reservada: [/está reservada/, /is reserved/],
    permisos: [/permisos más abiertos/, /more open than 0700/],
    ancestro_inseguro: [/otros usuarios pueden escribir/, /other users can write/],
    no_escribible: [/No se puede escribir/, /cannot be written to/],
  };
  const failing = (reason: string) => fakeCore({ setCorePrefs: vi.fn(async () => { throw rpc(`prefs.outputs.${reason}: texto en español del núcleo con detalles /x`); }) });
  for (const [reason, [es, en]] of Object.entries(REASONS)) {
    test(`${reason}: traducido en es y en en, sin el texto del núcleo`, async () => {
      const { unmount } = view(failing(reason));
      await userEvent.click(await screen.findByRole("button", { name: "Guardar" }));
      expect(await screen.findByText(es)).toBeVisible();
      expect(screen.queryByText(/texto en español del núcleo/)).toBeNull();
      unmount();
      view(failing(reason), "en");
      await userEvent.click(await screen.findByRole("button", { name: "Save" }));
      expect(await screen.findByText(en)).toBeVisible();
      expect(screen.queryByText(/texto en español del núcleo/)).toBeNull();
    });
  }

  test("un motivo desconocido y un error ajeno no muestran español del núcleo en inglés", async () => {
    view(failing("nuevo_motivo"), "en");
    await userEvent.click(await screen.findByRole("button", { name: "Save" }));
    expect(await screen.findByText("The folder is not valid.")).toBeVisible();
  });

  test("un error sin código: en español sale tal cual; en inglés, genérico", async () => {
    const core = () => fakeCore({ setCorePrefs: vi.fn(async () => { throw rpc("tasa fuera de rango"); }) });
    const { unmount } = view(core());
    await userEvent.click(await screen.findByRole("button", { name: "Guardar" }));
    expect(await screen.findByText("tasa fuera de rango")).toBeVisible();
    unmount();
    view(core(), "en");
    await userEvent.click(await screen.findByRole("button", { name: "Save" }));
    expect(await screen.findByText("Could not save.")).toBeVisible();
    expect(screen.queryByText("tasa fuera de rango")).toBeNull();
  });

  test("permisos: muestra chmod 700 con la ruta del núcleo y la copia", async () => {
    const core = fakeCore({ setCorePrefs: vi.fn(async () => { throw rpc("prefs.outputs.permisos: la carpeta /home/u/mi salidas tiene modo 0755 y debe ser 0700; corrígelo con: chmod 700 /home/u/mi salidas"); }) });
    core.copyText = vi.fn(async () => {});
    view(core, "en");
    await userEvent.click(await screen.findByRole("button", { name: "Save" }));
    expect(await screen.findByText("chmod 700 '/home/u/mi salidas'")).toBeVisible(); // comillas por el espacio
    await userEvent.click(screen.getByRole("button", { name: /Copy/ }));
    expect(core.copyText).toHaveBeenCalledWith("chmod 700 '/home/u/mi salidas'");
  });

  test("con cause: la ruta del chmod sale de metadata.path, no del texto", async () => {
    const core = fakeCore({ setCorePrefs: vi.fn(async () => { throw Object.assign(new Error("the folder is open"), { cause: { code: "FailedPrecondition", reason: "prefs.outputs.permisos", metadata: { code: "permisos", path: "/home/u/mi salidas" } } }); }) });
    view(core, "en");
    await userEvent.click(await screen.findByRole("button", { name: "Save" }));
    expect(await screen.findByText("chmod 700 '/home/u/mi salidas'")).toBeVisible();
  });

  test("el rechazo por la carpeta queda bajo su campo, marcado inválido y descrito", async () => {
    view(failing("permisos"));
    await userEvent.click(await screen.findByRole("button", { name: "Guardar" }));
    const input = await screen.findByRole("textbox", { name: "Carpeta de salidas" });
    await waitFor(() => expect(input).toHaveAttribute("aria-invalid", "true"));
    const err = document.getElementById(input.getAttribute("aria-describedby")!.split(" ").pop()!)!;
    expect(err).toHaveTextContent(/permisos/i);
  });

  test("otros motivos no muestran chmod", async () => {
    view(failing("no_existe"));
    await userEvent.click(await screen.findByRole("button", { name: "Guardar" }));
    await screen.findByText(/no existe/);
    expect(screen.queryByText(/chmod/)).toBeNull();
  });

  test("parseOutputsError: código y ruta", () => {
    expect(parseOutputsError(new Error("prefs.outputs.permisos: x; corrígelo con: chmod 700 /a/b"))).toEqual({ code: "permisos", path: "/a/b" });
    expect(parseOutputsError(new Error("otra cosa"))).toBeNull();
  });
});

test("Ajustes → Datos: la tarjeta de la bóveda explica el respaldo y navega a la bóveda", async () => {
  const go = vi.fn();
  localStorage.setItem("macuahuitl.lang", "es");
  render(<I18nProvider><NavContext.Provider value={{ go, inbox: {} }}><SettingsView core={fakeCore()} /></NavContext.Provider></I18nProvider>);
  expect(screen.getByText(/12 caracteres o más/)).toBeVisible();
  expect(screen.getByText(/Nunca forma parte de las exportaciones generales/)).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "Abrir la bóveda" }));
  expect(go).toHaveBeenCalledWith("vault");
});
