import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { setOSForTests } from "../../lib/platform";
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
afterEach(() => setOSForTests(undefined));

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

test("en inglés la nota del núcleo ya llega traducida y se muestra tal cual", async () => {
  view(fakeCore({ getCorePrefs: vi.fn(async () => ({ ...base, outputsDir: "/home/u/viejo", note: "The change applies to what starts afterwards." })) }), "en");
  await folder();
  expect(screen.getByText("The change applies to what starts afterwards.")).toBeVisible();
});

test("en inglés el error al leer las preferencias se muestra tal cual", async () => {
  view(fakeCore({ getCorePrefs: vi.fn(async () => { throw new Error("could not read the preferences file"); }) }), "en");
  expect(await screen.findByText("could not read the preferences file")).toBeVisible();
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

  test("un error sin código se muestra tal cual en cualquier idioma", async () => {
    view(fakeCore({ setCorePrefs: vi.fn(async () => { throw rpc("rate out of range"); }) }), "en");
    await userEvent.click(await screen.findByRole("button", { name: "Save" }));
    expect(await screen.findByText("rate out of range")).toBeVisible();
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

  test("rechazo del núcleo para una ruta hostil (UNC, ADS, HTML): reason + metadata.path, bajo su campo y sin interpretar la ruta", async () => {
    const path = '\\\\?\\C:\\x:ads<img src=x onerror="window.__pwn=1">';
    const core = fakeCore({ setCorePrefs: vi.fn(async () => { throw Object.assign(new Error("texto del núcleo"), { cause: { code: "FailedPrecondition", reason: "prefs.outputs.reservada", metadata: { code: "reservada", path } } }); }) });
    view(core);
    await userEvent.click(await screen.findByRole("button", { name: "Guardar" }));
    const input = await screen.findByRole("textbox", { name: "Carpeta de salidas" });
    await waitFor(() => expect(input).toHaveAttribute("aria-invalid", "true"));
    const err = document.getElementById(input.getAttribute("aria-describedby")!.split(" ").pop()!)!;
    expect(err).toHaveTextContent(/está reservada/);
    expect(err.querySelector("img")).toBeNull();
    expect(err.textContent).not.toContain("<img"); // la ruta del núcleo no se interpola en el texto del rechazo
    expect(err.querySelector("code")).toBeNull(); // ni hay orden de chmod con una ruta así
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

// Un error con código que no es de la carpeta ya llega traducido: en inglés se muestra tal cual, no el genérico.
test("en inglés, un error con reason que no es de carpeta se muestra tal cual", async () => {
  const err = Object.assign(new Error("rpc error: code = InvalidArgument desc = rotate size out of range"), { cause: { code: "InvalidArgument", reason: "prefs.err.rotate", metadata: {} } });
  view(fakeCore({ setCorePrefs: vi.fn(async () => { throw err; }) }), "en");
  await folder();
  await userEvent.click(screen.getByRole("button", { name: "Save" }));
  expect(await screen.findByText("rotate size out of range")).toBeVisible();
});

describe("Windows", () => {
  const ic = 'icacls "C:\\Users\\ana\\mi salidas" /inheritance:r /remove "*S-1-5-32-545" /grant:r "*S-1-5-21-1-2-3-1001:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"';
  const winErr = (reason: string, text: string) => Object.assign(new Error(text), { cause: { code: "FailedPrecondition", reason: `prefs.outputs.${reason}`, metadata: { code: reason, path: "C:\\Users\\ana\\mi salidas" } } });

  test("reglas y permisos: texto de ACL, orden icacls y su copia", async () => {
    setOSForTests("windows");
    const core = fakeCore({ setCorePrefs: vi.fn(async () => { throw winErr("permisos", `prefs.outputs.permisos: x; fix it in cmd with: ${ic}`); }) });
    core.copyText = vi.fn(async () => {});
    view(core, "en");
    expect(await screen.findByText(/only your user, SYSTEM and Administrators/)).toBeVisible();
    expect(screen.queryByText(/0700/)).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(ic)).toBeVisible();
    expect(screen.getByText(/remove that access/)).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: /Copy/ }));
    expect(core.copyText).toHaveBeenCalledWith(ic);
  });

  test("sin orden: muestra el detalle del núcleo y no promete una orden", async () => {
    setOSForTests("windows");
    view(fakeCore({ setCorePrefs: vi.fn(async () => { throw winErr("permisos", "prefs.outputs.permisos: la carpeta C:\\x da acceso a enlace"); }) }));
    await userEvent.click(await screen.findByRole("button", { name: "Guardar" }));
    expect(await screen.findByText(/da acceso a enlace/)).toBeVisible();
    expect(screen.queryByRole("button", { name: /Copiar/ })).toBeNull();
  });

  test("reservada: texto de Windows", async () => {
    setOSForTests("windows");
    view(fakeCore({ setCorePrefs: vi.fn(async () => { throw rpc("prefs.outputs.reservada: texto del núcleo"); }) }), "en");
    await userEvent.click(await screen.findByRole("button", { name: "Save" }));
    expect(await screen.findByText(/your user profile or \.ssh/)).toBeVisible();
    expect(screen.queryByText(/~\/\.ssh/)).toBeNull();
  });

  test("una orden con % no se muestra", async () => {
    setOSForTests("windows");
    view(fakeCore({ setCorePrefs: vi.fn(async () => { throw winErr("permisos", 'x; corrígelo en cmd con: icacls "C:\\a" /grant:r "%USERNAME%:(OI)(CI)F"'); }) }));
    await userEvent.click(await screen.findByRole("button", { name: "Guardar" }));
    await screen.findByText(/da acceso a otros usuarios/);
    expect(screen.queryByRole("button", { name: /Copiar/ })).toBeNull(); // sin orden segura: solo el detalle del núcleo
  });

  test("ancestro y reservada tienen su texto de Windows", async () => {
    setOSForTests("windows");
    view(fakeCore({ setCorePrefs: vi.fn(async () => { throw rpc("prefs.outputs.ancestro_inseguro: texto del núcleo"); }) }));
    await userEvent.click(await screen.findByRole("button", { name: "Guardar" }));
    expect(await screen.findByText(/C:\\Users\\Public/, { selector: '[role="alert"]' })).toBeVisible();
  });

  test("en Linux sigue el chmod y el texto de 0700", async () => {
    setOSForTests("linux");
    view(fakeCore({ setCorePrefs: vi.fn(async () => { throw rpc("prefs.outputs.permisos: x; corrígelo con: chmod 700 /home/u/s"); }) }), "en");
    expect(await screen.findByText(/mode exactly 0700/)).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("chmod 700 /home/u/s")).toBeVisible();
    expect(screen.getByRole("button", { name: /Copy the chmod command/ })).toBeVisible();
  });
});
