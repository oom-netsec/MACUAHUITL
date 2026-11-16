import { expect, test } from "vitest";
import { chmodCommand, icaclsCommand, outputsErrorText, parseOutputsError } from "./outputsError";
import { setOSForTests } from "./platform";

const t = (k: string) => `[${k}]`;
const text = (p: string) => `prefs.outputs.permisos: la carpeta ${p} tiene modo 0755 y debe ser 0700; corrígelo con: chmod 700 ${p}`;
// Error del puente con cause: el texto puede venir en cualquier idioma, lo que manda es reason y metadata.
const msg = (p: string) => Object.assign(new Error("fix it with something else"), { cause: { code: "FailedPrecondition", reason: "prefs.outputs.permisos", metadata: { code: "permisos", path: p } } });

test("la orden chmod cita lo raro y no se genera con \\, ' o control", () => {
  expect(chmodCommand("/home/u/salidas")).toBe("chmod 700 /home/u/salidas");
  expect(chmodCommand("/home/u/$(id)")).toBe("chmod 700 '/home/u/$(id)'");
  expect(chmodCommand("/x\\';echo pwned;#")).toBe("");
  expect(chmodCommand("/x'y")).toBe("");
  expect(chmodCommand("/x\ny")).toBe("");
  expect(chmodCommand("")).toBe("");
  // Un C1 o un bidi no se ejecuta entre comillas, pero puede hacer que la orden se vea distinta de lo que se pega.
  expect(chmodCommand("/x\u0085y")).toBe("");
  expect(chmodCommand("/x\u202ey")).toBe("");
  for (const inv of ["\u200b", "\u200e", "\u200f", "\u2028", "\u2060", "\ufeff"]) expect(chmodCommand(`/x${inv}y`)).toBe("");
  expect(chmodCommand("/home/u/Música/salidas")).toBe("chmod 700 '/home/u/Música/salidas'");
});

test("el texto de un rechazo de permisos lleva la orden solo si es segura", () => {
  expect(outputsErrorText(msg("/home/u/salidas"), t as never)).toBe("[settings.storage.err.permisos] chmod 700 /home/u/salidas");
  expect(outputsErrorText(msg("/home/u/$(id)"), t as never)).toBe("[settings.storage.err.permisos] chmod 700 '/home/u/$(id)'");
  expect(outputsErrorText(msg("/x\\';echo pwned;#"), t as never)).toBe("[settings.storage.err.permisos]");
  expect(outputsErrorText(new Error("otra cosa"), t as never)).toBe("otra cosa");
});

test("la ruta es lo que sigue al sufijo «corrígelo con: chmod 700 », no una mención anterior", () => {
  const m = "prefs.outputs.permisos: la carpeta /a/chmod 700 /b tiene modo 0755 y debe ser 0700; corrígelo con: chmod 700 /a/chmod 700 /b";
  expect(parseOutputsError(new Error(m))).toEqual({ code: "permisos", path: "/a/chmod 700 /b" });
});

test("con reason, el código y la ruta salen de cause y no del texto", () => {
  expect(parseOutputsError(msg("/a b"))).toEqual({ code: "permisos", path: "/a b" });
  const noExiste = Object.assign(new Error("folder missing"), { cause: { code: "NotFound", reason: "prefs.outputs.no_existe", metadata: { code: "no_existe", path: "/x" } } });
  expect(parseOutputsError(noExiste)).toEqual({ code: "no_existe", path: "/x" });
  expect(outputsErrorText(noExiste, t as never)).toBe("[settings.storage.err.no_existe]");
  // Un reason ajeno no es un rechazo de carpeta, aunque el texto lo parezca.
  const otro = Object.assign(new Error(text("/x")), { cause: { code: "Internal", reason: "otra.cosa", metadata: {} } });
  expect(parseOutputsError(otro)).toBeNull();
  expect(outputsErrorText(otro, t as never)).toBe(text("/x"));
  // El respaldo por texto sigue sirviendo sin reason.
  expect(parseOutputsError(new Error(text("/x")))).toEqual({ code: "permisos", path: "/x" });
});

test("los textos sirven en Ajustes, Job, Cambio y Diagnóstico", async () => {
  const { es } = await import("./i18n/es");
  const { en } = await import("./i18n/en");
  expect(es["settings.storage.err.permisos"]).not.toMatch(/guardar/);
  expect(en["settings.storage.err.permisos"]).not.toMatch(/save/i);
  // Sin orden (ruta que no se puede citar segura), el texto no debe pedir "esta orden".
  expect(es["settings.storage.err.permisos"]).not.toMatch(/esta orden/);
  expect(en["settings.storage.err.permisos"]).not.toMatch(/this command/);
  expect(es["change.outDir"]).toMatch(/subcarpeta/);
  expect(en["change.outDir"]).toMatch(/subfolder/);
});

const IC_OK = 'icacls "C:\\Users\\ana\\salidas" /inheritance:r /remove "*S-1-1-0" /grant:r "*S-1-5-21-1-2-3-1001:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"';

test("icaclsCommand: toma lo que sigue a la frase, en español o inglés", () => {
  const cmd = 'icacls "C:\\Users\\ana\\salidas" /inheritance:r /remove "*S-1-1-0" /grant:r "*S-1-5-18:(OI)(CI)F"';
  expect(icaclsCommand(`prefs.outputs.permisos: x; corrígelo en cmd con: ${cmd}`)).toBe(cmd);
  expect(icaclsCommand(`prefs.outputs.permisos: x; fix it in cmd with: ${cmd}`)).toBe(cmd);
  expect(icaclsCommand("prefs.outputs.permisos: sin orden")).toBe("");
  expect(icaclsCommand("x; fix it in cmd with: del /q C:\\*")).toBe(""); // no empieza con icacls "
  expect(icaclsCommand(`x; fix it in cmd with: ${IC_OK}`)).toBe(IC_OK);
});

test("icaclsCommand: descarta la orden con %, !, saltos, controles o invisibles", () => {
  for (const bad of ["%USERNAME%", "!x!", "\n& calc", "\x07", "\u202e", "\u200b", "\u2028", "\ufeff", "\u0085"]) {
    expect(icaclsCommand(`x; fix it in cmd with: icacls "C:\\a" ${bad}`)).toBe("");
  }
});

test("Windows: el texto de permisos lleva la orden icacls; en Linux sigue el chmod", () => {
  const win = Object.assign(new Error(`prefs.outputs.permisos: la carpeta C:\\s da acceso a S-1-1-0; corrígelo en cmd con: ${IC_OK}`), { cause: { code: "FailedPrecondition", reason: "prefs.outputs.permisos", metadata: { code: "permisos", path: "C:\\s" } } });
  try {
    setOSForTests("windows");
    expect(outputsErrorText(win, t as never)).toBe(`[settings.storage.err.permisos] ${IC_OK}`);
    expect(outputsErrorText(Object.assign(new Error("x; corrígelo en cmd con: icacls \"C:\\a\" %PATH%"), { cause: (win as { cause: object }).cause }), t as never)).toBe("[settings.storage.err.permisos]");
    setOSForTests("linux");
    expect(outputsErrorText(msg("/home/u/salidas"), t as never)).toBe("[settings.storage.err.permisos] chmod 700 /home/u/salidas");
    expect(outputsErrorText(win, t as never)).toBe("[settings.storage.err.permisos]"); // con ruta de Windows y en Linux: sin chmod (lleva \\)
  } finally { setOSForTests(undefined); }
});
